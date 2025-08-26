# analyzers/semgrep_runner.py
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

# --------------------------------- Public API ---------------------------------

@dataclass
class SemgrepInvocationError(Exception):
    exit_code: int
    cmd: List[str]
    stdout: str
    stderr: str

    def __str__(self) -> str:
        return _fmt_semgrep_error(self.cmd, self.exit_code, self.stderr)


def run_semgrep(
    paths: List[str],
    repo_root: str,
    config: Optional[str] = None,
    exclude: Optional[List[str]] = None,
    timeout_s: int = 60,
) -> List[Dict[str, Any]]:
    """
    Run Semgrep on the provided file paths (relative to repo_root) and return normalized findings.

    Returns a list of dicts like:
      {
        "path": "app.py",
        "start_line": 12,
        "end_line": 12,
        "severity": "HIGH",
        "rule_id": "python.lang.subprocess.shell",
        "title": "Subprocess with shell=True",
        "message": "Using shell=True is dangerous …",
        "fix": "subprocess.run([...], shell=False)",
        "cwe": "CWE-78",
        "owasp": "A01:2021"
      }
    """
    if not paths:
        return []

    semgrep_bin = _ensure_semgrep_available()
    cfg = _resolve_config(config, repo_root)
    excludes = [p for p in (exclude or []) if p]
    severity_floor = _severity_floor(os.getenv("PRSEC_SEMGREP_MIN_SEVERITY"))

    # Stable, de-duped, repo-relative paths
    rel_paths = sorted({ _rel_to_repo_root(p, repo_root) for p in paths })

    # Semgrep returns 0=no findings, 1=findings, >=2=error
    findings: List[Dict[str, Any]] = []

    # Optional parallelism
    jobs = (os.getenv("PRSEC_SEMGREP_JOBS") or "").strip()
    jobs_args: List[str] = []
    if jobs:
        jobs_args = ["-j", jobs]  # e.g., "auto" or "4"

    # Pre-build common args
    common = [
        semgrep_bin,
        "--config", cfg,
        "--json",
        "--timeout", str(timeout_s),
        "--skip-unknown-extensions",
        "--no-rewrite-rule-ids",
        "--disable-version-check",
        "--quiet",
        *jobs_args,
    ]
    for pat in excludes:
        common += ["--exclude", pat]

    # Chunk long arg lists to avoid OS argv limits
    for chunk in _chunk(rel_paths, 200):
        cmd = [*common, *chunk]
        try:
            proc = subprocess.run(
                cmd,
                cwd=repo_root,
                text=True,
                capture_output=True,
                check=False,  # handle rc ourselves
                timeout=timeout_s + 5,  # guardrail over Semgrep's internal timeout
            )
        except subprocess.TimeoutExpired as e:
            raise SemgrepInvocationError(
                exit_code=124,
                cmd=cmd,
                stdout=e.stdout or "",
                stderr=f"Semgrep timed out after {timeout_s}s: {e.stderr or ''}",
            )

        rc = proc.returncode
        if rc >= 2:
            raise SemgrepInvocationError(rc, cmd, proc.stdout or "", proc.stderr or "")

        data = _parse_json_or_raise(proc.stdout)
        for f in _normalize_results(data.get("results", []) or []):
            if severity_floor and _sev_order(f["severity"]) < _sev_order(severity_floor):
                continue
            # Skip any result missing a path (defensive)
            if not f.get("path"):
                continue
            findings.append(f)

    return findings


def to_github_annotations(
    findings: List[Dict[str, Any]],
    max_per_file: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Convert normalized findings → GitHub Checks annotations."""
    out: List[Dict[str, Any]] = []
    per_file_count: Dict[str, int] = {}

    for f in findings:
        path = f["path"]
        if max_per_file:
            c = per_file_count.get(path, 0)
            if c >= max_per_file:
                continue
            per_file_count[path] = c + 1

        level = _severity_to_annotation_level(f["severity"])
        title = f.get("title") or f.get("rule_id") or "Semgrep finding"
        meta: List[str] = []
        if f.get("rule_id"): meta.append(f"Rule: {f['rule_id']}")
        if f.get("cwe"):     meta.append(f"CWE: {f['cwe']}")
        if f.get("owasp"):   meta.append(f"OWASP: {f['owasp']}")
        if f.get("fix"):     meta.append(f"Suggested fix: {f['fix']}")

        annotation: Dict[str, Any] = {
            "path": path,
            "start_line": int(f["start_line"]),
            "end_line": int(f["end_line"]),
            "annotation_level": level,       # failure | warning | notice
            "title": title,
            "message": f.get("message") or title,
        }
        if meta:
            annotation["raw_details"] = "\n".join(meta)
        out.append(annotation)

    return out


def summarize_findings(findings: List[Dict[str, Any]]) -> Tuple[Dict[str, int], str]:
    """Return (counts_by_severity, markdown_summary)."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        if sev in counts:
            counts[sev] += 1

    md = [
        "### PR security reviewer — Semgrep summary",
        "",
        f"- **Critical:** {counts['CRITICAL']}",
        f"- **High:** {counts['HIGH']}",
        f"- **Medium:** {counts['MEDIUM']}",
        f"- **Low:** {counts['LOW']}",
    ]
    return counts, "\n".join(md)

# --------------------------------- Internals ----------------------------------

def _ensure_semgrep_available() -> str:
    """Return the Semgrep executable path or raise."""
    bin_env = os.getenv("SEMGREP_BIN")
    exe = shutil.which(bin_env) if bin_env else shutil.which("semgrep")
    if not exe:
        raise SemgrepInvocationError(
            exit_code=127,
            cmd=[bin_env or "semgrep", "--version"],
            stdout="",
            stderr=(
                "Semgrep CLI not found. Install with `pip install semgrep` or `brew install semgrep`, "
                "or point to the binary via SEMGREP_BIN."
            ),
        )
    return exe


def _resolve_config(cfg: Optional[str], repo_root: str) -> str:
    """
    Resolve Semgrep config:
      - if cfg is provided, use it
      - else use env SEMGREP_CONFIG (or typo SEMGRP_CONFIG), else 'p/ci'
      - if it looks like a local path, make it absolute relative to repo_root
      - registry IDs (p/... or r/), 'auto', and URLs pass through as-is
    """
    value = (cfg or os.getenv("SEMGREP_CONFIG") or os.getenv("SEMGRP_CONFIG") or "p/ci").strip()

    if (
        value.startswith(("p/", "r/"))
        or value in {"auto", "semgrep-auto"}
        or value.startswith(("http://", "https://"))
    ):
        return value

    if _looks_like_path(value):
        abs_repo = os.path.abspath(repo_root)
        return os.path.abspath(os.path.join(abs_repo, value))

    return value


def _looks_like_path(s: str) -> bool:
    return any(sep in s for sep in ("/", "\\", os.sep)) or s.endswith((".yml", ".yaml"))


def _parse_json_or_raise(stdout: str) -> Dict[str, Any]:
    try:
        return json.loads(stdout or "{}")
    except json.JSONDecodeError as e:
        sample = (stdout or "").strip()[:800]
        raise SemgrepInvocationError(exit_code=65, cmd=["semgrep", "--json"], stdout=sample, stderr=str(e))


def _normalize_results(results: Iterable[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
    for r in results:
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        start = r.get("start", {}) or {}
        end = r.get("end", {}) or {}

        sev = _normalize_severity(meta.get("severity") or extra.get("severity") or "LOW")

        cwe_val = meta.get("cwe") or meta.get("cwe_id") or meta.get("cwe_id_vuln")
        if isinstance(cwe_val, list):
            cwe = ", ".join(map(str, cwe_val))
        elif isinstance(cwe_val, str):
            cwe = cwe_val
        else:
            cwe = None

        owasp_val = meta.get("owasp") or meta.get("owasp_category")
        if isinstance(owasp_val, list):
            owasp = ", ".join(map(str, owasp_val))
        elif isinstance(owasp_val, str):
            owasp = owasp_val
        else:
            owasp = None

        title = extra.get("message") or r.get("check_id") or "Semgrep finding"

        yield {
            "path": r.get("path"),
            "start_line": int(start.get("line") or 1),
            "end_line": int(end.get("line") or start.get("line") or 1),
            "severity": sev,
            "rule_id": r.get("check_id"),
            "title": title,
            "message": extra.get("message") or "",
            "fix": extra.get("fix") or meta.get("fix"),
            "cwe": cwe,
            "owasp": owasp,
        }


def _rel_to_repo_root(path: str, repo_root: str) -> str:
    abs_repo = os.path.abspath(repo_root)
    abs_path = os.path.abspath(os.path.join(abs_repo, path))
    try:
        return os.path.relpath(abs_path, abs_repo)
    except ValueError:
        return os.path.basename(path)


def _normalize_severity(s: str) -> str:
    s = (s or "").strip().upper()
    if s in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return s
    if s in {"BLOCKER"}:
        return "CRITICAL"
    if s in {"ERROR"}:
        return "HIGH"
    if s in {"WARNING", "WARN"}:
        return "MEDIUM"
    return "LOW"


def _severity_floor(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    val = (raw or "").strip().upper()
    if val in {"", "NONE", "OFF", "DISABLE"}:
        return None
    return _normalize_severity(val)


def _severity_to_annotation_level(sev: str) -> str:
    sev = (sev or "LOW").upper()
    if sev in {"CRITICAL", "HIGH"}:
        return "failure"
    if sev == "MEDIUM":
        return "warning"
    return "notice"


def _sev_order(sev: str) -> int:
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get((sev or "").upper(), 1)


def _chunk(items: List[str], size: int) -> Iterable[List[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _fmt_semgrep_error(cmd: List[str], code: int, stderr: str) -> str:
    return (
        f"Semgrep failed (exit={code}).\n"
        f"Command: {shlex.join(cmd)}\n"
        f"STDERR (truncated):\n{(stderr or '').strip()[:800]}"
    )
