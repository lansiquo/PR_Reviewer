# analyzers/semgrep_runner.py
import json
import os
import shlex
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

# ---------- Public API ----------

def run_semgrep(
    paths: List[str],
    repo_root: str,
    config: Optional[str] = None,
    exclude: Optional[List[str]] = None,
    timeout_s: int = 60,
) -> List[Dict[str, Any]]:
    """
    Run Semgrep on the provided file paths (relative to repo_root) and return normalized findings.

    Returns a list of dicts:
    {
      "path": "app.py",
      "start_line": 12,
      "end_line": 12,
      "severity": "HIGH",          # one of: CRITICAL/HIGH/MEDIUM/LOW
      "rule_id": "python.lang.subprocess.shell",
      "title": "Subprocess with shell=True",
      "message": "Using shell=True is dangerous …",
      "fix": "subprocess.run([...], shell=False)",
      "cwe": "CWE-78",             # optional
      "owasp": "A01:2021"          # optional
    }
    """
    if not paths:
        return []

    _ensure_semgrep_available()

    cfg = config or os.getenv("SEMGREP_CONFIG") or os.getenv("SEMGRP_CONFIG") or "p/ci"
    excludes = exclude or []

    # Ensure paths are repo-relative for stable annotations
    rel_paths = [_rel_to_repo_root(p, repo_root) for p in paths]

    cmd = [
        "semgrep",
        "--config", cfg,
        "--json",
        "--timeout", str(timeout_s),
        "--skip-unknown-extensions",
        "--no-rewrite-rule-ids",
    ]
    for pat in excludes:
        cmd += ["--exclude", pat]
    cmd += rel_paths

    # Run in the repo root so Semgrep can resolve .semgrepignore and local configs
    proc = subprocess.run(
        cmd,
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=False,  # Semgrep returns 1 when findings exist; 0 = none; >=2 = errors
    )

    if proc.returncode >= 2:
        raise RuntimeError(_fmt_semgrep_error(cmd, proc.returncode, proc.stderr))

    # Parse JSON even if returncode==1 (findings)
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Semgrep produced invalid JSON: {e}\nSTDOUT (truncated): {proc.stdout[:500]}")

    results = data.get("results", []) or []
    findings: List[Dict[str, Any]] = []
    for r in results:
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        start = r.get("start", {}) or {}
        end = r.get("end", {}) or {}

        severity = _normalize_severity(
            meta.get("severity") or extra.get("severity") or "INFO"
        )
        fix = extra.get("fix") or meta.get("fix")
        title = extra.get("message") or r.get("check_id")
        cwe = (meta.get("cwe") or meta.get("cwe_id") or meta.get("cwe_id_vuln")) or None
        owasp = meta.get("owasp") or None

        findings.append({
            "path": r.get("path"),
            "start_line": int(start.get("line") or 1),
            "end_line": int(end.get("line") or start.get("line") or 1),
            "severity": severity,
            "rule_id": r.get("check_id"),
            "title": title,
            "message": extra.get("message") or "",
            "fix": fix,
            "cwe": cwe if isinstance(cwe, str) else None,
            "owasp": owasp if isinstance(owasp, str) else None,
        })

    return findings


def to_github_annotations(
    findings: List[Dict[str, Any]],
    max_per_file: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Convert normalized findings -> GitHub Checks annotations.
    """
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
        raw_details = []
        if f.get("rule_id"):
            raw_details.append(f"Rule: {f['rule_id']}")
        if f.get("cwe"):
            raw_details.append(f"CWE: {f['cwe']}")
        if f.get("owasp"):
            raw_details.append(f"OWASP: {f['owasp']}")
        if f.get("fix"):
            raw_details.append(f"Suggested fix: {f['fix']}")

        out.append({
            "path": path,
            "start_line": f["start_line"],
            "end_line": f["end_line"],
            "annotation_level": level,       # failure | warning | notice
            "title": title,
            "message": f.get("message") or title,
            "raw_details": "\n".join(raw_details) or None,
        })
    return out


def summarize_findings(findings: List[Dict[str, Any]]) -> Tuple[Dict[str, int], str]:
    """
    Return (counts_by_severity, markdown_summary).
    """
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f["severity"]
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

# ---------- Internals ----------

def _ensure_semgrep_available() -> None:
    exe = shutil.which("semgrep")
    if not exe:
        raise RuntimeError(
            "Semgrep CLI not found. Install with `pip install semgrep` or `brew install semgrep` "
            "and ensure it’s on PATH inside your venv/shell."
        )

def _rel_to_repo_root(path: str, repo_root: str) -> str:
    # Accept absolute or relative; return repo-relative
    abs_repo = os.path.abspath(repo_root)
    abs_path = os.path.abspath(os.path.join(abs_repo, path))
    try:
        return os.path.relpath(abs_path, abs_repo)
    except ValueError:
        # Different drive (Windows) — fall back to basename
        return os.path.basename(path)

def _normalize_severity(s: str) -> str:
    s = (s or "").strip().upper()
    # Prefer explicit metadata severities if present
    if s in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return s
    # Map legacy Semgrep severities
    if s == "ERROR":
        return "HIGH"
    if s == "WARNING":
        return "MEDIUM"
    return "LOW"

def _severity_to_annotation_level(sev: str) -> str:
    sev = sev.upper()
    if sev in {"CRITICAL", "HIGH"}:
        return "failure"
    if sev == "MEDIUM":
        return "warning"
    return "notice"

def _fmt_semgrep_error(cmd: List[str], code: int, stderr: str) -> str:
    return (
        f"Semgrep failed (exit={code}).\n"
        f"Command: {shlex.join(cmd)}\n"
        f"STDERR (truncated):\n{(stderr or '').strip()[:800]}"
    )
