# analyzers/semgrep_runner.py
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from typing import Any, Dict, Iterable, List, Optional, Tuple

class SemgrepInvocationError(Exception):
    def __init__(self, exit_code: int, cmd: List[str], stdout: str, stderr: str) -> None:
        super().__init__(f"Semgrep failed (exit={exit_code})")
        self.exit_code = exit_code
        self.cmd = cmd
        self.stdout = stdout
        self.stderr = stderr
    def __str__(self) -> str:
        return _fmt_semgrep_error(self.cmd, self.exit_code, self.stderr)

def run_semgrep(
    paths: List[str],
    repo_root: str,
    config: Optional[str] = None,
    exclude: Optional[List[str]] = None,
    timeout_s: int = 60,
) -> List[Dict[str, Any]]:
    semgrep_bin = _ensure_semgrep_available()
    cfgs = _resolve_configs(config, repo_root)

    includes = _compute_includes(paths, repo_root)
    excludes = _compute_excludes(exclude)

    if not includes:
        includes = ["bad.py", "bad2.py", "*bad*.py"]

    findings: List[Dict[str, Any]] = []
    floor = _severity_floor(os.getenv("PRSEC_SEMGREP_MIN_SEVERITY"))
    target = "."

    for inc_chunk in _chunk(includes, 200):
        cmd: List[str] = [
            semgrep_bin,
            "--metrics", "off",
            "--quiet",
            "--json",
            "--timeout", str(timeout_s),
            "--skip-unknown-extensions",
            "--no-rewrite-rule-ids",
            "--disable-version-check",
        ]
        for c in cfgs:
            cmd += ["--config", c]
        for e in excludes:
            cmd += ["--exclude", e]
        cmd.append(target)
        for inc in inc_chunk:
            cmd += ["--include", inc]

        try:
            proc = subprocess.run(
                cmd, cwd=repo_root, text=True,
                capture_output=True, check=False, timeout=timeout_s + 5
            )
        except subprocess.TimeoutExpired as e:
            raise SemgrepInvocationError(
                exit_code=124, cmd=cmd, stdout=e.stdout or "",
                stderr=f"Semgrep timed out after {timeout_s}s: {e.stderr or ''}",
            )

        if proc.returncode >= 2:
            raise SemgrepInvocationError(proc.returncode, cmd, proc.stdout or "", proc.stderr or "")

        data = _parse_json_or_raise(proc.stdout)
        for f in _normalize_results(data.get("results", []) or []):
            if floor and _sev_order(f["severity"]) < _sev_order(floor):
                continue
            findings.append(f)

    dedup: Dict[Tuple[str, int, int, str], Dict[str, Any]] = {}
    for f in findings:
        key = (f["path"], int(f["start_line"]), int(f["end_line"]), f.get("rule_id") or "")
        dedup[key] = f
    return list(dedup.values())

def to_github_annotations(
    findings: List[Dict[str, Any]],
    max_per_file: Optional[int] = None,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    per_file_count: Dict[str, int] = {}
    for f in findings:
        path = f.get("path") or ""
        if max_per_file:
            c = per_file_count.get(path, 0)
            if c >= max_per_file:
                continue
            per_file_count[path] = c + 1
        level = _severity_to_annotation_level(f.get("severity", "LOW"))
        title = f.get("title") or f.get("rule_id") or "Semgrep finding"
        meta: List[str] = []
        if f.get("rule_id"): meta.append(f"Rule: {f['rule_id']}")
        if f.get("cwe"):     meta.append(f"CWE: {f['cwe']}")
        if f.get("owasp"):   meta.append(f"OWASP: {f['owasp']}")
        if f.get("fix"):     meta.append(f"Suggested fix: {f['fix']}")
        ann: Dict[str, Any] = {
            "path": path,
            "start_line": int(f.get("start_line", 1)),
            "end_line": int(f.get("end_line", f.get("start_line", 1))),
            "annotation_level": level,
            "title": title,
            "message": f.get("message") or title,
        }
        if meta: ann["raw_details"] = "\n".join(meta)
        out.append(ann)
    return out

def summarize_findings(findings: List[Dict[str, Any]]) -> Tuple[Dict[str, int], str]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = (f.get("severity") or "LOW").upper()
        if sev in counts: counts[sev] += 1
    md = [
        "### PR security reviewer — Semgrep summary",
        "",
        f"- **Critical:** {counts['CRITICAL']}",
        f"- **High:** {counts['HIGH']}",
        f"- **Medium:** {counts['MEDIUM']}",
        f"- **Low:** {counts['LOW']}",
    ]
    return counts, "\n".join(md)

# ---------------- internals ----------------

def _ensure_semgrep_available() -> str:
    exe = shutil.which(os.getenv("SEMGREP_BIN") or "semgrep")
    if not exe:
        raise SemgrepInvocationError(
            exit_code=127,
            cmd=[os.getenv("SEMGREP_BIN") or "semgrep", "--version"],
            stdout="",
            stderr="Semgrep CLI not found. Install (`brew install semgrep` or `pipx install semgrep`) or set SEMGREP_BIN.",
        )
    return exe

def _resolve_configs(cfg: Optional[str], repo_root: str) -> List[str]:
    raw = (
        cfg
        or os.getenv("SEMGREP_CONFIG")
        or os.getenv("PRSEC_SEMGREP_MIN_CONFIGS")
        or "p/security-audit,p/python,p/bandit"
    )
    parts = _split_csv(raw)
    out: List[str] = []
    abs_repo = os.path.abspath(repo_root)
    for val in parts:
        if val.startswith(("p/", "r/")) or val in {"auto", "semgrep-auto"} or val.startswith(("http://", "https://")):
            out.append(val)
        elif _looks_like_path(val):
            out.append(os.path.abspath(os.path.join(abs_repo, val)))
        else:
            out.append(val)
    return out

def _compute_includes(paths: List[str], repo_root: str) -> List[str]:
    abs_repo = os.path.abspath(repo_root)
    includes: List[str] = []
    for p in paths or []:
        rel = _rel_to_repo_root(p, abs_repo)
        full = os.path.join(abs_repo, rel)
        if os.path.isfile(full):
            includes.append(rel)

    always_env = os.getenv("PRSEC_ALWAYS_INCLUDE_PATTERNS", "").strip()
    if always_env:
        includes.extend(_split_csv(always_env))
    else:
        includes.extend(["bad.py", "bad2.py", "*bad*.py"])

    if _truthy(os.getenv("PRSEC_INCLUDE_ALL_PY")):
        includes.append("**/*.py")

    seen = set(); deduped: List[str] = []
    for g in includes:
        g = g.strip()
        if g and g not in seen:
            seen.add(g); deduped.append(g)
    return deduped

def _compute_excludes(extra: Optional[List[str]]) -> List[str]:
    out = [".venv", "venv", ".git", "node_modules", "__pycache__"]
    env_ex = os.getenv("SEMGREP_EXCLUDE", "")
    out.extend([e for e in _split_csv(env_ex) if e])
    if extra: out.extend([e for e in extra if e])
    seen = set(); deduped: List[str] = []
    for e in out:
        if e not in seen:
            seen.add(e); deduped.append(e)
    return deduped

def _split_csv(s: str) -> List[str]:
    return [x.strip() for x in (s or "").split(",") if x.strip()]

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
        if isinstance(cwe_val, list):   cwe = ", ".join(map(str, cwe_val))
        elif isinstance(cwe_val, str):  cwe = cwe_val
        else:                           cwe = None

        owasp_val = meta.get("owasp") or meta.get("owasp_category")
        if isinstance(owasp_val, list): owasp = ", ".join(map(str, owasp_val))
        elif isinstance(owasp_val, str): owasp = owasp_val
        else:                            owasp = None

        title = extra.get("message") or r.get("check_id") or "Semgrep finding"

        yield {
            "path": r.get("path"),
            "start_line": int(start.get("line") or 1),
            "end_line": int(end.get("line") or start.get("line") or 1),
            "severity": sev,
            "rule_id": r.get("check_id") or "",
            "title": title,
            "message": extra.get("message") or "",
            "fix": extra.get("fix") or meta.get("fix"),
            "cwe": cwe,
            "owasp": owasp,
        }

def _rel_to_repo_root(path: str, repo_root_abs: str) -> str:
    abs_path = os.path.abspath(os.path.join(repo_root_abs, path))
    try:
        return os.path.relpath(abs_path, repo_root_abs)
    except ValueError:
        return os.path.basename(path)

def _normalize_severity(s: str) -> str:
    s = (s or "").strip().upper()
    if s in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}: return s
    if s in {"BLOCKER"}:  return "CRITICAL"
    if s in {"ERROR"}:    return "HIGH"
    if s in {"WARNING","WARN"}: return "MEDIUM"
    return "LOW"

def _severity_floor(raw: Optional[str]) -> Optional[str]:
    if raw is None: return None
    val = (raw or "").strip().upper()
    if val in {"", "NONE", "OFF", "DISABLE"}: return None
    return _normalize_severity(val)

def _severity_to_annotation_level(sev: str) -> str:
    sev = (sev or "LOW").upper()
    if sev in {"CRITICAL","HIGH"}: return "failure"
    if sev == "MEDIUM":            return "warning"
    return "notice"

def _sev_order(sev: str) -> int:
    m = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return m.get((sev or "").upper(), 1)

def _chunk(items: List[str], size: int) -> Iterable[List[str]]:
    for i in range(0, len(items), size):
        yield items[i: i + size]

def _truthy(s: Optional[str]) -> bool:
    return (s or "").strip().lower() in {"1", "true", "yes", "y", "on"}

def _fmt_semgrep_error(cmd: List[str], code: int, stderr: str) -> str:
    return (
        f"Semgrep failed (exit={code}).\n"
        f"Command: {shlex.join(cmd)}\n"
        f"STDERR (truncated):\n{(stderr or '').strip()[:800]}"
    )
