# analyzers/semgrep_runner.py
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple


# =============================== Public API ===================================

@dataclass
class SemgrepInvocationError(Exception):
    exit_code: int
    cmd: List[str]
    stdout: str
    stderr: str

    def __str__(self) -> str:
        stderr_sample = (self.stderr or "").strip()[:800]
        return (
            f"Semgrep failed (exit={self.exit_code}).\n"
            f"Command: {shlex.join(self.cmd)}\n"
            f"STDERR (truncated):\n{stderr_sample}"
        )


class SemgrepRunner:
    """
    Class-based Semgrep runner for PR security reviewer.

    Usage:
        runner = SemgrepRunner(repo_root="/path/to/repo", config=None)
        findings = runner.run(paths=["app.py", "src/"])
        annotations = SemgrepRunner.to_github_annotations(findings, max_per_file=5)
        counts, md = SemgrepRunner.summarize_findings(findings)
    """

    # ---------- Construction ----------

    def __init__(
        self,
        repo_root: str,
        config: Optional[str] = None,
        exclude: Optional[List[str]] = None,
        timeout_s: int = 60,
        min_severity_env_var: str = "PRSEC_SEMGREP_MIN_SEVERITY",
    ) -> None:
        self.repo_root = os.path.abspath(repo_root)
        self.config = self._resolve_config(config, self.repo_root)
        self.exclude = exclude or []
        self.timeout_s = timeout_s
        self.severity_floor = self._severity_floor(os.getenv(min_severity_env_var))
        self.semgrep_bin = self._ensure_semgrep_available()

    # ---------- Primary ops ----------

    def run(self, paths: List[str]) -> List[Dict[str, Any]]:
        """
        Run Semgrep on provided file/directory paths (absolute or relative to repo_root).
        Returns a list of normalized findings.
        """
        if not paths:
            return []

        rel_paths = [self._rel_to_repo_root(p, self.repo_root) for p in paths]
        findings: List[Dict[str, Any]] = []

        # Semgrep returns rc=0 (no findings), rc=1 (findings), rc>=2 (error)
        for chunk in self._chunk(rel_paths, 200):
            cmd = [
                self.semgrep_bin,
                "--config",
                self.config,
                "--json",
                "--timeout",
                str(self.timeout_s),
                "--skip-unknown-extensions",
                "--no-rewrite-rule-ids",
                "--disable-version-check",
                "--metrics=off",
                "--quiet",
            ]
            for pat in self.exclude:
                cmd += ["--exclude", pat]
            cmd += chunk

            try:
                proc = subprocess.run(
                    cmd,
                    cwd=self.repo_root,
                    text=True,
                    capture_output=True,
                    check=False,
                )
            except subprocess.TimeoutExpired as e:
                raise SemgrepInvocationError(
                    exit_code=124,
                    cmd=cmd,
                    stdout="",
                    stderr=f"Semgrep timed out after {self.timeout_s}s: {e}",
                )

            if proc.returncode >= 2:
                raise SemgrepInvocationError(
                    proc.returncode, cmd, proc.stdout or "", proc.stderr or ""
                )

            data = self._parse_json_or_raise(proc.stdout)
            for f in self._normalize_results(data.get("results", []) or []):
                if self.severity_floor and self._sev_order(f["severity"]) < self._sev_order(self.severity_floor):
                    continue
                findings.append(f)

        return findings

    @staticmethod
    def to_github_annotations(
        findings: List[Dict[str, Any]],
        max_per_file: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Convert normalized findings → GitHub Checks annotations.
        """
        out: List[Dict[str, Any]] = []
        per_file_count: Dict[str, int] = {}

        for f in findings:
            path = f["path"] or ""
            if max_per_file:
                c = per_file_count.get(path, 0)
                if c >= max_per_file:
                    continue
                per_file_count[path] = c + 1

            level = SemgrepRunner._severity_to_annotation_level(f.get("severity", "LOW"))
            title = f.get("title") or f.get("rule_id") or "Semgrep finding"

            meta_parts: List[str] = []
            if f.get("rule_id"):
                meta_parts.append(f"Rule: {f['rule_id']}")
            if f.get("cwe"):
                meta_parts.append(f"CWE: {f['cwe']}")
            if f.get("owasp"):
                meta_parts.append(f"OWASP: {f['owasp']}")
            if f.get("fix"):
                meta_parts.append(f"Suggested fix: {f['fix']}")

            out.append(
                {
                    "path": path,
                    "start_line": int(f.get("start_line") or 1),
                    "end_line": int(f.get("end_line") or f.get("start_line") or 1),
                    "annotation_level": level,  # failure | warning | notice
                    "title": title,
                    "message": f.get("message") or title,
                    "raw_details": "\n".join(meta_parts) or None,
                }
            )

        return out

    @staticmethod
    def summarize_findings(findings: List[Dict[str, Any]]) -> Tuple[Dict[str, int], str]:
        """
        Return (counts_by_severity, markdown_summary).
        """
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = (f.get("severity") or "LOW").upper()
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

    @staticmethod
    def _ensure_semgrep_available() -> str:
        """Return the Semgrep executable path or raise."""
        bin_env = os.getenv("SEMGREP_BIN")
        exe = shutil.which(bin_env) if bin_env else shutil.which("semgrep")
        if not exe:
            cmd = [bin_env or "semgrep", "--version"]
            raise SemgrepInvocationError(
                exit_code=127,
                cmd=cmd,
                stdout="",
                stderr=(
                    "Semgrep CLI not found. Install with `pip install semgrep` or `brew install semgrep`, "
                    "or point to the binary via SEMGREP_BIN."
                ),
            )
        return exe

    @staticmethod
    def _resolve_config(cfg: Optional[str], repo_root: str) -> str:
        """
        Resolve SEMGREP config:
          - if cfg is provided, use it
          - else use env SEMGREP_CONFIG (or typo SEMGRP_CONFIG), else 'p/ci'
          - if it looks like a path, make it absolute relative to repo_root
        """
        value = cfg or os.getenv("SEMGREP_CONFIG") or os.getenv("SEMGRP_CONFIG") or "p/ci"
        if SemgrepRunner._looks_like_path(value):
            abs_repo = os.path.abspath(repo_root)
            abs_path = os.path.abspath(os.path.join(abs_repo, value))
            return abs_path
        return value

    @staticmethod
    def _looks_like_path(s: str) -> bool:
        return any(sep in s for sep in ("/", "\\", os.sep)) or s.endswith((".yml", ".yaml"))

    @staticmethod
    def _parse_json_or_raise(stdout: str) -> Dict[str, Any]:
        try:
            return json.loads(stdout or "{}")
        except json.JSONDecodeError as e:
            sample = (stdout or "").strip()[:800]
            raise SemgrepInvocationError(
                exit_code=65, cmd=["semgrep", "--json"], stdout=sample, stderr=str(e)
            )

    @staticmethod
    def _normalize_results(results: Iterable[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
        for r in results:
            extra = r.get("extra", {}) or {}
            meta = extra.get("metadata", {}) or {}
            start = r.get("start", {}) or {}
            end = r.get("end", {}) or {}

            # Severity normalization
            sev = SemgrepRunner._normalize_severity(
                meta.get("severity") or extra.get("severity") or "LOW"
            )

            # Optional metadata: handle strings/ints/lists/dicts robustly
            cwe_raw = meta.get("cwe") or meta.get("cwe_id") or meta.get("cwe_id_vuln")
            cwe = SemgrepRunner._first_str(SemgrepRunner._flatten_to_strings(cwe_raw), prefix="CWE-")

            owasp_raw = meta.get("owasp")
            owasp = SemgrepRunner._first_str(SemgrepRunner._flatten_to_strings(owasp_raw))

            title = extra.get("message") or r.get("check_id") or "Semgrep finding"

            # Lines: clamp to sensible bounds; GH checks rejects zeros/negatives or inverted ranges
            start_line = max(1, int(start.get("line") or 1))
            end_line = max(start_line, int(end.get("line") or start.get("line") or 1))

            yield {
                "path": r.get("path"),
                "start_line": start_line,
                "end_line": end_line,
                "severity": sev,
                "rule_id": r.get("check_id"),
                "title": title,
                "message": extra.get("message") or "",
                "fix": extra.get("fix") or meta.get("fix"),
                "cwe": cwe,
                "owasp": owasp,
            }

    @staticmethod
    def _rel_to_repo_root(path: str, repo_root: str) -> str:
        # Accept absolute or relative; return repo-relative
        abs_repo = os.path.abspath(repo_root)
        abs_path = os.path.abspath(os.path.join(abs_repo, path))
        try:
            return os.path.relpath(abs_path, abs_repo)
        except ValueError:
            # Different drive (Windows) — fall back to basename
            return os.path.basename(path)

    @staticmethod
    def _normalize_severity(s: str) -> str:
        s = (s or "").strip().upper()
        if s in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            return s
        # Semgrep legacy levels → our scale
        if s in {"BLOCKER"}:
            return "CRITICAL"
        if s in {"ERROR"}:
            return "HIGH"
        if s in {"WARNING"}:
            return "MEDIUM"
        # INFO/UNKNOWN → LOW
        return "LOW"

    @staticmethod
    def _severity_to_annotation_level(sev: str) -> str:
        sev = (sev or "LOW").upper()
        if sev in {"CRITICAL", "HIGH"}:
            return "failure"
        if sev == "MEDIUM":
            return "warning"
        return "notice"

    @staticmethod
    def _sev_order(sev: str) -> int:
        """For filtering: LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4."""
        m = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return m.get((sev or "").upper(), 1)

    @staticmethod
    def _chunk(items: List[str], size: int) -> Iterable[List[str]]:
        for i in range(0, len(items), size):
            yield items[i : i + size]

    @staticmethod
    def _severity_floor(s: Optional[str]) -> Optional[str]:
        """
        Normalize/validate a minimum severity threshold.
        Accepts: CRITICAL/HIGH/MEDIUM/LOW (case-insensitive) and legacy INFO/ERROR/WARNING/BLOCKER.
        Returns normalized level or None if unset/invalid.
        """
        if not s:
            return None
        return SemgrepRunner._normalize_severity(s)

    @staticmethod
    def _flatten_to_strings(v: Any) -> List[str]:
        """
        Normalize Semgrep metadata fields that may be strings, ints, dicts, or lists thereof,
        returning a flat list of string tokens.
        """
        out: List[str] = []

        def _walk(x: Any) -> None:
            if x is None:
                return
            if isinstance(x, (str, int)):
                out.append(str(x))
                return
            if isinstance(x, dict):
                for val in x.values():
                    _walk(val)
                return
            if isinstance(x, (list, tuple, set)):
                for it in x:
                    _walk(it)
                return

        _walk(v)
        return out

    @staticmethod
    def _first_str(values: List[str], prefix: Optional[str] = None) -> Optional[str]:
        """
        Return the first non-empty string, optionally ensuring it carries a prefix (e.g., "CWE-").
        If a numeric-like token is given with a prefix requirement, it will be prefixed.
        """
        for s in values:
            t = s.strip()
            if not t:
                continue
            if prefix:
                # If already has prefix (case-insensitive), keep as-is
                if t.upper().startswith(prefix.upper()):
                    return t
                # If looks numeric, add prefix
                if t.isdigit():
                    return f"{prefix}{t.lstrip()}"
            return t
        return None


# ========================== Back-compat function shims =========================

def run_semgrep(
    paths: List[str],
    repo_root: str,
    config: Optional[str] = None,
    exclude: Optional[List[str]] = None,
    timeout_s: int = 60,
) -> List[Dict[str, Any]]:
    """
    Backward-compatible function wrapper around SemgrepRunner.run().
    """
    runner = SemgrepRunner(repo_root=repo_root, config=config, exclude=exclude, timeout_s=timeout_s)
    return runner.run(paths)


def to_github_annotations(
    findings: List[Dict[str, Any]],
    max_per_file: Optional[int] = None,
) -> List[Dict[str, Any]]:
    return SemgrepRunner.to_github_annotations(findings, max_per_file=max_per_file)


def summarize_findings(findings: List[Dict[str, Any]]) -> Tuple[Dict[str, int], str]:
    return SemgrepRunner.summarize_findings(findings)
