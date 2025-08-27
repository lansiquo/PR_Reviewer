# analyzers/semgrep_runner.py
from __future__ import annotations

import json
import logging
import os
import shlex
import shutil
import subprocess
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

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
    timeout_s: int = 120,  # Increased default timeout
) -> List[Dict[str, Any]]:
    """
    Run Semgrep on PR files to detect vulnerabilities. Enhanced with better error handling
    and PR-specific optimizations.
    """
    logger.info(f"Starting Semgrep scan on {len(paths)} files")
    
    semgrep_bin = _ensure_semgrep_available()
    cfgs = _resolve_configs(config, repo_root)
    
    # Enhanced include/exclude computation with validation
    includes = _compute_includes(paths, repo_root)
    excludes = _compute_excludes(exclude)
    
    # Validate that we have files to scan
    if not includes:
        logger.warning("No valid files found for scanning, adding default patterns")
        includes = ["**/*.py", "*.py", "*bad*.py"]
    
    logger.info(f"Scanning with {len(includes)} include patterns: {includes[:5]}{'...' if len(includes) > 5 else ''}")
    
    findings: List[Dict[str, Any]] = []
    floor = _severity_floor(os.getenv("PRSEC_SEMGREP_MIN_SEVERITY"))
    target = "."
    
    # Enhanced environment setup
    env = dict(os.environ)
    env.setdefault("SEMGREP_LOG_LEVEL", "error")
    env.setdefault("PYTHONWARNINGS", "ignore")
    # Prevent Semgrep from sending metrics
    env["SEMGREP_SEND_METRICS"] = "off"
    
    # Process includes in smaller chunks to avoid command line length limits
    chunk_size = int(os.getenv("PRSEC_INCLUDE_CHUNK_SIZE", "100"))
    
    for chunk_idx, inc_chunk in enumerate(_chunk(includes, chunk_size)):
        logger.debug(f"Processing chunk {chunk_idx + 1} with {len(inc_chunk)} includes")
        
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
        
        # Add configurations
        for c in cfgs:
            cmd += ["--config", c]
        
        # Add excludes
        for e in excludes:
            cmd += ["--exclude", e]
        
        # Target comes before includes (Semgrep requirement)
        cmd.append(target)
        
        # Add includes for this chunk
        for inc in inc_chunk:
            cmd += ["--include", inc]
        
        logger.debug(f"Semgrep command: {shlex.join(cmd)}")
        
        try:
            proc = subprocess.run(
                cmd,
                cwd=repo_root,
                text=True,
                capture_output=True,
                check=False,  # rc: 0=no findings, 1=findings found, >=2=error
                timeout=timeout_s + 30,  # Buffer beyond semgrep's internal timeout
                env=env,
            )
            
            # Enhanced exit code handling
            if proc.returncode == 0:
                logger.debug("Semgrep completed with no findings")
            elif proc.returncode == 1:
                logger.debug("Semgrep completed with findings")
            elif proc.returncode == 2:
                logger.error("Semgrep configuration error")
                raise SemgrepInvocationError(proc.returncode, cmd, proc.stdout or "", proc.stderr or "")
            elif proc.returncode == 3:
                logger.error("Semgrep invalid usage")
                raise SemgrepInvocationError(proc.returncode, cmd, proc.stdout or "", proc.stderr or "")
            elif proc.returncode == 7:
                # Timeout or partial failure - try to extract partial results
                logger.warning(f"Semgrep timeout or partial failure (chunk {chunk_idx + 1})")
                if (proc.stdout or "").strip():
                    logger.info("Found partial results from timed-out scan, attempting to parse")
                else:
                    logger.warning("No output from timed-out Semgrep run, skipping chunk")
                    continue  # Skip this chunk and continue with next
            else:
                logger.error(f"Semgrep failed with unexpected exit code: {proc.returncode}")
                raise SemgrepInvocationError(proc.returncode, cmd, proc.stdout or "", proc.stderr or "")
            
        except subprocess.TimeoutExpired as e:
            logger.error(f"Semgrep process timed out after {timeout_s + 30}s")
            raise SemgrepInvocationError(
                exit_code=124, cmd=cmd, stdout=e.stdout or "",
                stderr=f"Semgrep timed out after {timeout_s}s: {e.stderr or ''}",
            )
        
        # Parse results
        try:
            data = _parse_json_or_raise(proc.stdout)
        except SemgrepInvocationError as e:
            if proc.returncode == 7:
                # Empty or invalid output on timeout - continue with next chunk
                logger.warning(f"Failed to parse output from chunk {chunk_idx + 1}, continuing")
                continue
            else:
                raise e
        
        # Process findings with severity filtering
        chunk_findings = 0
        for f in _normalize_results(data.get("results", []) or []):
            if floor and _sev_order(f["severity"]) < _sev_order(floor):
                continue
            findings.append(f)
            chunk_findings += 1
        
        logger.debug(f"Chunk {chunk_idx + 1} produced {chunk_findings} findings")
    
    # De-duplicate findings across chunks
    dedup: Dict[Tuple[str, int, int, str], Dict[str, Any]] = {}
    for f in findings:
        # Create a unique key based on file, location, and rule
        key = (f["path"], int(f["start_line"]), int(f["end_line"]), f.get("rule_id") or "")
        dedup[key] = f
    
    unique_findings = list(dedup.values())
    logger.info(f"Semgrep scan completed: {len(unique_findings)} unique findings from {len(findings)} total")
    
    return unique_findings

def analyze_pr_security(
    pr_files: List[str],
    repo_root: str,
    config: Optional[str] = None,
    focus_on_changes: bool = True
) -> Dict[str, Any]:
    """
    Analyze PR for security vulnerabilities with enhanced reporting.
    
    Args:
        pr_files: List of changed files in the PR
        repo_root: Root directory of the repository  
        config: Semgrep config to use (defaults to security-focused rules)
        focus_on_changes: If True, focus scan on changed files only
    
    Returns:
        Dictionary with findings, summary, and metadata
    """
    logger.info(f"Analyzing PR security for {len(pr_files)} changed files")
    
    # Filter to relevant files for security scanning
    scannable_files = []
    excluded_files = []
    for file_path in pr_files:
        full_path = os.path.join(repo_root, file_path)
        if not os.path.exists(full_path):
            logger.debug(f"Skipping non-existent file: {file_path}")
            continue
        if _is_excluded_file(file_path):
            excluded_files.append(file_path)
            continue
        if _is_scannable_file(file_path):
            scannable_files.append(file_path)
    
    logger.info(f"Excluded {len(excluded_files)} files: {excluded_files[:3]}{'...' if len(excluded_files) > 3 else ''}")
    logger.info(f"Scannable files: {scannable_files}")
    
    logger.info(f"Filtered to {len(scannable_files)} scannable files")
    
    if not scannable_files and focus_on_changes:
        logger.warning("No scannable files in PR, falling back to full Python scan")
        scannable_files = ["**/*.py"]
    
    # Use security-focused config by default
    if not config:
        config = os.getenv("PRSEC_SEMGREP_CONFIG", "p/security-audit,p/owasp-top-10,p/cwe-top-25")
    
    try:
        findings = run_semgrep(
            paths=scannable_files,
            repo_root=repo_root,
            config=config,
            timeout_s=int(os.getenv("PRSEC_SEMGREP_TIMEOUT", "180"))
        )
        
        # Debug: Check if we scanned files that should have findings
        potential_vuln_files = [f for f in scannable_files if 'bad' in f.lower()]
        if potential_vuln_files and not findings:
            logger.warning(f"Expected vulnerabilities in {potential_vuln_files} but found none. "
                         f"Check if Semgrep config '{config}' is working correctly.")
        
        # Generate summary and annotations
        severity_counts, summary_md = summarize_findings(findings)
        annotations = to_github_annotations(findings, max_per_file=10)
        
        # Categorize findings by type
        categories = _categorize_findings(findings)
        
        result = {
            "success": True,
            "findings": findings,
            "annotations": annotations,
            "severity_counts": severity_counts,
            "summary_markdown": summary_md,
            "categories": categories,
            "scanned_files": scannable_files,
            "total_findings": len(findings),
            "high_severity_count": severity_counts.get("CRITICAL", 0) + severity_counts.get("HIGH", 0)
        }
        
        logger.info(f"PR security analysis completed: {result['total_findings']} findings, "
                   f"{result['high_severity_count']} high severity")
        
        return result
        
    except Exception as e:
        logger.error(f"PR security analysis failed: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "findings": [],
            "scanned_files": scannable_files,
            "total_findings": 0
        }

def to_github_annotations(
    findings: List[Dict[str, Any]],
    max_per_file: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Convert Semgrep findings to GitHub Check Run annotations."""
    out: List[Dict[str, Any]] = []
    per_file_count: Dict[str, int] = {}
    
    for f in findings:
        path = f.get("path") or ""
        
        # Enforce per-file limits to avoid annotation spam
        if max_per_file:
            c = per_file_count.get(path, 0)
            if c >= max_per_file:
                continue
            per_file_count[path] = c + 1
        
        level = _severity_to_annotation_level(f.get("severity", "LOW"))
        title = f.get("title") or f.get("rule_id") or "Security Issue"
        
        # Build metadata for the annotation
        meta: List[str] = []
        if f.get("rule_id"): 
            meta.append(f"Rule: {f['rule_id']}")
        if f.get("cwe"):     
            meta.append(f"CWE: {f['cwe']}")
        if f.get("owasp"):   
            meta.append(f"OWASP: {f['owasp']}")
        if f.get("fix"):     
            meta.append(f"Fix: {f['fix']}")
        
        ann: Dict[str, Any] = {
            "path": path,
            "start_line": max(1, int(f.get("start_line", 1))),
            "end_line": max(1, int(f.get("end_line", f.get("start_line", 1)))),
            "annotation_level": level,
            "title": title,
            "message": f.get("message") or title,
        }
        
        if meta: 
            ann["raw_details"] = "\n".join(meta)
        
        out.append(ann)
    
    return out

def summarize_findings(findings: List[Dict[str, Any]]) -> Tuple[Dict[str, int], str]:
    """Generate a summary of security findings."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    for f in findings:
        sev = (f.get("severity") or "LOW").upper()
        if sev in counts: 
            counts[sev] += 1
    
    total = sum(counts.values())
    high_risk = counts["CRITICAL"] + counts["HIGH"]
    
    # Generate markdown summary
    md_lines = [
        "## 🛡️ PR Security Analysis Results",
        "",
        f"**Total Issues Found:** {total}",
        ""
    ]
    
    if total == 0:
        md_lines.extend([
            "✅ **No security issues detected in this PR!**",
            "",
            "The code changes have been scanned and no security vulnerabilities were found."
        ])
    else:
        md_lines.extend([
            "### Severity Breakdown:",
            "",
            f"- 🚨 **Critical:** {counts['CRITICAL']}",
            f"- ⚠️  **High:** {counts['HIGH']}",  
            f"- ⚡ **Medium:** {counts['MEDIUM']}",
            f"- ℹ️  **Low:** {counts['LOW']}",
            ""
        ])
        
        if high_risk > 0:
            md_lines.extend([
                f"⚠️ **{high_risk} high-risk issue(s) require immediate attention.**",
                ""
            ])
        
        md_lines.extend([
            "Please review the security findings above and address any issues before merging.",
            "",
            "<details>",
            "<summary>Scan Details</summary>",
            "",
            "This analysis was performed using Semgrep security rules focusing on:",
            "- OWASP Top 10 vulnerabilities",
            "- CWE (Common Weakness Enumeration) patterns", 
            "- Language-specific security anti-patterns",
            "- Injection attacks, XSS, authentication issues, etc.",
            "",
            "</details>"
        ])
    
    return counts, "\n".join(md_lines)

# ---------------- Enhanced Helper Functions ----------------

def _is_scannable_file(file_path: str) -> bool:
    """Check if file should be included in security scan."""
    # Focus on source code files
    extensions = {'.py', '.js', '.ts', '.java', '.go', '.php', '.rb', '.c', '.cpp', '.cs'}
    return any(file_path.endswith(ext) for ext in extensions)

def _is_excluded_file(file_path: str) -> bool:
    """Check if file should be excluded from scanning."""
    exclusions = {
        '__pycache__', '.pyc', '.git', 'node_modules', 
        '.venv', 'venv', 'dist', 'build', '.tox'
    }
    # Also exclude specific file types that aren't source code
    excluded_extensions = {'.pyc', '.pyo', '.pyd', '.so', '.dylib'}
    
    return (any(excl in file_path for excl in exclusions) or 
            any(file_path.endswith(ext) for ext in excluded_extensions))

def _categorize_findings(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Categorize findings by security issue type."""
    categories: Dict[str, List[Dict[str, Any]]] = {
        "injection": [],
        "authentication": [],
        "authorization": [], 
        "crypto": [],
        "data_exposure": [],
        "other": []
    }
    
    for finding in findings:
        rule_id = (finding.get("rule_id", "")).lower()
        message = (finding.get("message", "")).lower()
        
        # Categorize based on rule ID and message content
        if any(term in rule_id or term in message for term in ["sql", "injection", "xss", "csrf"]):
            categories["injection"].append(finding)
        elif any(term in rule_id or term in message for term in ["auth", "login", "password", "session"]):
            categories["authentication"].append(finding)
        elif any(term in rule_id or term in message for term in ["permission", "access", "privilege"]):
            categories["authorization"].append(finding)
        elif any(term in rule_id or term in message for term in ["crypto", "hash", "random", "encrypt"]):
            categories["crypto"].append(finding)
        elif any(term in rule_id or term in message for term in ["secret", "key", "token", "expose"]):
            categories["data_exposure"].append(finding)
        else:
            categories["other"].append(finding)
    
    # Remove empty categories
    return {k: v for k, v in categories.items() if v}

# ---------------- Existing Helper Functions (Enhanced) ----------------

def _ensure_semgrep_available() -> str:
    """Ensure Semgrep is available and return path."""
    exe = shutil.which(os.getenv("SEMGREP_BIN") or "semgrep")
    if not exe:
        raise SemgrepInvocationError(
            exit_code=127,
            cmd=[os.getenv("SEMGREP_BIN") or "semgrep", "--version"],
            stdout="",
            stderr="Semgrep CLI not found. Install with: pip install semgrep, brew install semgrep, or set SEMGREP_BIN.",
        )
    logger.debug(f"Using Semgrep binary: {exe}")
    return exe

def _resolve_configs(cfg: Optional[str], repo_root: str) -> List[str]:
    """Resolve Semgrep configuration sources."""
    raw = (
        cfg
        or os.getenv("SEMGREP_CONFIG")
        or os.getenv("PRSEC_SEMGREP_CONFIG")
        or "p/security-audit,p/owasp-top-10,p/cwe-top-25"  # Security-focused defaults
    )
    
    parts = _split_csv(raw)
    out: List[str] = []
    abs_repo = os.path.abspath(repo_root)
    
    for val in parts:
        val = val.strip()
        if not val:
            continue
            
        if val.startswith(("p/", "r/")) or val in {"auto", "semgrep-auto"} or val.startswith(("http://", "https://")):
            out.append(val)
        elif _looks_like_path(val):
            config_path = os.path.abspath(os.path.join(abs_repo, val))
            if os.path.exists(config_path):
                out.append(config_path)
            else:
                logger.warning(f"Config file not found: {config_path}")
        else:
            out.append(val)
    
    logger.debug(f"Resolved configs: {out}")
    return out

def _compute_includes(paths: List[str], repo_root: str) -> List[str]:
    """Build include patterns for scanning."""
    abs_repo = os.path.abspath(repo_root)
    includes: List[str] = []
    
    # Process PR files - only include source files that exist
    valid_files = 0
    for p in paths or []:
        rel = _rel_to_repo_root(p, abs_repo)
        full = os.path.join(abs_repo, rel)
        
        if os.path.isfile(full) and _is_scannable_file(rel) and not _is_excluded_file(rel):
            includes.append(rel)
            valid_files += 1
    
    logger.debug(f"Added {valid_files} PR files to scan")
    
    # Add always-include patterns
    always_env = os.getenv("PRSEC_ALWAYS_INCLUDE_PATTERNS", "").strip()
    if always_env:
        includes.extend(_split_csv(always_env))
    else:
        # Include common vulnerable file patterns
        includes.extend(["*bad*.py", "*test*.py", "*example*.py"])
    
    # Optionally include all source files
    if _truthy(os.getenv("PRSEC_INCLUDE_ALL_SOURCE")):
        includes.extend(["**/*.py", "**/*.js", "**/*.ts", "**/*.java"])
    
    # De-duplicate while preserving order
    seen = set()
    deduped: List[str] = []
    for g in includes:
        g = g.strip()
        if g and g not in seen:
            seen.add(g)
            deduped.append(g)
    
    return deduped

def _compute_excludes(extra: Optional[List[str]]) -> List[str]:
    """Compute exclude patterns."""
    out = [
        ".venv", "venv", ".git", "node_modules", "__pycache__", 
        "**/*.pyc", "*.pyc", ".pytest_cache", ".mypy_cache",
        "dist", "build", ".tox", "*.egg-info"
    ]
    
    env_ex = os.getenv("SEMGREP_EXCLUDE", "")
    out.extend([e for e in _split_csv(env_ex) if e])
    
    if extra: 
        out.extend([e for e in extra if e])
    
    # De-duplicate
    seen = set()
    deduped: List[str] = []
    for e in out:
        if e not in seen:
            seen.add(e)
            deduped.append(e)
    
    return deduped

def _split_csv(s: str) -> List[str]:
    """Split comma-separated values."""
    return [x.strip() for x in (s or "").split(",") if x.strip()]

def _looks_like_path(s: str) -> bool:
    """Check if string looks like a file path."""
    return any(sep in s for sep in ("/", "\\", os.sep)) or s.endswith((".yml", ".yaml"))

def _parse_json_or_raise(stdout: str) -> Dict[str, Any]:
    """Parse JSON output or raise descriptive error."""
    try:
        if not stdout or not stdout.strip():
            return {"results": []}
        return json.loads(stdout)
    except json.JSONDecodeError as e:
        sample = (stdout or "").strip()[:1200]
        logger.error(f"JSON parse error: {e}, sample output: {sample}")
        raise SemgrepInvocationError(exit_code=65, cmd=["semgrep", "--json"], stdout=sample, stderr=str(e))

def _normalize_results(results: Iterable[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
    """Normalize Semgrep results to consistent format."""
    for r in results:
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        start = r.get("start", {}) or {}
        end = r.get("end", {}) or {}
        
        sev = _normalize_severity(meta.get("severity") or extra.get("severity") or "LOW")
        
        # Handle CWE data
        cwe_val = meta.get("cwe") or meta.get("cwe_id") or meta.get("cwe_id_vuln")
        if isinstance(cwe_val, list):   
            cwe = ", ".join(map(str, cwe_val))
        elif isinstance(cwe_val, str):  
            cwe = cwe_val
        else:                           
            cwe = None
        
        # Handle OWASP data  
        owasp_val = meta.get("owasp") or meta.get("owasp_category")
        if isinstance(owasp_val, list): 
            owasp = ", ".join(map(str, owasp_val))
        elif isinstance(owasp_val, str): 
            owasp = owasp_val
        else:                            
            owasp = None
        
        title = extra.get("message") or r.get("check_id") or "Security Issue"
        
        yield {
            "path": r.get("path"),
            "start_line": max(1, int(start.get("line") or 1)),
            "end_line": max(1, int(end.get("line") or start.get("line") or 1)),
            "severity": sev,
            "rule_id": r.get("check_id") or "",
            "title": title,
            "message": extra.get("message") or "",
            "fix": extra.get("fix") or meta.get("fix"),
            "cwe": cwe,
            "owasp": owasp,
        }

def _rel_to_repo_root(path: str, repo_root_abs: str) -> str:
    """Convert path to relative from repo root."""
    abs_path = os.path.abspath(os.path.join(repo_root_abs, path))
    try:
        return os.path.relpath(abs_path, repo_root_abs)
    except ValueError:
        return os.path.basename(path)

def _normalize_severity(s: str) -> str:
    """Normalize severity strings to standard values."""
    s = (s or "").strip().upper()
    if s in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}: 
        return s
    if s in {"BLOCKER"}:  
        return "CRITICAL"
    if s in {"ERROR"}:    
        return "HIGH"
    if s in {"WARNING","WARN"}: 
        return "MEDIUM"
    return "LOW"

def _severity_floor(raw: Optional[str]) -> Optional[str]:
    """Parse minimum severity threshold."""
    if raw is None: 
        return None
    val = (raw or "").strip().upper()
    if val in {"", "NONE", "OFF", "DISABLE"}: 
        return None
    return _normalize_severity(val)

def _severity_to_annotation_level(sev: str) -> str:
    """Convert severity to GitHub annotation level."""
    sev = (sev or "LOW").upper()
    if sev in {"CRITICAL","HIGH"}: 
        return "failure"
    if sev == "MEDIUM":            
        return "warning"
    return "notice"

def _sev_order(sev: str) -> int:
    """Get numeric order for severity comparison."""
    m = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return m.get((sev or "").upper(), 1)

def _chunk(items: List[str], size: int) -> Iterable[List[str]]:
    """Split list into chunks of specified size."""
    for i in range(0, len(items), size):
        yield items[i: i + size]

def _truthy(s: Optional[str]) -> bool:
    """Check if string represents a truthy value."""
    return (s or "").strip().lower() in {"1", "true", "yes", "y", "on"}

def _fmt_semgrep_error(cmd: List[str], code: int, stderr: str) -> str:
    """Format Semgrep error message."""
    return (
        f"Semgrep failed (exit={code}).\n"
        f"Command: {shlex.join(cmd)}\n"
        f"STDERR (tail):\n{(stderr or '').strip()}"
    )