import re
from typing import List, Dict

# Simple, explainable rules operating on added lines only (lines starting with '+')

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "Looks like an AWS Access Key ID"),
    (r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{12,}[\"']", "Hardcoded credential")
]

REQ_NO_TIMEOUT = re.compile(r"requests\.(get|post|put|delete|patch)\(.*\)")
SQL_FSTRING = re.compile(r"(execute|executemany)\(f[\"'].*[{].*[}]")

ALLOW_FILE_EXT = {"py", "js", "ts", "java", "go", "rb"}


class Analyzer:
    def scan_patch(self, filename: str, patch: str) -> List[Dict]:
        findings: List[Dict] = []
        ext = filename.split(".")[-1].lower()
        if ext not in ALLOW_FILE_EXT:
            return findings

        line_no = 0
        for line in patch.splitlines():
            # Unified diff header lines start with @@ -a,b +c,d @@; track added-line counter
            if line.startswith("@@"):
                try:
                    # example: @@ -10,7 +10,8 @@
                    plus = line.split("+")[1]
                    start = int(plus.split(",")[0])
                    line_no = start - 1
                except Exception:
                    pass
                continue
            if line.startswith("+") and not line.startswith("+++"):
                line_no += 1
                code = line[1:]
                # Rule: secrets
                for pat, msg in SECRET_PATTERNS:
                    if re.search(pat, code):
                        findings.append({
                            "rule": "secret.hardcoded",
                            "file": filename,
                            "line": line_no,
                            "message": msg,
                            "suggestion": "Move to a secret manager / env var"
                        })
                        break
                # Rule: requests without timeout (Python)
                if REQ_NO_TIMEOUT.search(code) and "timeout=" not in code:
                    findings.append({
                        "rule": "py.requests.no-timeout",
                        "file": filename,
                        "line": line_no,
                        "message": "requests call without explicit timeout",
                        "suggestion": "add timeout=5 (or per policy)"
                    })
                # Rule: raw SQL with f-strings (Python)
                if SQL_FSTRING.search(code):
                    findings.append({
                        "rule": "py.sql.fstring",
                        "file": filename,
                        "line": line_no,
                        "message": "Potential SQL injection via f-string",
                        "suggestion": "Use parameterized queries (placeholders, params tuple)"
                    })
            elif line.startswith(" "):
                line_no += 1
        return findings

    def summarize(self, findings: List[Dict]) -> Dict:
        total = len(findings)
        by_rule = {}
        for f in findings:
            by_rule[f["rule"]] = by_rule.get(f["rule"], 0) + 1
        status = "No issues found" if total == 0 else f"{total} issue(s): " + ", ".join(f"{k}={v}" for k,v in by_rule.items())
        return {"total": total, "by_rule": by_rule, "status_line": status}