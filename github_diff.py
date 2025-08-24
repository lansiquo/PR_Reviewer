# github_diff.py
import time
from typing import Dict, List, Tuple, Literal
import requests

GitStatus = Literal["added", "modified", "removed", "renamed", "copied", "changed", "unchanged"]

class GitHubClient:
    def __init__(self, token: str, base_url: str = "https://api.github.com"):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "pr-security-reviewer"
        })

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}{path}"
        # Simple retry for transient 5xx / secondary rate limits
        for attempt in range(5):
            resp = self.session.request(method, url, timeout=30, **kwargs)
            if resp.status_code in (502, 503, 504, 522, 524, 429):
                # Honor Retry-After if present
                pause = int(resp.headers.get("Retry-After", "2"))
                time.sleep(min(8, pause * (attempt + 1)))
                continue
            if resp.status_code == 403 and "secondary rate limit" in resp.text.lower():
                time.sleep(2 * (attempt + 1))
                continue
            resp.raise_for_status()
            return resp
        resp.raise_for_status()
        return resp

    def get_pr_shas(self, owner: str, repo: str, pr_number: int) -> Tuple[str, str]:
        """Return (base_sha, head_sha)."""
        r = self._request("GET", f"/repos/{owner}/{repo}/pulls/{pr_number}")
        j = r.json()
        return j["base"]["sha"], j["head"]["sha"]

    def get_changed_files(self, owner: str, repo: str, pr_number: int) -> List[Dict]:
        """
        Return a list of file-change dicts from the PR (all pages).
        Each item includes at least: filename, status, additions, deletions, changes, previous_filename (if renamed).
        """
        page = 1
        out: List[Dict] = []
        while True:
            r = self._request("GET", f"/repos/{owner}/{repo}/pulls/{pr_number}/files",
                              params={"per_page": 100, "page": page})
            items = r.json()
            out.extend(items)
            # Pagination: stop when fewer than 100 or no next link
            link = r.headers.get("Link", "")
            if 'rel="next"' not in link or len(items) == 0:
                break
            page += 1
        return out

def extract_paths_for_analysis(files: List[Dict]) -> List[str]:
    """
    Normalize changed files to analyze:
    - include: added, modified, changed, renamed (use new filename)
    - exclude: removed
    - ignore: binary files without patch (GitHub flags via "patch" absence); keep them only if you have a binary analyzer
    """
    paths: List[str] = []
    for f in files:
        status: GitStatus = f.get("status", "modified")  # type: ignore
        if status == "removed":
            continue
        # Prefer the current filename; for renames GitHub includes both fields
        filename = f.get("filename")
        if not filename:
            continue
        # If you only run Semgrep (source code), skip obvious binaries
        if f.get("patch") is None and f.get("filename", "").lower().endswith((".png", ".jpg", ".jpeg", ".pdf", ".zip", ".jar", ".gz", ".exe", ".dll")):
            continue
        paths.append(filename)
    # De-dup while preserving order
    seen = set()
    uniq = []
    for p in paths:
        if p not in seen:
            uniq.append(p); seen.add(p)
    return uniq
