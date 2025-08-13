import os, time, json, requests
import jwt  # PyJWT
import base64
from typing import Optional   

GITHUB_API = os.environ.get("GITHUB_API_BASE", "https://api.github.com")

class GitHubClient:
    def __init__(self, owner: str, repo: str, installation_id: Optional[int]):
        self.owner = owner
        self.repo = repo
        self.installation_id = installation_id
        self._token = None

    def _app_jwt(self) -> str:
        app_id = os.environ.get("GITHUB_APP_ID")
        if not app_id:
            raise RuntimeError("GITHUB_APP_ID not set")
        
        # Accept any of: PEM inline, base64 inline, or path to PEM file
        key_pem  = os.environ.get("GITHUB_PRIVATE_KEY_PEM")
        key_b64  = os.environ.get("GITHUB_PRIVATE_KEY_B64")
        key_path = os.environ.get("GITHUB_PRIVATE_KEY_PATH")

        if not key_pem and key_b64:
            key_pem = base64.b64decode(key_b64).decode("utf-8")
        
        
        if not key_pem and key_path:
            with open(key_path, "r", encoding="utf-8") as f:
                key_pem = f.read()

        if not key_pem:
            raise RuntimeError("Provide GITHUB_PRIVATE_KEY_PEM or GITHUB_PRIVATE_KEY_PATH (or GITHUB_PRIVATE_KEY_B64)")

        now = int(time.time())
        payload = {"iat": now - 60, "exp": now + 540, "iss": int(app_id)}
        return jwt.encode(payload, key_pem, algorithm="RS256")


    def _ensure_token(self):
        # Prefer explicit token for local dev
        if self._token:
            return self._token
        pat = os.environ.get("GITHUB_TOKEN")
        if pat:
            self._token = pat
            return self._token
        if not self.installation_id:
            raise RuntimeError("Missing installation_id and no GITHUB_TOKEN provided")
        # Exchange App JWT → installation access token
        app_token = self._app_jwt()
        url = f"{GITHUB_API}/app/installations/{self.installation_id}/access_tokens"
        r = requests.post(url, headers={"Authorization": f"Bearer {app_token}", "Accept": "application/vnd.github+json"}, timeout=30)
        r.raise_for_status()
        self._token = r.json()["token"]
        return self._token

    def _h(self):
        token = self._ensure_token()
        return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}

    def get_pr_files(self, pr_number: int, per_page=100, max_pages=5):
        files = []
        page = 1
        while page <= max_pages:
            url = f"{GITHUB_API}/repos/{self.owner}/{self.repo}/pulls/{pr_number}/files?per_page={per_page}&page={page}"
            r = requests.get(url, headers=self._h(), timeout=30)
            r.raise_for_status()
            chunk = r.json()
            files.extend(chunk)
            if len(chunk) < per_page:
                break
            page += 1
        return files

    def set_commit_status(self, sha: str, state: str, context: str, description: str, target_url: Optional[str] ):
        # state ∈ {error, failure, pending, success}
        url = f"{GITHUB_API}/repos/{self.owner}/{self.repo}/statuses/{sha}"
        payload = {"state": state, "context": context, "description": description[:140]}
        if target_url:
            payload["target_url"] = target_url
        r = requests.post(url, headers=self._h(), json=payload, timeout=30)
        r.raise_for_status()
        return r.json()

    def post_issue_comment(self, pr_number: int, body: str):
        url = f"{GITHUB_API}/repos/{self.owner}/{self.repo}/issues/{pr_number}/comments"
        r = requests.post(url, headers=self._h(), json={"body": body}, timeout=30)
        r.raise_for_status()
        return r.json()