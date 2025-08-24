# app.py
import hashlib
import hmac
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Literal

import requests
from fastapi import FastAPI, Request, Header
from fastapi.responses import JSONResponse

from analyzers.semgrep_runner import (
    run_semgrep,
    to_github_annotations,
    summarize_findings,
)

# --------------------------------------------------------------------------------------
# Optional GitHub App auth via PyJWT (fallback to EXPLICIT_INSTALLATION_TOKEN if set)
#   pip install PyJWT cryptography
# --------------------------------------------------------------------------------------
try:
    import jwt  # PyJWT
except Exception:  # pragma: no cover
    jwt = None

# --------------------------------------------------------------------------------------
# Logging & config
# --------------------------------------------------------------------------------------
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("webhook")

# Load .env if present
try:
    from dotenv import load_dotenv  # pip install python-dotenv

    load_dotenv()
except Exception:
    pass

# Core env
GITHUB_APP_ID = (os.getenv("GITHUB_APP_ID") or os.getenv("APP_ID") or "").strip() or None
GITHUB_PRIVATE_KEY = (
    os.getenv("GITHUB_PRIVATE_KEY") or os.getenv("PRIVATE_KEY") or ""
).strip() or None
GITHUB_PRIVATE_KEY_PATH = (os.getenv("GITHUB_PRIVATE_KEY_PATH") or "").strip() or None

WEBHOOK_SECRET = (os.getenv("WEBHOOK_SECRET") or "").strip() or None
WEBHOOK_SECRET_BYTES = WEBHOOK_SECRET.encode("utf-8") if WEBHOOK_SECRET else None

# Allow local override with an explicit token (PAT or installation token)
EXPLICIT_INSTALLATION_TOKEN = (
    os.getenv("EXPLICIT_INSTALLATION_TOKEN")
    or os.getenv("GITHUB_INSTALLATION_TOKEN")
    or ""
).strip() or None

# Private key from file if path provided
if (not GITHUB_PRIVATE_KEY) and GITHUB_PRIVATE_KEY_PATH and os.path.exists(GITHUB_PRIVATE_KEY_PATH):
    with open(GITHUB_PRIVATE_KEY_PATH, "r") as _f:
        GITHUB_PRIVATE_KEY = _f.read()

# Fix escaped \n in env-provided private keys
if GITHUB_PRIVATE_KEY and "\\n" in GITHUB_PRIVATE_KEY:
    GITHUB_PRIVATE_KEY = GITHUB_PRIVATE_KEY.replace("\\n", "\n")

log.info(
    "auth_config app_id=%s key=%s key_path=%s explicit_install=%s",
    bool(GITHUB_APP_ID),
    bool(GITHUB_PRIVATE_KEY),
    bool(GITHUB_PRIVATE_KEY_PATH),
    bool(EXPLICIT_INSTALLATION_TOKEN),
)

# --------------------------------------------------------------------------------------
# Constants & caches
# --------------------------------------------------------------------------------------
GITHUB_API = "https://api.github.com"
API_HEADERS_BASE = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "pr-security-reviewer",
}

# In-memory cache for installation tokens
_installation_token_cache: Dict[int, Dict[str, object]] = {}

# --------------------------------------------------------------------------------------
# App
# --------------------------------------------------------------------------------------
app = FastAPI()


import subprocess, shutil

def ensure_repo_checkout(owner: str, repo_name: str, head_sha: str, token: str) -> str:
    """
    Ensure the PR HEAD is checked out locally and return its path.
    Uses installation token for HTTPS auth.
    """
    base_dir = os.getenv("WORK_DIR", "/tmp/prsec")
    target = os.path.join(base_dir, owner, repo_name, head_sha[:12])

    if not shutil.which("git"):
        raise FileNotFoundError("git_not_installed")

    # Build an authenticated clone URL without leaking the token in logs
    repo_url = f"https://x-access-token:{token}@github.com/{owner}/{repo_name}.git"

    cmds = []
    if os.path.isdir(target):
        cmds = [
            ["git", "-C", target, "fetch", "--depth", "2", "origin", head_sha],
            ["git", "-C", target, "checkout", "-f", head_sha],
        ]
    else:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        cmds = [
            ["git", "clone", "--no-checkout", "--depth", "2", repo_url, target],
            ["git", "-C", target, "fetch", "origin", head_sha],
            ["git", "-C", target, "checkout", "-f", head_sha],
        ]

    for cmd in cmds:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    return target


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


# --------------------------------------------------------------------------------------
# GitHub auth helpers (App → Installation token)
# --------------------------------------------------------------------------------------
def _make_app_jwt(app_id: str, private_key_pem: str) -> str:
    """
    Create a JWT signed with the GitHub App's private key.
    """
    if not jwt:
        raise RuntimeError("PyJWT required for App auth. `pip install PyJWT cryptography`")
    now = datetime.now(timezone.utc)
    payload = {
        "iat": int(now.timestamp()) - 60,  # 1 min skew
        "exp": int((now + timedelta(minutes=9)).timestamp()),  # <= 10 minutes per GitHub
        "iss": app_id,
    }
    return jwt.encode(payload, private_key_pem, algorithm="RS256")


def _exchange_installation_token(installation_id: int) -> Tuple[str, int]:
    """
    Exchange App JWT → Installation access token. Returns (token, expires_at_epoch).
    """
    if not (GITHUB_APP_ID and GITHUB_PRIVATE_KEY):
        raise RuntimeError(
            "GITHUB_APP_ID and GITHUB_PRIVATE_KEY must be set (or provide EXPLICIT_INSTALLATION_TOKEN)"
        )
    app_jwt = _make_app_jwt(GITHUB_APP_ID, GITHUB_PRIVATE_KEY)
    url = f"{GITHUB_API}/app/installations/{installation_id}/access_tokens"
    headers = {**API_HEADERS_BASE, "Authorization": f"Bearer {app_jwt}"}
    r = requests.post(url, headers=headers, timeout=30)
    r.raise_for_status()
    j = r.json()
    token = j["token"]
    # expires_at: e.g. "2025-08-24T13:37:00Z"
    expires_at_str = j["expires_at"]
    expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
    return token, int(expires_at.timestamp())


def get_installation_token(installation_id: Optional[int]) -> Optional[str]:
    """
    Preferred: returns an installation token for this installation_id, caching until expiry.
    Fallback: returns EXPLICIT_INSTALLATION_TOKEN if provided (PAT or installation token).
    """
    # Allow hot-changing the override without restarting
    explicit = (
        os.getenv("EXPLICIT_INSTALLATION_TOKEN")
        or os.getenv("GITHUB_INSTALLATION_TOKEN")
        or ""
    ).strip() or None
    if explicit:
        return explicit

    if not installation_id:
        return None

    cached = _installation_token_cache.get(installation_id)
    now = int(time.time())
    if cached and now < int(cached["exp"]):  # not expired
        return str(cached["token"])

    token, exp = _exchange_installation_token(installation_id)
    # Refresh a minute before expiry
    _installation_token_cache[installation_id] = {"token": token, "exp": exp - 60}
    return token


# --------------------------------------------------------------------------------------
# GitHub API client and diff utilities
# --------------------------------------------------------------------------------------
GitStatus = Literal["added", "modified", "removed", "renamed", "copied", "changed", "unchanged"]


class GitHubClient:
    def __init__(self, token: str, base_url: str = GITHUB_API):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({**API_HEADERS_BASE, "Authorization": f"Bearer {token}"})

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}{path}"
        for attempt in range(5):
            resp = self.session.request(method, url, timeout=30, **kwargs)
            # Transient handling
            if resp.status_code in (429, 502, 503, 504):
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
        r = self._request("GET", f"/repos/{owner}/{repo}/pulls/{pr_number}")
        j = r.json()
        return j["base"]["sha"], j["head"]["sha"]

    def get_changed_files(self, owner: str, repo: str, pr_number: int) -> List[Dict]:
        page = 1
        out: List[Dict] = []
        while True:
            r = self._request(
                "GET",
                f"/repos/{owner}/{repo}/pulls/{pr_number}/files",
                params={"per_page": 100, "page": page},
            )
            items = r.json()
            out.extend(items)
            link = r.headers.get("Link", "")
            if 'rel="next"' not in link or len(items) == 0:
                break
            page += 1
        return out


def extract_paths_for_analysis(files: List[Dict]) -> List[str]:
    """
    Include added/modified/changed/renamed files (new filename). Exclude removed.
    Skip obvious binaries when there's no patch (Semgrep won't analyze).
    """
    paths: List[str] = []
    for f in files:
        status: GitStatus = f.get("status", "modified")  # type: ignore
        if status == "removed":
            continue
        filename = f.get("filename")
        if not filename:
            continue
        if f.get("patch") is None and filename.lower().endswith(
            (".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".jar", ".gz", ".exe", ".dll", ".so", ".dylib", ".ico", ".bmp")
        ):
            continue
        paths.append(filename)
    # de-dup preserve order
    seen, uniq = set(), []
    for p in paths:
        if p not in seen:
            uniq.append(p)
            seen.add(p)
    return uniq


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------
def _verify_signature(body: bytes, x_hub_signature_256: Optional[str]) -> Tuple[bool, str]:
    """
    Returns (ok, err). If WEBHOOK_SECRET is not configured, skip check and return (True, "").
    """
    if not WEBHOOK_SECRET_BYTES:
        return True, ""
    if not (x_hub_signature_256 and x_hub_signature_256.startswith("sha256=")):
        return False, "missing_or_bad_signature_header"
    digest = hmac.new(WEBHOOK_SECRET_BYTES, body, hashlib.sha256).hexdigest()
    expected = f"sha256={digest}"
    if not hmac.compare_digest(expected, x_hub_signature_256):
        return False, "signature_mismatch"
    return True, ""


# --------------------------------------------------------------------------------------
# Webhook
# --------------------------------------------------------------------------------------
@app.post("/webhook")
async def webhook(
    request: Request,
    x_github_event: Optional[str] = Header(default=None),
    x_hub_signature_256: Optional[str] = Header(default=None),
    x_github_delivery: Optional[str] = Header(default=None),
):
    body: bytes = await request.body()
    log.info("delivery=%s event=%s len=%d", x_github_delivery, x_github_event, len(body))

    # Signature verification (if secret configured)
    ok, err = _verify_signature(body, x_hub_signature_256)
    if not ok:
        status = 400 if err == "missing_or_bad_signature_header" else 401
        return JSONResponse({"ok": False, "error": err}, status_code=status)

    # Parse JSON if present
    payload: Dict = {}
    if body:
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            log.warning("Non-JSON body (len=%d)", len(body))

    # Cheap router; avoid indexing missing keys
    if x_github_event == "ping":
        return JSONResponse({"ok": True, "pong": True}, status_code=200)

    if x_github_event == "push":
        repo = (payload.get("repository") or {}).get("full_name")
        ref = payload.get("ref")
        log.info("push repo=%s ref=%s", repo, ref)

    if x_github_event == "pull_request":
        action = payload.get("action")
        pr = (payload.get("pull_request") or {})
        number = pr.get("number")
        if number is None:
            return JSONResponse({"ok": False, "error": "missing_pr_number"}, status_code=400)

        if action in {"opened", "reopened", "synchronize", "ready_for_review"}:
            repo_info = payload.get("repository") or {}
            owner = ((repo_info.get("owner") or {}).get("login") or "").strip()
            repo_name = (repo_info.get("name") or "").strip()
            if not owner or not repo_name:
                return JSONResponse({"ok": False, "error": "missing_repo_context"}, status_code=400)

            prnum = int(number)
            installation_id = (payload.get("installation") or {}).get("id")

            # Acquire an installation token (or use env override)
            token = get_installation_token(installation_id)
            if not token:
                log.error(
                    "No installation token available. Provide EXPLICIT_INSTALLATION_TOKEN "
                    "or configure GITHUB_APP_ID/GITHUB_PRIVATE_KEY and ensure installation_id is present."
                )
                return JSONResponse({"ok": False, "error": "no_installation_token"}, status_code=500)

            gh = GitHubClient(token=token)
            try:
                base_sha, head_sha = gh.get_pr_shas(owner, repo_name, prnum)
                raw_files = gh.get_changed_files(owner, repo_name, prnum)
                changed_paths = extract_paths_for_analysis(raw_files)
            except requests.HTTPError as e:
                log.exception("GitHub API error while fetching PR data")
                return JSONResponse(
                    {"ok": False, "error": "github_api_error", "detail": str(e)}, status_code=502
                )

            log.info("pr=%s base=%s head=%s changed_files=%d", prnum, base_sha, head_sha, len(changed_paths))

            # -- Step 2: run Semgrep on changed files -----------------------
           # After you compute base_sha, head_sha, changed_paths
            try:
                repo_root = ensure_repo_checkout(owner, repo_name, head_sha, token)
            except FileNotFoundError as e:
                err = str(e)
                if err == "git_not_installed":
                    return JSONResponse({"ok": False, "error": "git_not_installed"}, status_code=500)
                return JSONResponse({"ok": False, "error": "repo_checkout_path_error", "detail": err}, status_code=500)
            except subprocess.CalledProcessError as e:
                return JSONResponse(
                    {"ok": False, "error": "git_checkout_failed", "detail": e.stderr.decode("utf-8", "ignore")},
                    status_code=502,
                )

            # Optional: ensure semgrep is installed before calling your runner
            if not shutil.which("semgrep"):
                return JSONResponse({"ok": False, "error": "semgrep_not_installed"}, status_code=500)

            semgrep_config = os.getenv("SEMGREP_CONFIG", "p/ci")
            findings = run_semgrep(
                paths=changed_paths,
                repo_root=repo_root,
                config=semgrep_config,
                exclude=["tests/**", "**/vendor/**", "**/node_modules/**"],
                timeout_s=60,
            )

            counts, summary_md = summarize_findings(findings)
            annotations = to_github_annotations(findings, max_per_file=10)

            log.info("semgrep findings: %s", counts)

            return JSONResponse(
                {
                    "ok": True,
                    "event": x_github_event,
                    "pr": prnum,
                    "base": base_sha,
                    "head": head_sha,
                    "changed_count": len(changed_paths),
                    "changed_paths": changed_paths[:20],  # preview only
                    "truncated": len(changed_paths) > 20,
                    "semgrep_counts": counts,
                    "semgrep_summary": summary_md,
                    "annotations_preview": annotations[:5],
                },
                status_code=200,
            )

    return JSONResponse({"ok": True, "event": x_github_event, "received": bool(payload)}, status_code=200)
