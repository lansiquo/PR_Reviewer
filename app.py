# app.py
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Literal

import requests
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

# --- analyzers ---
from analyzers.semgrep_runner import (
    run_semgrep,
    to_github_annotations,
    summarize_findings,
)

# --- Optional GitHub App auth (PyJWT) ---
try:
    import jwt  # PyJWT
except Exception:  # pragma: no cover
    jwt = None

# --- Logging & .env ---
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("webhook")

try:
    from dotenv import load_dotenv  # pip install python-dotenv
    load_dotenv()
except Exception:
    pass

# --- Config / env ---
GITHUB_APP_ID = (os.getenv("GITHUB_APP_ID") or os.getenv("APP_ID") or "").strip() or None
GITHUB_PRIVATE_KEY = (
    os.getenv("GITHUB_PRIVATE_KEY") or os.getenv("PRIVATE_KEY") or ""
).strip() or None
GITHUB_PRIVATE_KEY_PATH = (os.getenv("GITHUB_PRIVATE_KEY_PATH") or "").strip() or None

# accept either name for the secret
WEBHOOK_SECRET = (
    os.getenv("GITHUB_WEBHOOK_SECRET") or os.getenv("WEBHOOK_SECRET") or ""
).strip() or None
WEBHOOK_SECRET_BYTES = WEBHOOK_SECRET.encode() if WEBHOOK_SECRET else None

# explicit token override (useful locally / CI)
EXPLICIT_INSTALLATION_TOKEN = (
    os.getenv("EXPLICIT_INSTALLATION_TOKEN")
    or os.getenv("GITHUB_INSTALLATION_TOKEN")
    or ""
).strip() or None

# test/integration toggles
PRSEC_SKIP_CHECKOUT = os.getenv("PRSEC_SKIP_CHECKOUT") == "1"
PRSEC_SKIP_SEMGREP = os.getenv("PRSEC_SKIP_SEMGREP") == "1"

# private key from file; fix escaped \n
if (not GITHUB_PRIVATE_KEY) and GITHUB_PRIVATE_KEY_PATH and os.path.exists(GITHUB_PRIVATE_KEY_PATH):
    with open(GITHUB_PRIVATE_KEY_PATH, "r") as fh:
        GITHUB_PRIVATE_KEY = fh.read()
if GITHUB_PRIVATE_KEY and "\\n" in GITHUB_PRIVATE_KEY:
    GITHUB_PRIVATE_KEY = GITHUB_PRIVATE_KEY.replace("\\n", "\n")

log.info(
    "auth_config app_id=%s key=%s key_path=%s explicit_install=%s",
    bool(GITHUB_APP_ID),
    bool(GITHUB_PRIVATE_KEY),
    bool(GITHUB_PRIVATE_KEY_PATH),
    bool(EXPLICIT_INSTALLATION_TOKEN),
)

# --- Constants & state ---
GITHUB_API = "https://api.github.com"
API_HEADERS_BASE = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "pr-security-reviewer",
}
_installation_token_cache: Dict[int, Dict[str, object]] = {}

app = FastAPI()


# ---------------------------- Git / checkout ---------------------------------
# app.py
def ensure_repo_checkout(owner: str, repo_name: str, head_sha: str, token: str) -> str:
    if not shutil.which("git"):
        raise FileNotFoundError("git_not_installed")

    base_dir = os.getenv("WORK_DIR", "/tmp/prsec")
    target = os.path.join(base_dir, owner, repo_name, head_sha[:12])
    os.makedirs(os.path.dirname(target), exist_ok=True)

    t = token or ""
    # Pick URL based on token type
    if t.startswith(("ghp_", "github_pat_")):            # PAT
        user = os.getenv("GITHUB_USERNAME") or owner
        repo_url = f"https://{user}:{t}@github.com/{owner}/{repo_name}.git"
    else:                                                # Installation token (ghs_/ghu_/ghr_)
        repo_url = f"https://x-access-token:{t}@github.com/{owner}/{repo_name}.git"

    # Safe debug
    log.info("checkout url=%s", repo_url.replace(t, "****"))

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "echo"

    def run(*args):
        subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)

    if os.path.isdir(target):
        # Ensure the existing worktree uses the correct remote URL
        run("git", "-C", target, "remote", "set-url", "origin", repo_url)
        run("git", "-C", target, "fetch", "--depth", "2", "origin", head_sha)
        run("git", "-C", target, "checkout", "-f", head_sha)
    else:
        run("git", "clone", "--no-checkout", "--depth", "2", repo_url, target)
        run("git", "-C", target, "fetch", "origin", head_sha)
        run("git", "-C", target, "checkout", "-f", head_sha)

    return target



# ---------------------------- GitHub auth ------------------------------------
def _make_app_jwt(app_id: str, private_key_pem: str) -> str:
    if not jwt:
        raise RuntimeError("PyJWT required. `pip install PyJWT cryptography`")
    now = datetime.now(timezone.utc)
    payload = {
        "iat": int(now.timestamp()) - 60,
        "exp": int((now + timedelta(minutes=9)).timestamp()),
        "iss": app_id,
    }
    return jwt.encode(payload, private_key_pem, algorithm="RS256")

# add near your auth helpers
def _get_private_key_text() -> Optional[str]:
    # in-memory value first
    if GITHUB_PRIVATE_KEY:
        return GITHUB_PRIVATE_KEY
    # then try the path
    if GITHUB_PRIVATE_KEY_PATH and os.path.exists(GITHUB_PRIVATE_KEY_PATH):
        with open(GITHUB_PRIVATE_KEY_PATH, "r") as fh:
            key = fh.read()
        return key.replace("\\n", "\n") if "\\n" in key else key
    return None


def _exchange_installation_token(installation_id: int) -> Tuple[str, int]:
    if not GITHUB_APP_ID:
        raise RuntimeError("GITHUB_APP_ID must be set (or provide EXPLICIT_INSTALLATION_TOKEN)")

    private_key = _get_private_key_text()
    if not private_key:
        raise RuntimeError("GITHUB_PRIVATE_KEY(_PATH) must be set/readable (or provide EXPLICIT_INSTALLATION_TOKEN)")

    app_jwt = _make_app_jwt(GITHUB_APP_ID, private_key)
    url = f"{GITHUB_API}/app/installations/{installation_id}/access_tokens"
    headers = {**API_HEADERS_BASE, "Authorization": f"Bearer {app_jwt}"}
    r = requests.post(url, headers=headers, timeout=30)
    r.raise_for_status()
    j = r.json()
    expires_at = datetime.fromisoformat(j["expires_at"].replace("Z", "+00:00"))
    return j["token"], int(expires_at.timestamp())

def _resolve_installation_id(owner: str, repo: str) -> Optional[int]:
    """
    Resolve GitHub App installation id for a given owner/repo using the App JWT.
    Returns None if the app isn’t installed on that repo or app creds are missing.
    """
    if not (GITHUB_APP_ID and GITHUB_PRIVATE_KEY):
        return None
    app_jwt = _make_app_jwt(GITHUB_APP_ID, GITHUB_PRIVATE_KEY)
    url = f"{GITHUB_API}/repos/{owner}/{repo}/installation"
    headers = {**API_HEADERS_BASE, "Authorization": f"Bearer {app_jwt}"}
    r = requests.get(url, headers=headers, timeout=30)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return int(r.json()["id"])

# app.py
def get_installation_token(installation_id: Optional[int], owner: Optional[str] = None, repo: Optional[str] = None) -> Optional[str]:
    explicit = (os.getenv("EXPLICIT_INSTALLATION_TOKEN") or os.getenv("GITHUB_INSTALLATION_TOKEN") or "").strip() or None
    if explicit:
        return explicit

    # prefer provided id; if missing, resolve from repo
    iid = int(installation_id) if installation_id else None
    if not iid and owner and repo:
        iid = _resolve_installation_id(owner, repo)
    if not iid:
        return None

    cached = _installation_token_cache.get(iid)
    now = int(time.time())
    if cached and now < int(cached["exp"]):
        return str(cached["token"])

    try:
        token, exp = _exchange_installation_token(iid)
    except requests.HTTPError as e:
        # If the id is wrong for this app, try resolving from repo and retry once
        if e.response is not None and e.response.status_code == 404 and owner and repo:
            iid2 = _resolve_installation_id(owner, repo)
            if not iid2 or iid2 == iid:
                raise
            token, exp = _exchange_installation_token(iid2)
            iid = iid2
        else:
            raise

    _installation_token_cache[iid] = {"token": token, "exp": exp - 60}
    return token



# ---------------------------- GitHub client ----------------------------------
GitStatus = Literal["added", "modified", "removed", "renamed", "copied", "changed", "unchanged"]


class GitHubClient:
    def __init__(self, token: str, base_url: str = GITHUB_API):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

        # Installation tokens (ghs_...) use Bearer; PATs (ghp_/github_pat_) use token
        auth = f"Bearer {token}"
        t = token or ""
        if t.startswith(("ghp_", "github_pat_")):
            auth = f"token {token}"

        self.session.headers.update({**API_HEADERS_BASE, "Authorization": auth})


    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}{path}"
        for attempt in range(5):
            resp = self.session.request(method, url, timeout=30, **kwargs)
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
        j = self._request("GET", f"/repos/{owner}/{repo}/pulls/{pr_number}").json()
        return j["base"]["sha"], j["head"]["sha"]

    def get_changed_files(self, owner: str, repo: str, pr_number: int) -> List[Dict]:
        page, out = 1, []
        while True:
            r = self._request(
                "GET", f"/repos/{owner}/{repo}/pulls/{pr_number}/files", params={"per_page": 100, "page": page}
            )
            items = r.json()
            out.extend(items)
            link = r.headers.get("Link", "")
            if 'rel="next"' not in link or not items:
                break
            page += 1
        return out


def extract_paths_for_analysis(files: List[Dict]) -> List[str]:
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
    seen, uniq = set(), []
    for p in paths:
        if p not in seen:
            uniq.append(p)
            seen.add(p)
    return uniq


# ---------------------------- Helpers ----------------------------------------
def _verify_signature(body: bytes, x_hub_signature_256: Optional[str]) -> Tuple[bool, str]:
    if not WEBHOOK_SECRET_BYTES:
        return True, ""
    if not (x_hub_signature_256 and x_hub_signature_256.startswith("sha256=")):
        return False, "missing_or_bad_signature_header"
    digest = hmac.new(WEBHOOK_SECRET_BYTES, body, hashlib.sha256).hexdigest()
    expected = f"sha256={digest}"
    if not hmac.compare_digest(expected, x_hub_signature_256):
        return False, "signature_mismatch"
    return True, ""


# ---------------------------- Routes -----------------------------------------
@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.post("/webhook")
async def webhook(
    request: Request,
    x_github_event: Optional[str] = Header(default=None),
    x_hub_signature_256: Optional[str] = Header(default=None),
    x_github_delivery: Optional[str] = Header(default=None),
):
    body: bytes = await request.body()
    log.info("delivery=%s event=%s len=%d", x_github_delivery, x_github_event, len(body))

    ok, err = _verify_signature(body, x_hub_signature_256)
    if not ok:
        return JSONResponse({"ok": False, "error": err}, status_code=400 if err.startswith("missing") else 401)

    payload: Dict = {}
    if body:
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            log.warning("Non-JSON body (len=%d)", len(body))

    if x_github_event == "ping":
        return JSONResponse({"ok": True, "pong": True}, status_code=200)

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

            token = get_installation_token(installation_id, owner=owner, repo=repo_name)
            if not token:
                log.error(
                    "No installation token; set EXPLICIT_INSTALLATION_TOKEN or configure App credentials."
                )
                return JSONResponse({"ok": False, "error": "no_installation_token"}, status_code=500)

            gh = GitHubClient(token=token)
            try:
                base_sha, head_sha = gh.get_pr_shas(owner, repo_name, prnum)
                raw_files = gh.get_changed_files(owner, repo_name, prnum)
                changed_paths = extract_paths_for_analysis(raw_files)
            except requests.HTTPError as e:
                log.exception("GitHub API error while fetching PR data")
                return JSONResponse({"ok": False, "error": "github_api_error", "detail": str(e)}, status_code=502)

            log.info("pr=%s base=%s head=%s changed_files=%d", prnum, base_sha, head_sha, len(changed_paths))

            # Repo checkout (skippable for tests)
            if PRSEC_SKIP_CHECKOUT:
                repo_root = tempfile.mkdtemp(prefix="prsec_")
            else:
                try:
                    repo_root = ensure_repo_checkout(owner, repo_name, head_sha, token)
                except FileNotFoundError as e:
                    if str(e) == "git_not_installed":
                        return JSONResponse({"ok": False, "error": "git_not_installed"}, status_code=500)
                    return JSONResponse({"ok": False, "error": "repo_checkout_path_error", "detail": str(e)}, status_code=500)
                except subprocess.CalledProcessError as e:
                    return JSONResponse(
                        {"ok": False, "error": "git_checkout_failed", "detail": e.stderr.decode("utf-8", "ignore")},
                        status_code=502,
                    )

            # Semgrep (skippable for tests)
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            summary_md = "Semgrep skipped."
            annotations = []
            if PRSEC_SKIP_SEMGREP:
                log.info("semgrep skipped via PRSEC_SKIP_SEMGREP=1")
            else:
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
                    "changed_paths": changed_paths[:20],
                    "truncated": len(changed_paths) > 20,
                    "semgrep_counts": counts,
                    "semgrep_summary": summary_md,
                    "annotations_preview": annotations[:5],
                },
                status_code=200,
            )

    # default fall-through
    return JSONResponse({"ok": True, "event": x_github_event, "received": bool(payload)}, status_code=200, ) 

