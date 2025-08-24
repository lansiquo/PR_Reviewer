# app.py
import hashlib, hmac, json, logging, os, sys, time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Literal

import requests
from fastapi import FastAPI, Request, Header
from fastapi.responses import JSONResponse
from analyzers.semgrep_runner import run_semgrep, to_github_annotations, summarize_findings



# If you prefer GitHub App auth (recommended), install PyJWT:
#   pip install PyJWT cryptography
try:
    import jwt  # PyJWT
except Exception:  # pragma: no cover
    jwt = None  # We'll fallback to env-provided GITHUB_INSTALLATION_TOKEN

# --------------------------------------------------------------------------------------
# Logging & config
# --------------------------------------------------------------------------------------
logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("webhook")

WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "").encode()
GITHUB_APP_ID = os.getenv("GITHUB_APP_ID")
GITHUB_PRIVATE_KEY = os.getenv("GITHUB_PRIVATE_KEY")  # PEM string
EXPLICIT_INSTALLATION_TOKEN = os.getenv("GITHUB_INSTALLATION_TOKEN")  # optional override

GITHUB_API = "https://api.github.com"
API_HEADERS_BASE = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "pr-security-reviewer",
}

# In-memory cache for installation tokens
_installation_token_cache: Dict[int, Dict[str, object]] = {}
# --------------------------------------------------------------------------------------

app = FastAPI()

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
        "iat": int(now.timestamp()) - 60,                # 1 min clock skew
        "exp": int((now + timedelta(minutes=9)).timestamp()),  # GitHub max is 10 minutes
        "iss": app_id,
    }
    return jwt.encode(payload, private_key_pem, algorithm="RS256")

def _exchange_installation_token(installation_id: int) -> Tuple[str, int]:
    """
    Exchange App JWT → Installation access token. Returns (token, expires_at_epoch).
    """
    assert GITHUB_APP_ID and GITHUB_PRIVATE_KEY, "GITHUB_APP_ID and GITHUB_PRIVATE_KEY must be set"
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
    if EXPLICIT_INSTALLATION_TOKEN:
        return EXPLICIT_INSTALLATION_TOKEN
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
            # Secondary rate limit / transient handling
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
            r = self._request("GET", f"/repos/{owner}/{repo}/pulls/{pr_number}/files",
                              params={"per_page": 100, "page": page})
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
        if f.get("patch") is None and filename.lower().endswith((
            ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".jar", ".gz",
            ".exe", ".dll", ".so", ".dylib", ".ico", ".bmp"
        )):
            continue
        paths.append(filename)
    # de-dup preserve order
    seen, uniq = set(), []
    for p in paths:
        if p not in seen:
            uniq.append(p); seen.add(p)
    return uniq

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

    # Signature check only if secret is set
    if WEBHOOK_SECRET:
        if not (x_hub_signature_256 and x_hub_signature_256.startswith("sha256=")):
            return JSONResponse({"ok": False, "error": "missing_or_bad_signature_header"}, status_code=400)
        digest = hmac.new(WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(f"sha256={digest}", x_hub_signature_256):
            return JSONResponse({"ok": False, "error": "signature_mismatch"}, status_code=401)

    payload = {}
    if body:
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            log.warning("Non-JSON body (len=%d)", len(body))

    # Cheap router; never index into missing keys
    if x_github_event == "ping":
        return JSONResponse({"ok": True, "pong": True}, status_code=200)

    if x_github_event == "push":
        repo = (payload.get("repository") or {}).get("full_name")
        ref = payload.get("ref")
        log.info("push repo=%s ref=%s", repo, ref)

    if x_github_event == "pull_request":
        action = payload.get("action")
        number = (payload.get("pull_request") or {}).get("number")
        log.info("pull_request action=%s number=%s", action, number)

        if action in {"opened", "reopened", "synchronize", "ready_for_review"}:
            owner = (payload.get("repository") or {}).get("owner", {}).get("login")
            repo  = (payload.get("repository") or {}).get("name")
            prnum = int(number) if number is not None else None
            installation_id = (payload.get("installation") or {}).get("id")

            # Acquire an installation token (or use env override)
            token = get_installation_token(installation_id)
            if not token:
                log.error("No installation token available. Set GITHUB_INSTALLATION_TOKEN "
                          "or configure GITHUB_APP_ID/GITHUB_PRIVATE_KEY and ensure installation_id is present.")
                return JSONResponse({"ok": False, "error": "no_installation_token"}, status_code=500)

            gh = GitHubClient(token=token)
            try:
                base_sha, head_sha = gh.get_pr_shas(owner, repo, prnum)  # type: ignore[arg-type]
                raw_files = gh.get_changed_files(owner, repo, prnum)     # type: ignore[arg-type]
                changed_paths = extract_paths_for_analysis(raw_files)
            except requests.HTTPError as e:
                log.exception("GitHub API error while fetching PR data")
                return JSONResponse({"ok": False, "error": "github_api_error", "detail": str(e)}, status_code=502)

            log.info("pr=%s base=%s head=%s changed_files=%d",
                     prnum, base_sha, head_sha, len(changed_paths))
            
            


            # -- Step 2: run Semgrep on changed files -----------------------
            repo_root = os.getenv("REPO_ROOT", "/tmp/checkout")  # wherever you checkout the PR head
            semgrep_config = os.getenv("SEMGREP_CONFIG", "p/ci")

            # NOTE: Ensure repo_root contains the PR HEAD contents.
            # (Clone/checkout is a separate step; this code assumes files exist.)

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

            return JSONResponse({
                "ok": True,
                "event": x_github_event,
                "pr": prnum,
                "base": base_sha,
                "head": head_sha,
                "changed_count": len(changed_paths),
                "changed_paths": changed_paths[:20],  # preview only
                "truncated": len(changed_paths) > 20
            }, status_code=200)

    return JSONResponse({"ok": True, "event": x_github_event, "received": bool(payload)}, status_code=200)
