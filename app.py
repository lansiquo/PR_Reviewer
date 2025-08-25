import os
import json
import time
import hmac
import hashlib
import logging
from typing import Any, Dict, Optional

import requests
from fastapi import FastAPI, Header, HTTPException, Request

try:
    import jwt  # PyJWT
except Exception:  # pragma: no cover
    jwt = None

app = FastAPI()
log = logging.getLogger("webhook")
logging.basicConfig(level=os.getenv("LOGLEVEL", "INFO"))

# ---------------- Config ----------------
GITHUB_API = os.getenv("GITHUB_API", "https://api.github.com")
WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "testsecret").strip()
APP_ID = (os.getenv("GITHUB_APP_ID") or "").strip()
APP_PEM = (os.getenv("GITHUB_APP_PRIVATE_KEY") or "").strip()  # PEM or \n-escaped PEM
EXPLICIT_INSTALLATION_TOKEN = (os.getenv("EXPLICIT_INSTALLATION_TOKEN") or "").strip()

# ---------------- Util ----------------
def _mask(s: str, keep: int = 6) -> str:
    if not s:
        return ""
    return s[:keep] + "…" + s[-keep:]

def _secure_eq(a: str, b: str) -> bool:
    try:
        return hmac.compare_digest(a, b)
    except Exception:
        return False

def _normalize_pem(pem: str) -> str:
    return pem.replace("\\n", "\n").strip()

def _hmac_sig(secret: str, body: bytes, algo: str) -> str:
    algo = algo.lower()
    h = {"sha256": hashlib.sha256, "sha1": hashlib.sha1}[algo]
    return f"{algo}=" + hmac.new(secret.encode("utf-8"), body, h).hexdigest()

def _bearer(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "prsec-webhook/1.0",
    }

def _create_app_jwt() -> str:
    if not (APP_ID and APP_PEM and jwt):
        raise RuntimeError("App JWT unavailable; set GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY, and install PyJWT")
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 9 * 60, "iss": APP_ID}
    token = jwt.encode(payload, _normalize_pem(APP_PEM), algorithm="RS256")
    return token.decode() if isinstance(token, (bytes, bytearray)) else token

def _get_installation_token(installation_id: int) -> str:
    if EXPLICIT_INSTALLATION_TOKEN:
        return EXPLICIT_INSTALLATION_TOKEN
    app_jwt = _create_app_jwt()
    url = f"{GITHUB_API}/app/installations/{installation_id}/access_tokens"
    r = requests.post(url, headers={"Authorization": f"Bearer {app_jwt}", "Accept": "application/vnd.github+json"}, timeout=20)
    r.raise_for_status()
    return r.json()["token"]

def post_pr_comment(owner: str, repo: str, pr_number: int, body: str, token: str) -> None:
    url = f"{GITHUB_API}/repos/{owner}/{repo}/issues/{pr_number}/comments"
    r = requests.post(url, headers=_bearer(token), data=json.dumps({"body": body}), timeout=20)
    r.raise_for_status()

def set_status(owner: str, repo: str, sha: str, state: str, context: str, description: str, target_url: Optional[str], token: str) -> None:
    url = f"{GITHUB_API}/repos/{owner}/{repo}/statuses/{sha}"
    payload = {"state": state, "context": context, "description": description}
    if target_url:
        payload["target_url"] = target_url
    r = requests.post(url, headers=_bearer(token), data=json.dumps(payload), timeout=20)
    r.raise_for_status()

# ---------------- Routes ----------------
@app.get("/health")
def health() -> Dict[str, Any]:
    return {"ok": True}

@app.post("/webhook")
async def webhook(
    request: Request,
    x_github_event: str = Header(..., alias="X-GitHub-Event"),
    x_github_delivery: str = Header(..., alias="X-GitHub-Delivery"),
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
    x_hub_signature: Optional[str] = Header(None, alias="X-Hub-Signature"),
):
    body: bytes = await request.body()

    # Require a signature header when a secret is configured
    provided = x_hub_signature_256 or x_hub_signature
    if WEBHOOK_SECRET and not provided:
        raise HTTPException(status_code=400, detail="Signature required")

    if provided:
        if provided.startswith("sha256="):
            expected = _hmac_sig(WEBHOOK_SECRET, body, "sha256")
        elif provided.startswith("sha1="):
            expected = _hmac_sig(WEBHOOK_SECRET, body, "sha1")
        else:
            raise HTTPException(status_code=400, detail="Unsupported signature prefix")

        if not _secure_eq(provided, expected):
            log.warning(
                "signature mismatch delivery=%s provided=%s expected=%s",
                x_github_delivery, _mask(provided), _mask(expected),
            )
            raise HTTPException(status_code=401, detail="Invalid signature")

    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    log.info("webhook: delivery=%s event=%s len=%d", x_github_delivery, x_github_event, len(body))

    # Ping
    if x_github_event == "ping":
        return {"ok": True, "pong": True}

    # PR events
    if x_github_event == "pull_request":
        action = payload.get("action")
        if action not in {"opened", "reopened", "synchronize", "edited", "ready_for_review"}:
            return {"ok": True, "ignored": action}

        repo = payload["repository"]["name"]
        owner = payload["repository"]["owner"]["login"]
        pr_number = int(payload["number"])
        head_sha = payload["pull_request"]["head"]["sha"]
        base_sha = payload["pull_request"]["base"]["sha"]
        installation_id = int(payload.get("installation", {}).get("id") or 0)

        # Token
        try:
            token = _get_installation_token(installation_id) if installation_id else (EXPLICIT_INSTALLATION_TOKEN or "")
            if not token:
                raise RuntimeError("No installation token available")
        except Exception as e:
            log.exception("token acquisition failed: %s", e)
            raise HTTPException(status_code=500, detail="Token acquisition failed")

        # Receipt in PR Conversation
        try:
            short = head_sha[:7]
            msg = f"PRSec ✅ received `{action}` for `{short}` (delivery `{x_github_delivery}`)"
            post_pr_comment(owner, repo, pr_number, msg, token)
        except Exception as e:
            log.warning("failed to comment on PR (non-fatal): %s", e)

        # Optional status
        try:
            set_status(owner, repo, head_sha, state="pending", context="PRSec/Semgrep", description="Scanning…", target_url=None, token=token)
        except Exception as e:
            log.warning("set_status failed (non-fatal): %s", e)

        return {"ok": True, "event": "pull_request", "action": action, "pr": pr_number, "head": head_sha, "base": base_sha}

    return {"ok": True, "ignored_event": x_github_event}
