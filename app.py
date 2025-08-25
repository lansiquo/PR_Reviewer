import os
import io
import json
import time
import hmac
import tarfile
import hashlib
import logging
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
import certifi
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request

# ------ analyzers ------
from analyzers.semgrep_runner import (
    run_semgrep,
    to_github_annotations,
    summarize_findings,
)

try:
    import jwt  # PyJWT
except Exception:  # pragma: no cover
    jwt = None

# ---------------- App / Logging ----------------
app = FastAPI(title="PRSec Webhook", version="1.1.0")
log = logging.getLogger("webhook")
logging.basicConfig(level=os.getenv("LOGLEVEL", "INFO"))
BOOT_TS = time.time()

# ---------------- Config ----------------
GITHUB_API = os.getenv("GITHUB_API", "https://api.github.com").rstrip("/")
WEBHOOK_SECRET = (os.getenv("GITHUB_WEBHOOK_SECRET") or "").strip()
SECRETS = [s.strip() for s in (os.getenv("GITHUB_WEBHOOK_SECRETS") or WEBHOOK_SECRET).split(",") if s.strip()]

APP_ID = (os.getenv("GITHUB_APP_ID") or "").strip()
APP_PEM_PATH = (os.getenv("GITHUB_APP_PRIVATE_KEY_PATH") or "").strip()
APP_PEM_INLINE = (os.getenv("GITHUB_APP_PRIVATE_KEY") or "").strip()
EXPLICIT_INSTALLATION_TOKEN = (os.getenv("EXPLICIT_INSTALLATION_TOKEN") or "").strip()
FORCE_EXPLICIT_TOKEN = os.getenv("FORCE_EXPLICIT_TOKEN") == "1"

HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT_S", "25"))
CHECK_NAME = os.getenv("PRSEC_CHECK_NAME", "PRSec/Semgrep")
SEMGREP_CONFIG = os.getenv("SEMGREP_CONFIG")  # optional override
SEMGREP_EXCLUDE = [s for s in (os.getenv("SEMGREP_EXCLUDE") or "").split(",") if s]
MAX_ANNOTS = 200  # safety ceiling so we don't flood

# ---------------- Helpers ----------------
def _mask(s: str, keep: int = 6) -> str:
    if not s:
        return ""
    return s[:keep] + "…" + s[-keep:]

def _secure_eq(a: str, b: str) -> bool:
    try:
        return hmac.compare_digest(a, b)
    except Exception:
        return False

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

def _ca_bundle() -> str:
    return (
        os.getenv("REQUESTS_CA_BUNDLE")
        or os.getenv("SSL_CERT_FILE")
        or certifi.where()
    )

def _post_json(url: str, token: str, payload: dict) -> dict:
    r = requests.post(url, headers=_bearer(token), json=payload, timeout=HTTP_TIMEOUT, verify=_ca_bundle())
    try_json = None
    try:
        try_json = r.json()
    except Exception:
        try_json = None
    if r.status_code >= 400:
        log.error("POST %s -> %s %s body=%s resp=%s",
                  url, r.status_code, r.reason, str(payload)[:400], (r.text or str(try_json))[:800])
    else:
        loc = (try_json or {}).get("html_url") or r.headers.get("Location")
        log.info("POST %s -> %s %s", url, r.status_code, f"Created: {loc}" if loc else "OK")
    r.raise_for_status()
    return try_json or {}

def _get_json(url: str, token: str, params: Optional[dict] = None) -> dict:
    r = requests.get(url, headers=_bearer(token), params=params or {}, timeout=HTTP_TIMEOUT, verify=_ca_bundle())
    if r.status_code >= 400:
        log.error("GET %s -> %s %s: %s", url, r.status_code, r.reason, r.text[:800])
    r.raise_for_status()
    return r.json()

def _read_private_key() -> str:
    if APP_PEM_PATH:
        key = Path(APP_PEM_PATH).read_text()
    else:
        key = APP_PEM_INLINE.replace("\\n", "\n").strip()
    if not key.startswith("-----BEGIN") or "PRIVATE KEY" not in key:
        raise RuntimeError("GITHUB_APP_PRIVATE_KEY[_PATH] is not a valid PEM private key")
    return key

def _create_app_jwt() -> str:
    if not APP_ID:
        raise RuntimeError("GITHUB_APP_ID is missing")
    if jwt is None:
        raise RuntimeError("PyJWT not installed; pip install PyJWT")
    key = _read_private_key()
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 9 * 60, "iss": APP_ID}
    token = jwt.encode(payload, key, algorithm="RS256")
    return token.decode() if isinstance(token, (bytes, bytearray)) else token

def _get_installation_token(installation_id: int) -> str:
    # Prefer per-installation token from the event; fallback to explicit only when forced or missing id
    if installation_id and not FORCE_EXPLICIT_TOKEN:
        app_jwt = _create_app_jwt()
        url = f"{GITHUB_API}/app/installations/{installation_id}/access_tokens"
        r = requests.post(url, headers={"Authorization": f"Bearer {app_jwt}", "Accept": "application/vnd.github+json"},
                          timeout=HTTP_TIMEOUT, verify=_ca_bundle())
        if r.status_code >= 400:
            log.error("POST %s -> %s %s: %s", url, r.status_code, r.reason, r.text[:800])
        r.raise_for_status()
        return r.json()["token"]
    if EXPLICIT_INSTALLATION_TOKEN:
        return EXPLICIT_INSTALLATION_TOKEN
    raise RuntimeError("No installation token available")

# ---------- GitHub ops ----------
def post_pr_comment(owner: str, repo: str, pr_number: int, body: str, token: str) -> None:
    _post_json(f"{GITHUB_API}/repos/{owner}/{repo}/issues/{pr_number}/comments", token, {"body": body})

def set_status(owner: str, repo: str, sha: str, state: str, context: str, description: str, target_url: Optional[str], token: str) -> None:
    payload = {"state": state, "context": context, "description": description}
    if target_url:
        payload["target_url"] = target_url
    _post_json(f"{GITHUB_API}/repos/{owner}/{repo}/statuses/{sha}", token, payload)

def create_check_run(owner: str, repo: str, head_sha: str, name: str, title: str, summary: str, annotations: List[Dict[str, Any]], token: str) -> int:
    """Create a check run with up to 50 annotations; return check_run id."""
    chunk = annotations[:50]
    data = {
        "name": name,
        "head_sha": head_sha,
        "status": "completed",  # we submit completed with conclusion immediately after scan
        "conclusion": "neutral",  # will be patched below by update_check_run()
        "output": {"title": title, "summary": summary, "annotations": chunk},
    }
    resp = _post_json(f"{GITHUB_API}/repos/{owner}/{repo}/check-runs", token, data)
    return int(resp.get("id") or 0)

def update_check_run(owner: str, repo: str, check_id: int, conclusion: str, title: str, summary: str, annotations: List[Dict[str, Any]], token: str) -> None:
    """Update check run; can send more annotations in 50-sized chunks."""
    base = {"conclusion": conclusion, "output": {"title": title, "summary": summary}}
    if annotations:
        base["output"]["annotations"] = annotations[:50]
    _post_json(f"{GITHUB_API}/repos/{owner}/{repo}/check-runs/{check_id}", token, base)
    # send remaining annotations in batches (append pattern)
    rest = annotations[50:]
    while rest:
        batch, rest = rest[:50], rest[50:]
        _post_json(f"{GITHUB_API}/repos/{owner}/{repo}/check-runs/{check_id}",
                   token, {"output": {"title": title, "summary": summary, "annotations": batch}})

def list_changed_files(owner: str, repo: str, pr: int, token: str) -> List[str]:
    files: List[str] = []
    page = 1
    while True:
        js = _get_json(f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr}/files", token, params={"per_page": 100, "page": page})
        if not js:
            break
        files.extend([x["filename"] for x in js if isinstance(x.get("filename"), str)])
        if len(js) < 100:
            break
        page += 1
    return files

def download_tarball(owner: str, repo: str, sha: str, token: str, workdir: Path) -> Path:
    """Download and extract the repo tarball at SHA, return the extracted repo root."""
    url = f"{GITHUB_API}/repos/{owner}/{repo}/tarball/{sha}"
    r = requests.get(url, headers=_bearer(token), timeout=HTTP_TIMEOUT, verify=_ca_bundle(), stream=True)
    if r.status_code >= 400:
        log.error("GET %s -> %s %s: %s", url, r.status_code, r.reason, r.text[:800])
    r.raise_for_status()
    tar_bytes = io.BytesIO(r.content)
    with tarfile.open(fileobj=tar_bytes, mode="r:gz") as tf:
        tf.extractall(workdir)  # safe here; trusted GitHub tarball
        # First top-level directory is the repo root
        top = next((m for m in tf.getmembers() if m.isdir() and "/" not in m.name.strip("/")), None)
    if not top:
        # best effort: use the first directory created
        subdirs = [p for p in workdir.iterdir() if p.is_dir()]
        if not subdirs:
            raise RuntimeError("Failed to locate repo root in tarball")
        return subdirs[0]
    return workdir / top.name

# ---------- Scanning pipeline ----------
def run_semgrep_pipeline(owner, repo, pr, head_sha, installation_id, delivery):
    final_state = "error"
    final_desc  = "Scan failed"
    try:
        token = _get_installation_token(installation_id)
        repo_root = download_tarball(owner, repo, head_sha, token, Path(tempfile.mkdtemp()))
        try:
            changed = list_changed_files(owner, repo, pr, token)
        except Exception as e:
            log.error("failed to list changed files: %s", e)
            changed = []
        paths = changed or [str(p.relative_to(repo_root)) for p in repo_root.rglob("*.py")]

        findings = run_semgrep(paths=paths, repo_root=str(repo_root),
                               config=SEMGREP_CONFIG, exclude=SEMGREP_EXCLUDE, timeout_s=120)
        counts, summary_md = summarize_findings(findings)
        annots = to_github_annotations(findings)[:MAX_ANNOTS]

        # check run + conclusion
        conclusion = "success" if sum(counts.values()) == 0 else "failure"
        try:
            check_id = create_check_run(owner, repo, head_sha, CHECK_NAME,
                                        f"{CHECK_NAME} results", summary_md, annots[:50], token)
            update_check_run(owner, repo, check_id, conclusion, f"{CHECK_NAME} results", summary_md, annots[50:], token)
        except Exception as e:
            log.error("check run reporting failed: %s", e)

        final_state = "success" if conclusion == "success" else "failure"
        final_desc  = "No issues found" if final_state == "success" else "Issues detected"
    except Exception as e:
        log.error("pipeline error: %s", e)
    finally:
        try:
            set_status(owner, repo, head_sha, state=final_state, context=CHECK_NAME,
                       description=final_desc, target_url=None, token=token if 'token' in locals() else EXPLICIT_INSTALLATION_TOKEN)
        except Exception as e:
            log.error("failed to send final status: %s", e)


# ---------------- Startup / Health ----------------
@app.on_event("startup")
def _startup_log_routes() -> None:
    try:
        from starlette.routing import Route
        for r in app.router.routes:
            if isinstance(r, Route):
                log.info("route registered: %s methods=%s", r.path, sorted(r.methods))
        log.info("webhook secrets configured: %d", len(SECRETS))
    except Exception:
        pass

@app.get("/health", include_in_schema=False)
def health() -> Dict[str, Any]:
    return {"ok": True, "service": "prsec-webhook", "uptime_s": int(time.time() - BOOT_TS), "has_secret": bool(SECRETS)}

# ---------------- Webhook ----------------
@app.post("/webhook")
async def webhook(
    request: Request,
    background: BackgroundTasks,
    x_github_event: str = Header(..., alias="X-GitHub-Event"),
    x_github_delivery: str = Header(..., alias="X-GitHub-Delivery"),
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
    x_hub_signature: Optional[str] = Header(None, alias="X-Hub-Signature"),
    x_github_hook_id: Optional[str] = Header(None, alias="X-GitHub-Hook-ID"),
    x_github_target: Optional[str] = Header(None, alias="X-GitHub-Hook-Installation-Target-Type"),
):
    body: bytes = await request.body()

    # Signature verification (sha256/sha1), multi-secret
    provided = x_hub_signature_256 or x_hub_signature
    if SECRETS and not provided:
        raise HTTPException(status_code=400, detail="Signature required")
    if provided:
        if provided.startswith("sha256="):
            algo = "sha256"
        elif provided.startswith("sha1="):
            algo = "sha1"
        else:
            raise HTTPException(status_code=400, detail="Unsupported signature prefix")

        if not any(_secure_eq(provided, _hmac_sig(sec, body, algo)) for sec in SECRETS):
            log.warning("signature mismatch delivery=%s provided=%s tried=%d secret(s)", x_github_delivery, _mask(provided), len(SECRETS))
            raise HTTPException(status_code=401, detail="Invalid signature")

    # Parse payload
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    log.info("delivery=%s event=%s len=%d hook_id=%s target=%s", x_github_delivery, x_github_event, len(body), x_github_hook_id, x_github_target)

    if x_github_event == "ping":
        return {"ok": True, "pong": True}

    if x_github_event == "pull_request":
        action = payload.get("action")
        if action not in {"opened", "reopened", "synchronize", "edited", "ready_for_review"}:
            return {"ok": True, "ignored": action}

        base_repo = payload["pull_request"]["base"]["repo"]
        owner = base_repo["owner"]["login"]
        repo = base_repo["name"]
        pr_number = int(payload["number"])
        head_sha = payload["pull_request"]["head"]["sha"]
        base_sha = payload["pull_request"]["base"]["sha"]
        installation_id = int(payload.get("installation", {}).get("id") or 0)

        # Leave a visible receipt
        try:
            token = _get_installation_token(installation_id)
            msg = f"PRSec ✅ received `{action}` for `{head_sha[:7]}` (delivery `{x_github_delivery}`)"
            post_pr_comment(owner, repo, pr_number, msg, token)
        except Exception as e:
            log.error("failed to comment on PR: %s", e)

        # Set pending immediately (non-blocking)
        try:
            set_status(owner, repo, head_sha, state="pending", context=CHECK_NAME, description="Scanning…", target_url=None, token=token)
        except Exception as e:
            log.error("failed to set pending status (non-fatal): %s", e)

        # Kick off background analysis
        background.add_task(run_semgrep_pipeline, owner, repo, pr_number, head_sha, installation_id, x_github_delivery)

        return {"ok": True, "event": "pull_request", "action": action, "pr": pr_number, "head": head_sha, "base": base_sha}

    return {"ok": True, "ignored_event": x_github_event}
