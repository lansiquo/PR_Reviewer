# app.py
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
from typing import Any, Dict, List, Optional, Tuple

import requests
import certifi
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request

# --- analyzers ---
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
app = FastAPI(title="PRSec Webhook", version="2.0.0")
log = logging.getLogger("webhook")
logging.basicConfig(level=os.getenv("LOGLEVEL", "INFO"))
BOOT_TS = time.time()

# ---------------- Config ----------------
GITHUB_API = os.getenv("GITHUB_API", "https://api.github.com").rstrip("/")

# Webhook secrets (comma-separated allowed). If none, accept with a warning.
WEBHOOK_SECRET = (os.getenv("GITHUB_WEBHOOK_SECRET") or "").strip()
SECRETS = [s.strip() for s in (os.getenv("GITHUB_WEBHOOK_SECRETS") or WEBHOOK_SECRET).split(",") if s.strip()]
ALLOW_UNVERIFIED = os.getenv("ALLOW_UNVERIFIED_WEBHOOKS") == "1"

# GitHub App creds
APP_ID = (os.getenv("GITHUB_APP_ID") or "").strip()
APP_PEM_PATH = (os.getenv("GITHUB_APP_PRIVATE_KEY_PATH") or "").strip()
APP_PEM_INLINE = (os.getenv("GITHUB_APP_PRIVATE_KEY") or "").strip()  # \n-escaped allowed

# Token fallback/debug
EXPLICIT_INSTALLATION_TOKEN = (os.getenv("EXPLICIT_INSTALLATION_TOKEN") or "").strip()
FORCE_EXPLICIT_TOKEN = os.getenv("FORCE_EXPLICIT_TOKEN") == "1"

# Timeouts / limits
HTTP_TIMEOUT_S       = int(os.getenv("HTTP_TIMEOUT_S", "25"))
SEMGREP_TIMEOUT_S    = int(os.getenv("SEMGREP_TIMEOUT_S", "120"))      # per Semgrep call
PIPELINE_DEADLINE_S  = int(os.getenv("PIPELINE_DEADLINE_S", "90"))     # 0 disables hard cap
WATCHDOG_GRACE_S     = int(os.getenv("WATCHDOG_GRACE_S", "20"))        # extra guard after deadline

# Scan/reporting
CHECK_NAME      = os.getenv("PRSEC_CHECK_NAME", "PRSec/Semgrep")
SEMGREP_CONFIG  = os.getenv("SEMGREP_CONFIG") or None
SEMGREP_EXCLUDE = [s for s in (os.getenv("SEMGREP_EXCLUDE") or "").split(",") if s]
MAX_ANNOTS      = int(os.getenv("PRSEC_MAX_ANNOTATIONS", "200"))

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

def _deadline_guard(start_ts: float, limit_s: int, stage: str) -> None:
    if limit_s and (time.time() - start_ts) > limit_s:
        raise RuntimeError(f"pipeline deadline exceeded before {stage} (>{limit_s}s)")

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
    """
    Prefer per-installation token from the event; fallback to EXPLICIT_INSTALLATION_TOKEN
    only when forced or missing id.
    """
    if installation_id and not FORCE_EXPLICIT_TOKEN:
        app_jwt = _create_app_jwt()
        url = f"{GITHUB_API}/app/installations/{installation_id}/access_tokens"
        r = requests.post(
            url,
            headers={"Authorization": f"Bearer {app_jwt}", "Accept": "application/vnd.github+json"},
            timeout=HTTP_TIMEOUT_S,
            verify=_ca_bundle(),
        )
        if r.status_code >= 400:
            log.error("POST %s -> %s %s: %s", url, r.status_code, r.reason, r.text[:800])
        r.raise_for_status()
        return r.json()["token"]
    if EXPLICIT_INSTALLATION_TOKEN:
        return EXPLICIT_INSTALLATION_TOKEN
    raise RuntimeError("No installation token available")

# ---- central GH request with 401 auto-retry (fresh installation token) ----
def _gh_request(
    method: str,
    url: str,
    token: str,
    install_id: Optional[int] = None,
    **kwargs,
) -> requests.Response:
    r = requests.request(method, url, headers=_bearer(token), timeout=HTTP_TIMEOUT_S, verify=_ca_bundle(), **kwargs)
    if r.status_code == 401 and install_id:
        try:
            fresh = _get_installation_token(int(install_id))
            r = requests.request(method, url, headers=_bearer(fresh), timeout=HTTP_TIMEOUT_S, verify=_ca_bundle(), **kwargs)
        except Exception as e:
            log.error("401 retry: failed to mint fresh installation token: %s", e)
    return r

def _post_json(url: str, token: str, payload: dict, install_id: Optional[int] = None) -> dict:
    r = _gh_request("POST", url, token, install_id=install_id, json=payload)
    try_json = None
    try:
        try_json = r.json()
    except Exception:
        try_json = None
    if r.status_code >= 400:
        log.error("POST %s -> %s %s body=%s resp=%s", url, r.status_code, r.reason, str(payload)[:400], (r.text or str(try_json))[:800])
    else:
        loc = (try_json or {}).get("html_url") or r.headers.get("Location")
        log.info("POST %s -> %s %s", url, r.status_code, f"Created: {loc}" if loc else "OK")
    r.raise_for_status()
    return try_json or {}

def _patch_json(url: str, token: str, payload: dict, install_id: Optional[int] = None) -> dict:
    r = _gh_request("PATCH", url, token, install_id=install_id, json=payload)
    try_json = None
    try:
        try_json = r.json()
    except Exception:
        try_json = None
    if r.status_code >= 400:
        log.error("PATCH %s -> %s %s body=%s resp=%s", url, r.status_code, r.reason, str(payload)[:400], (r.text or str(try_json))[:800])
    r.raise_for_status()
    return try_json or {}

def _get_json(url: str, token: str, params: Optional[dict] = None, install_id: Optional[int] = None) -> dict:
    r = _gh_request("GET", url, token, install_id=install_id, params=params or {})
    if r.status_code >= 400:
        log.error("GET %s -> %s %s: %s", url, r.status_code, r.reason, r.text[:800])
    r.raise_for_status()
    return r.json()

# ---------- GitHub Checks helpers ----------
def _create_check_in_progress(owner: str, repo: str, head_sha: str, name: str,
                              title: str, summary: str, token: str,
                              install_id: Optional[int]) -> int:
    data = {
        "name": name,
        "head_sha": head_sha,
        "status": "in_progress",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "output": {"title": title, "summary": summary},
    }
    resp = _post_json(f"{GITHUB_API}/repos/{owner}/{repo}/check-runs", token, data, install_id=install_id)
    return int(resp.get("id") or 0)

def create_check_in_progress_with_fallback(
    base_owner: str, base_repo: str, head_owner: str, head_repo: str,
    head_sha: str, name: str, title: str, summary: str,
    token: str, install_id: Optional[int],
) -> Tuple[str, str, int]:
    """Try base repo first; if it fails with 403/404/422, try head repo."""
    try:
        check_id = _create_check_in_progress(base_owner, base_repo, head_sha, name, title, summary, token, install_id)
        return base_owner, base_repo, check_id
    except requests.HTTPError as e:
        rc = getattr(e.response, "status_code", 0)
        if rc in (403, 404, 422):  # fork or perms
            log.info("check-run create fallback to head repo due to %s", rc)
            check_id = _create_check_in_progress(head_owner, head_repo, head_sha, name, title, summary, token, install_id)
            return head_owner, head_repo, check_id
        raise

def complete_check_run(owner: str, repo: str, check_id: int, conclusion: str,
                       title: str, summary: str, annotations: List[Dict[str, Any]],
                       token: str, install_id: Optional[int]) -> None:
    url = f"{GITHUB_API}/repos/{owner}/{repo}/check-runs/{check_id}"
    payload = {
        "status": "completed",
        "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "conclusion": conclusion,
        "output": {"title": title, "summary": summary, "annotations": annotations[:50]},
    }
    _patch_json(url, token, payload, install_id=install_id)
    # append remaining annotations in batches of 50
    rest = annotations[50:]
    while rest:
        batch, rest = rest[:50], rest[50:]
        _patch_json(url, token, {"output": {"title": title, "summary": summary, "annotations": batch}}, install_id=install_id)

def watchdog_timeout_check(owner: str, repo: str, check_id: int, token: str,
                           install_id: Optional[int], after_seconds: int) -> None:
    """If still in_progress after grace, mark timed_out to avoid permanent 'in progress'."""
    try:
        time.sleep(max(after_seconds, 1))
        url = f"{GITHUB_API}/repos/{owner}/{repo}/check-runs/{check_id}"
        jr = _get_json(url, token, install_id=install_id)
        if (jr.get("status") == "in_progress") and (jr.get("conclusion") in (None, "action_required")):
            log.warning("watchdog: completing stale check-run id=%s as timed_out", check_id)
            _patch_json(url, token, {
                "status": "completed",
                "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "conclusion": "timed_out",
                "output": {"title": CHECK_NAME, "summary": "Timed out waiting for scan to complete."},
            }, install_id=install_id)
    except Exception as e:
        log.error("watchdog error: %s", e)

# ---------- Repo utilities ----------
def list_changed_files(owner: str, repo: str, pr: int, token: str, install_id: Optional[int]) -> List[str]:
    files: List[str] = []
    page = 1
    while True:
        js = _get_json(f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr}/files", token, params={"per_page": 100, "page": page}, install_id=install_id)
        if not js:
            break
        files.extend([x["filename"] for x in js if isinstance(x.get("filename"), str)])
        if len(js) < 100:
            break
        page += 1
    return files

def download_tarball(owner: str, repo: str, sha: str, token: str, install_id: Optional[int], workdir: Path) -> Path:
    url = f"{GITHUB_API}/repos/{owner}/{repo}/tarball/{sha}"
    r = _gh_request("GET", url, token, install_id=install_id, stream=True)
    if r.status_code >= 400:
        log.error("GET %s -> %s %s: %s", url, r.status_code, r.reason, r.text[:800])
    r.raise_for_status()
    tar_bytes = io.BytesIO(r.content)
    with tarfile.open(fileobj=tar_bytes, mode="r:gz") as tf:
        tf.extractall(workdir)  # GitHub tarball is trusted
        top = next((m for m in tf.getmembers() if m.isdir() and "/" not in m.name.strip("/")), None)
    if not top:
        subs = [p for p in workdir.iterdir() if p.is_dir()]
        if not subs:
            raise RuntimeError("Failed to locate repo root in tarball")
        return subs[0]
    return workdir / top.name

# ---------- Scanning pipeline (check-run only) ----------
def run_semgrep_pipeline(
    base_owner: str,
    base_repo: str,
    head_owner: str,
    head_repo: str,
    pr: int,
    head_sha: str,
    installation_id: int,
    check_owner: str,
    check_repo: str,
    check_id: int,
    token: str,
) -> None:
    final_conclusion, final_summary = "failure", "Scan failed"
    start_ts = time.time()

    try:
        with tempfile.TemporaryDirectory(prefix="prsec_") as td:
            tdp = Path(td)

            _deadline_guard(start_ts, PIPELINE_DEADLINE_S, "tarball download")
            try:
                repo_root = download_tarball(head_owner, head_repo, head_sha, token, installation_id, tdp)
            except Exception as e:
                log.error("download/extract failed: %s", e)
                return

            _deadline_guard(start_ts, PIPELINE_DEADLINE_S, "listing changed files")
            try:
                changed = list_changed_files(base_owner, base_repo, pr, token, installation_id)
            except Exception as e:
                log.error("failed to list changed files: %s", e)
                changed = []

            paths = changed or [str(p.relative_to(repo_root)) for p in repo_root.rglob("*.py")]

            _deadline_guard(start_ts, PIPELINE_DEADLINE_S, "semgrep start")
            findings: List[Dict[str, Any]] = []
            try:
                findings = run_semgrep(
                    paths=paths,
                    repo_root=str(repo_root),
                    config=SEMGREP_CONFIG,
                    exclude=SEMGREP_EXCLUDE,
                    timeout_s=SEMGREP_TIMEOUT_S,
                )
            except Exception as e:
                log.error("semgrep invocation failed: %s", e)
            _deadline_guard(start_ts, PIPELINE_DEADLINE_S, "semgrep finish")

            counts, summary_md = summarize_findings(findings)
            annotations = to_github_annotations(findings)[:MAX_ANNOTS]

            final_conclusion = "success" if sum(counts.values()) == 0 else "failure"
            final_summary = "No issues found" if final_conclusion == "success" else "Issues detected"

            _deadline_guard(start_ts, PIPELINE_DEADLINE_S, "check-run completion")
            try:
                complete_check_run(check_owner, check_repo, check_id,
                                   final_conclusion, f"{CHECK_NAME} results",
                                   summary_md, annotations, token, installation_id)
            except Exception as e:
                log.error("check run reporting failed: %s", e)

    except Exception as e:
        log.error("pipeline error: %s", e)
    finally:
        # If we couldn't complete it above, watchdog will finalize it later.
        pass

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

    # Signature verification (sha256/sha1). If no secrets configured, accept with a warning.
    provided = x_hub_signature_256 or x_hub_signature
    if not SECRETS:
        log.warning("no webhook secrets configured; accepting delivery=%s without verification", x_github_delivery)
    else:
        if not provided:
            raise HTTPException(status_code=400, detail="Signature required")
        if provided.startswith("sha256="):
            algo = "sha256"
        elif provided.startswith("sha1="):
            algo = "sha1"
        else:
            raise HTTPException(status_code=400, detail="Unsupported signature prefix")
        if not any(_secure_eq(provided, _hmac_sig(sec, body, algo)) for sec in SECRETS):
            suffixes = [_hmac_sig(sec, body, algo)[-6:] for sec in SECRETS]
            log.warning("signature mismatch delivery=%s algo=%s provided_suffix=%s tried=%d expected_suffixes=%s",
                        x_github_delivery, algo, (provided or "")[-6:], len(SECRETS), suffixes)
            if not ALLOW_UNVERIFIED:
                raise HTTPException(status_code=401, detail="Invalid signature")
            log.warning("continuing despite signature mismatch (ALLOW_UNVERIFIED_WEBHOOKS=1)")

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

        # base/head repos (fork-safe)
        base = payload["pull_request"]["base"]["repo"]
        head = payload["pull_request"]["head"]["repo"]
        base_owner, base_repo = base["owner"]["login"], base["name"]
        head_owner, head_repo = head["owner"]["login"], head["name"]

        pr_number = int(payload["number"])
        head_sha  = payload["pull_request"]["head"]["sha"]
        base_sha  = payload["pull_request"]["base"]["sha"]
        installation_id = int(payload.get("installation", {}).get("id") or 0)

        # token (per-installation if possible)
        try:
            token = _get_installation_token(installation_id)
        except Exception as e:
            log.error("token acquisition failed: %s", e)
            raise HTTPException(status_code=500, detail="Token acquisition failed")

        # receipt comment (base repo), best-effort
        try:
            _post_json(f"{GITHUB_API}/repos/{base_owner}/{base_repo}/issues/{pr_number}/comments",
                       token, {"body": f"PRSec ✅ received `{action}` for `{head_sha[:7]}` (delivery `{x_github_delivery}`)"},
                       install_id=installation_id)
        except Exception as e:
            log.error("failed to comment on PR: %s", e)

        # Create an in-progress check run immediately (base first, fallback to head).
        try:
            check_owner, check_repo, check_id = create_check_in_progress_with_fallback(
                base_owner, base_repo, head_owner, head_repo, head_sha,
                CHECK_NAME, f"{CHECK_NAME} results", "Scanning…", token, installation_id
            )
        except Exception as e:
            log.error("failed to create check run: %s", e)
            raise HTTPException(status_code=500, detail="Check run creation failed")

        # Kick off the scan (which will complete the check run),
        # and a watchdog to force-close if it gets stuck.
        background.add_task(
            run_semgrep_pipeline,
            base_owner, base_repo, head_owner, head_repo, pr_number, head_sha,
            installation_id, check_owner, check_repo, check_id, token,
        )
        background.add_task(
            watchdog_timeout_check,
            check_owner, check_repo, check_id, token, installation_id,
            (PIPELINE_DEADLINE_S or 0) + WATCHDOG_GRACE_S,
        )

        return {"ok": True, "event": "pull_request", "action": action, "pr": pr_number, "head": head_sha, "base": base_sha}

    return {"ok": True, "ignored_event": x_github_event}
