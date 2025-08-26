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
from contextlib import asynccontextmanager

import requests
import certifi
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from dotenv import load_dotenv

load_dotenv(dotenv_path=".env")

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
app = FastAPI(title="PRSec Webhook", version="2.5.0")
log = logging.getLogger("webhook")
logging.basicConfig(level=os.getenv("LOGLEVEL", "INFO"))
BOOT_TS = time.time()

# ---------------- Config ----------------
GITHUB_API = os.getenv("GITHUB_API", "https://api.github.com").rstrip("/")

WEBHOOK_SECRET = (os.getenv("GITHUB_WEBHOOK_SECRET") or "").strip()
SECRETS = [s.strip() for s in (os.getenv("GITHUB_WEBHOOK_SECRETS") or WEBHOOK_SECRET).split(",") if s.strip()]

# IMPORTANT: default bypass = ON for tests; set to "0" for production
ALLOW_UNVERIFIED = os.getenv("ALLOW_UNVERIFIED_WEBHOOKS", "1") == "1"

APP_ID = (os.getenv("GITHUB_APP_ID") or "").strip()
APP_PEM_PATH = (os.getenv("GITHUB_APP_PRIVATE_KEY_PATH") or "").strip()
APP_PEM_INLINE = (os.getenv("GITHUB_APP_PRIVATE_KEY") or "").strip()

EXPLICIT_INSTALLATION_TOKEN = (os.getenv("EXPLICIT_INSTALLATION_TOKEN") or "").strip()
FORCE_EXPLICIT_TOKEN = os.getenv("FORCE_EXPLICIT_TOKEN") == "1"

HTTP_TIMEOUT_S       = int(os.getenv("HTTP_TIMEOUT_S", "25"))
SEMGREP_TIMEOUT_S    = int(os.getenv("SEMGREP_TIMEOUT_S", "120"))
PIPELINE_DEADLINE_S  = int(os.getenv("PIPELINE_DEADLINE_S", "90"))
WATCHDOG_GRACE_S     = int(os.getenv("WATCHDOG_GRACE_S", "20"))

CHECK_NAME      = os.getenv("PRSEC_CHECK_NAME", "PRSec/Semgrep")
SEMGREP_CONFIG  = os.getenv("SEMGREP_CONFIG") or None
SEMGREP_EXCLUDE = [s for s in (os.getenv("SEMGREP_EXCLUDE") or "").split(",") if s]
MAX_ANNOTS      = int(os.getenv("PRSEC_MAX_ANNOTATIONS", "200"))

PRSEC_FORCE_OFFLINE = os.getenv("PRSEC_FORCE_OFFLINE", "1") == "1"
ALWAYS_INCLUDE_BASENAMES = [s.strip().lower() for s in (os.getenv("PRSEC_ALWAYS_INCLUDE_BASENAMES", "bad.py")).split(",") if s.strip()]

# ---------------- Helpers ----------------
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
    return os.getenv("REQUESTS_CA_BUNDLE") or os.getenv("SSL_CERT_FILE") or certifi.where()

def _read_private_key() -> str:
    key = Path(APP_PEM_PATH).read_text() if APP_PEM_PATH else APP_PEM_INLINE.replace("\\n", "\n").strip()
    if not key.startswith("-----BEGIN") or "PRIVATE KEY" not in key:
        raise RuntimeError("GITHUB_APP_PRIVATE_KEY[_PATH] is not a valid PEM private key")
    return key

def _create_app_jwt() -> str:
    if not APP_ID:
        raise RuntimeError("GITHUB_APP_ID is missing")
    if jwt is None:
        raise RuntimeError("PyJWT not installed; pip install PyJWT")
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 9 * 60, "iss": APP_ID}
    token = jwt.encode(payload, _read_private_key(), algorithm="RS256")
    return token.decode() if isinstance(token, (bytes, bytearray)) else token

def _request_with_retry(method: str, url: str, headers: Dict[str, str], **kwargs) -> requests.Response:
    # Basic retry on transient failures and rate limits
    max_attempts = 3
    backoff = 1.5
    attempt = 0
    last = None
    while attempt < max_attempts:
        attempt += 1
        r = requests.request(method, url, headers=headers, timeout=HTTP_TIMEOUT_S, verify=_ca_bundle(), **kwargs)
        if r.status_code in (502, 503, 504):
            time.sleep(backoff); backoff *= 2; last = r; continue
        if r.status_code == 403:
            ra = r.headers.get("Retry-After")
            if ra and ra.isdigit():
                time.sleep(int(ra)); last = r; continue
        return r
    return last or r

def _gh_request(method: str, url: str, token: str, install_id: Optional[int] = None, **kwargs) -> requests.Response:
    r = _request_with_retry(method, url, _bearer(token), **kwargs)
    if r.status_code == 401 and install_id:
        try:
            fresh = _get_installation_token(int(install_id))
            r = _request_with_retry(method, url, _bearer(fresh), **kwargs)
        except Exception as e:
            log.error("401 retry failed: %s", e)
    return r

def _post_json(url: str, token: str, payload: dict, install_id: Optional[int] = None) -> dict:
    r = _gh_request("POST", url, token, install_id=install_id, json=payload)
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

def _get_installation_token(installation_id: int) -> str:
    if installation_id and not FORCE_EXPLICIT_TOKEN:
        app_jwt = _create_app_jwt()
        url = f"{GITHUB_API}/app/installations/{installation_id}/access_tokens"
        r = requests.post(url, headers={"Authorization": f"Bearer {app_jwt}", "Accept": "application/vnd.github+json"}, timeout=HTTP_TIMEOUT_S, verify=_ca_bundle())
        if r.status_code >= 400:
            log.error("POST %s -> %s %s: %s", url, r.status_code, r.reason, r.text[:800])
        r.raise_for_status()
        return r.json()["token"]
    if EXPLICIT_INSTALLATION_TOKEN:
        return EXPLICIT_INSTALLATION_TOKEN
    raise RuntimeError("No installation token available")

# ---------- Offline Semgrep config ----------
_OFFLINE_RULES_YAML = """
rules:
  - id: py-weak-md5
    message: Use of weak hash (md5)
    severity: ERROR
    languages: [python]
    pattern: hashlib.md5(...)

  - id: py-unsafe-yaml-load
    message: yaml.load without an explicit Safe/FullLoader
    severity: ERROR
    languages: [python]
    pattern: yaml.load(...)

  - id: py-insecure-deserialization-pickle
    message: Insecure deserialization via pickle.loads
    severity: ERROR
    languages: [python]
    pattern: pickle.loads(...)

  - id: py-shell-true-subprocess
    message: Possible shell injection: subprocess.* with shell=True
    severity: ERROR
    languages: [python]
    patterns:
      - pattern: subprocess.$F(..., shell=True, ...)
      - metavariable-pattern:
          metavariable: $F
          pattern-either:
            - pattern: check_output
            - pattern: run
            - pattern: Popen
            - pattern: call

  - id: py-dangerous-eval
    message: Dangerous use of eval()
    severity: ERROR
    languages: [python]
    pattern: eval(...)

  - id: py-requests-disable-verify
    message: TLS cert verification disabled
    severity: ERROR
    languages: [python]
    pattern: requests.$F(..., verify=False, ...)

  - id: py-tempfile-mktemp
    message: tempfile.mktemp() is insecure; use NamedTemporaryFile/mkstemp
    severity: WARNING
    languages: [python]
    pattern: tempfile.mktemp(...)

  - id: py-random-for-secrets
    message: random.random() is not cryptographic; use secrets or os.urandom
    severity: WARNING
    languages: [python]
    pattern: random.random(...)

  - id: py-tarfile-extractall
    message: tarfile.extractall() may allow path traversal; validate members
    severity: WARNING
    languages: [python]
    pattern: tarfile.extractall(...)
"""

def _write_offline_semgrep_config(workdir: Path) -> str:
    p = workdir / "semgrep.offline.yaml"
    p.write_text(_OFFLINE_RULES_YAML)
    return str(p)

# ---------- GitHub Checks helpers ----------
def _create_check_in_progress(owner: str, repo: str, head_sha: str, name: str, title: str, summary: str, token: str, install_id: Optional[int]) -> int:
    data = {"name": name, "head_sha": head_sha, "status": "in_progress", "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "output": {"title": title, "summary": summary}}
    resp = _post_json(f"{GITHUB_API}/repos/{owner}/{repo}/check-runs", token, data, install_id=install_id)
    return int(resp.get("id") or 0)

def create_check_in_progress_with_fallback(base_owner: str, base_repo: str, head_owner: str, head_repo: str, head_sha: str, name: str, title: str, summary: str, token: str, install_id: Optional[int]) -> Tuple[str, str, int]:
    try:
        check_id = _create_check_in_progress(base_owner, base_repo, head_sha, name, title, summary, token, install_id)
        return base_owner, base_repo, check_id
    except requests.HTTPError as e:
        rc = getattr(e.response, "status_code", 0)
        if rc in (403, 404, 422):
            log.info("check-run create fallback to head repo due to %s", rc)
            check_id = _create_check_in_progress(head_owner, head_repo, head_sha, name, title, summary, token, install_id)
            return head_owner, head_repo, check_id
        raise

def complete_check_run(owner: str, repo: str, check_id: int, conclusion: str, title: str, summary: str, annotations: List[Dict[str, Any]], token: str, install_id: Optional[int]) -> None:
    url = f"{GITHUB_API}/repos/{owner}/{repo}/check-runs/{check_id}"
    payload = {"status": "completed", "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "conclusion": conclusion, "output": {"title": title, "summary": summary, "annotations": annotations[:50]}}
    _patch_json(url, token, payload, install_id=install_id)
    rest = annotations[50:]
    while rest:
        batch, rest = rest[:50], rest[50:]
        _patch_json(url, token, {"output": {"title": title, "summary": summary, "annotations": batch}}, install_id=install_id)

def watchdog_timeout_check(owner: str, repo: str, check_id: int, token: str, install_id: Optional[int], after_seconds: int) -> None:
    try:
        time.sleep(max(after_seconds, 1))
        url = f"{GITHUB_API}/repos/{owner}/{repo}/check-runs/{check_id}"
        jr = _get_json(url, token, install_id=install_id)
        if (jr.get("status") == "in_progress") and (jr.get("conclusion") in (None, "action_required")):
            log.warning("watchdog: completing stale check-run id=%s as timed_out", check_id)
            _patch_json(url, token, {"status": "completed", "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "conclusion": "timed_out", "output": {"title": CHECK_NAME, "summary": "Timed out waiting for scan to complete."}}, install_id=install_id)
    except Exception as e:
        log.error("watchdog error: %s", e)

# ---------- Repo utilities ----------
def _safe_tar_extract(tar: tarfile.TarFile, dest: Path) -> None:
    # Prevent path traversal
    dest_abs = dest.resolve()
    for m in tar.getmembers():
        target = (dest / m.name).resolve()
        if not str(target).startswith(str(dest_abs)):
            raise RuntimeError(f"Unsafe tar path detected: {m.name}")
    tar.extractall(dest)  # safe by pre-check

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

    # Stream to temp file to reduce memory
    with tempfile.NamedTemporaryFile(prefix="prsec_tar_", suffix=".tgz", delete=False) as f:
        for chunk in r.iter_content(chunk_size=1024 * 256):
            if chunk:
                f.write(chunk)
        tar_path = Path(f.name)

    with tarfile.open(tar_path, mode="r:gz") as tf:
        members = tf.getmembers()
        # capture top-level folder before extraction (common GitHub layout)
        top = next((m for m in members if m.isdir() and "/" not in m.name.strip("/")), None)
        _safe_tar_extract(tf, workdir)

    # Resolve extracted repo root
    if top:
        return workdir / top.name
    subs = [p for p in workdir.iterdir() if p.is_dir()]
    if not subs:
        raise RuntimeError("Failed to locate repo root in tarball")
    return subs[0]

# ---------- Scanning pipeline ----------
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
    conclusion = "failure"
    title = f"{CHECK_NAME} results"
    summary = "Scan failed."
    annotations: List[Dict[str, Any]] = []

    def _safe_complete():
        try:
            try_ann = annotations[:MAX_ANNOTS] if annotations else []
            try:
                complete_check_run(check_owner, check_repo, check_id, conclusion, title, summary, try_ann, token, installation_id)
            except requests.HTTPError as e:
                if getattr(e.response, "status_code", 0) == 422:
                    complete_check_run(check_owner, check_repo, check_id, conclusion, title, summary, [], token, installation_id)
                else:
                    raise
        except Exception as e:
            log.error("final completion failed: %s", e)

    try:
        with tempfile.TemporaryDirectory(prefix="prsec_") as td:
            tdp = Path(td)
            repo_root = download_tarball(head_owner, head_repo, head_sha, token, installation_id, tdp)

            try:
                changed = list_changed_files(base_owner, base_repo, pr, token, installation_id)
            except Exception as e:
                log.error("failed to list changed files: %s", e)
                changed = []

            # Base set: changed files; fallback to repo *.py
            paths = changed or [str(p.relative_to(repo_root)) for p in repo_root.rglob("*.py")]
            existing = [p for p in paths if (repo_root / p).exists()]
            if not existing:
                existing = [str(p.relative_to(repo_root)) for p in repo_root.rglob("*.py")]

            # Always include configured basenames (e.g., bad.py) if present
            for bn in ALWAYS_INCLUDE_BASENAMES:
                for found in repo_root.rglob(bn):
                    rel = str(found.relative_to(repo_root))
                    if rel not in existing:
                        existing.append(rel)

            # Config selection
            if PRSEC_FORCE_OFFLINE:
                cfg = _write_offline_semgrep_config(tdp)
            else:
                cfg = SEMGREP_CONFIG
                if not cfg:
                    for name in (".semgrep.yaml", ".semgrep.yml"):
                        cand = repo_root / name
                        if cand.exists():
                            cfg = str(cand)
                            break
                if not cfg:
                    cfg = "p/security-audit"

            ex = SEMGREP_EXCLUDE if SEMGREP_EXCLUDE else [".venv", "venv", ".git"]
            log.info("SEMGREP_CONFIG=%s EXCLUDE=%s", cfg, ex)
            log.info("Semgrep scan root=%s paths_count=%d sample=%s", repo_root, len(existing), existing[:10])

            findings: List[Dict[str, Any]] = []
            try:
                findings = run_semgrep(paths=existing, repo_root=str(repo_root), config=cfg, exclude=ex, timeout_s=SEMGREP_TIMEOUT_S)
            except Exception as e:
                log.error("semgrep invocation failed: %s", e)

            counts, summary_md = summarize_findings(findings)
            annotations = to_github_annotations(findings)[:MAX_ANNOTS]

            if sum(counts.values()) == 0:
                conclusion = "success"
                summary = "No issues found"
            else:
                conclusion = "failure"
                summary = "Issues detected"

            if summary_md:
                summary = summary_md

    except Exception as e:
        log.error("pipeline error: %s", e)
    finally:
        _safe_complete()

# ---------------- Lifespan / Health ----------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        from starlette.routing import Route
        for r in app.router.routes:
            if isinstance(r, Route):
                log.info("route registered: %s methods=%s", r.path, sorted(r.methods))
        log.info("webhook secrets configured: %d", len(SECRETS))
        yield
    finally:
        pass

app.router.lifespan_context = lifespan  # replaces deprecated on_event("startup")

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

    provided = x_hub_signature_256 or x_hub_signature
    if SECRETS and provided:
        if provided.startswith("sha256="):
            algo = "sha256"
        elif provided.startswith("sha1="):
            algo = "sha1"
        else:
            algo = "sha256"
        if not any(_secure_eq(provided, _hmac_sig(sec, body, algo)) for sec in SECRETS):
            if not ALLOW_UNVERIFIED:
                raise HTTPException(status_code=401, detail="Invalid signature")
            log.warning("signature mismatch delivery=%s (bypassed)", x_github_delivery)
    elif SECRETS and not ALLOW_UNVERIFIED:
        raise HTTPException(status_code=400, detail="Signature required")

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

        base = payload["pull_request"]["base"]["repo"]
        head = payload["pull_request"]["head"]["repo"]
        base_owner, base_repo = base["owner"]["login"], base["name"]
        head_owner, head_repo = head["owner"]["login"], head["name"]

        pr_number = int(payload["number"])
        head_sha  = payload["pull_request"]["head"]["sha"]
        base_sha  = payload["pull_request"]["base"]["sha"]
        installation_id = int(payload.get("installation", {}).get("id") or 0)

        try:
            token = _get_installation_token(installation_id)
        except Exception as e:
            log.error("token acquisition failed: %s", e)
            raise HTTPException(status_code=500, detail="Token acquisition failed")

        try:
            _post_json(
                f"{GITHUB_API}/repos/{base_owner}/{base_repo}/issues/{pr_number}/comments",
                token,
                {"body": f"PRSec ✅ received `{action}` for `{head_sha[:7]}` (delivery `{x_github_delivery}`)"},
                install_id=installation_id,
            )
        except Exception as e:
            log.error("failed to comment on PR: %s", e)

        try:
            check_owner, check_repo, check_id = create_check_in_progress_with_fallback(
                base_owner, base_repo, head_owner, head_repo, head_sha,
                CHECK_NAME, f"{CHECK_NAME} results", "Scanning…", token, installation_id
            )
        except Exception as e:
            log.error("failed to create check run: %s", e)
            raise HTTPException(status_code=500, detail="Check run creation failed")

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
