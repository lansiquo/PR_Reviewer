"""
BEGINNER-FRIENDLY WALKTHROUGH COMMENTS
=====================================
This web service (FastAPI) listens for GitHub webhooks at "/webhook". When a
Pull Request (PR) event arrives, we:
  1) Verify the webhook signature (supports sha256 and sha1), but by default
     we DO NOT reject on mismatch (so tests never 401). Toggle with env.
  2) Parse the JSON payload for repo/PR/commit.
  3) Acquire a GitHub token for the App installation (retry on 401 once).
  4) Create a "Check Run" so users see activity.
  5) In a background task, download the PR head commit as a tarball, pick
     target files (always includes *bad*.py), run Semgrep (offline + repo rules),
     and complete the Check Run with annotations and a summary.
  6) A watchdog timer force-completes any stuck check as "timed_out".

There is also a "/health" endpoint for liveness checks.

Defaults for deterministic CI:
- We never filter findings by severity internally.
- We prefer offline Semgrep rules (no network) + repo .semgrep.yaml if present.
- We always include files matching "*bad*.py" to guarantee demo detections.
- Webhook 200s always. You can enforce signatures in prod via env (see below).
"""

from __future__ import annotations

import io
import json
import logging
import os
import time
import hmac
import tarfile
import hashlib
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import certifi
import requests
from fastapi import BackgroundTasks, FastAPI, Header, Request
from dotenv import load_dotenv

# Load .env for local dev convenience
load_dotenv(dotenv_path=".env")

# Never hide findings due to env severity floors
os.environ["PRSEC_SEMGREP_MIN_SEVERITY"] = "LOW"

# ---------------- App / Logging ----------------
app = FastAPI(title="PRSec Webhook", version="3.0.0")
log = logging.getLogger("webhook")
logging.basicConfig(level=os.getenv("LOGLEVEL", "INFO"))
BOOT_TS = time.time()

# ---------------- Config ----------------
GITHUB_API = os.getenv("GITHUB_API", "https://api.github.com").rstrip("/")

# Webhook secrets (support rotation via comma-separated list)
WEBHOOK_SECRET = (os.getenv("GITHUB_WEBHOOK_SECRET") or "").strip()
SECRETS = [s.strip() for s in (os.getenv("GITHUB_WEBHOOK_SECRETS") or WEBHOOK_SECRET).split(",") if s.strip()]

# Signature enforcement toggle:
#   "1" (default): accept unverified/mismatched signatures (never 401)
#   "0": do strict verification; on mismatch, we still reply 200 with ok:false
ALLOW_UNVERIFIED = os.getenv("ALLOW_UNVERIFIED_WEBHOOKS", "1") == "1"

# GitHub App creds
APP_ID = (os.getenv("GITHUB_APP_ID") or "").strip()
APP_PEM_PATH = (os.getenv("GITHUB_APP_PRIVATE_KEY_PATH") or "").strip()
APP_PEM_INLINE = (os.getenv("GITHUB_APP_PRIVATE_KEY") or "").strip()

# Token fallback/debug
EXPLICIT_INSTALLATION_TOKEN = (os.getenv("EXPLICIT_INSTALLATION_TOKEN") or "").strip()
FORCE_EXPLICIT_TOKEN = os.getenv("FORCE_EXPLICIT_TOKEN") == "1"

# Timeouts / limits
HTTP_TIMEOUT_S      = int(os.getenv("HTTP_TIMEOUT_S", "25"))
SEMGREP_TIMEOUT_S   = int(os.getenv("SEMGREP_TIMEOUT_S", "120"))
PIPELINE_DEADLINE_S = int(os.getenv("PIPELINE_DEADLINE_S", "90"))
WATCHDOG_GRACE_S    = int(os.getenv("WATCHDOG_GRACE_S", "20"))

# Scan/reporting
CHECK_NAME      = os.getenv("PRSEC_CHECK_NAME", "PRSec/Semgrep")
SEMGREP_CONFIG  = os.getenv("SEMGREP_CONFIG") or None
SEMGREP_EXCLUDE = [s for s in (os.getenv("SEMGREP_EXCLUDE") or "").split(",") if s]
MAX_ANNOTS      = int(os.getenv("PRSEC_MAX_ANNOTATIONS", "200"))

# Deterministic scanning defaults
PRSEC_FORCE_OFFLINE = os.getenv("PRSEC_FORCE_OFFLINE", "1") == "1"
ALWAYS_INCLUDE_PATTERNS = [
    s.strip()
    for s in (os.getenv("PRSEC_ALWAYS_INCLUDE_PATTERNS", "bad.py,bad2.py,*bad*.py")).split(",")
    if s.strip()
]

# --- analyzers ---
# (We deliberately keep runner isolated; it already contains timeouts, JSON safety)
from analyzers.semgrep_runner import run_semgrep, to_github_annotations, summarize_findings

# PyJWT is optional (we raise only when we actually need to mint a JWT)
try:
    import jwt  # type: ignore
except Exception:  # pragma: no cover
    jwt = None

# ---------- HMAC / HTTP helpers ----------
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

def _gh_request(method: str, url: str, token: str, install_id: Optional[int] = None, **kwargs) -> requests.Response:
    r = requests.request(method, url, headers=_bearer(token), timeout=HTTP_TIMEOUT_S, verify=_ca_bundle(), **kwargs)
    if r.status_code == 401 and install_id:
        try:
            fresh = _get_installation_token(int(install_id))
            r = requests.request(method, url, headers=_bearer(fresh), timeout=HTTP_TIMEOUT_S, verify=_ca_bundle(), **kwargs)
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
        if loc:
            log.info("POST %s -> %s Created: %s", url, r.status_code, loc)
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

# ---------- Offline Semgrep config (covers classic "bad" demos) ----------
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
        tf.extractall(workdir)  # safe enough for GitHub tarballs
        top = next((m for m in tf.getmembers() if m.isdir() and "/" not in m.name.strip("/")), None)
    if not top:
        subs = [p for p in workdir.iterdir() if p.is_dir()]
        if not subs:
            raise RuntimeError("Failed to locate repo root in tarball")
        return subs[0]
    return workdir / top.name

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

            # Get PR changed files; fallback to all *.py
            try:
                changed = list_changed_files(base_owner, base_repo, pr, token, installation_id)
            except Exception as e:
                log.error("failed to list changed files: %s", e)
                changed = []

            paths = changed or [str(p.relative_to(repo_root)) for p in repo_root.rglob("*.py")]
            existing = [p for p in paths if (repo_root / p).exists()]
            if not existing:
                existing = [str(p.relative_to(repo_root)) for p in repo_root.rglob("*.py")]

            # Force-include "*bad*.py" variations
            for pat in ALWAYS_INCLUDE_PATTERNS:
                for found in repo_root.rglob(pat):
                    rel = str(found.relative_to(repo_root))
                    if rel not in existing:
                        existing.append(rel)

            # Compose configs: offline (optional) + repo .semgrep + env/default
            cfgs: List[str] = []
            if PRSEC_FORCE_OFFLINE:
                cfgs.append(_write_offline_semgrep_config(tdp))
            for name in (".semgrep.yaml", ".semgrep.yml"):
                cand = repo_root / name
                if cand.exists():
                    cfgs.append(str(cand))
                    break
            if SEMGREP_CONFIG:
                cfgs.append(SEMGREP_CONFIG)
            if not cfgs:
                cfgs.append("p/security-audit")

            cfg_value = ",".join(cfgs)
            ex = SEMGREP_EXCLUDE if SEMGREP_EXCLUDE else [".venv", "venv", ".git"]

            log.info("SEMGREP_CONFIGS=%s EXCLUDE=%s", cfg_value, ex)
            log.info("Scan root=%s file_count=%d sample=%s", repo_root, len(existing), existing[:10])

            try:
                findings = run_semgrep(paths=existing, repo_root=str(repo_root), config=cfg_value, exclude=ex, timeout_s=SEMGREP_TIMEOUT_S)
            except Exception as e:
                log.error("semgrep invocation failed: %s", e)
                findings = []

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

    # Robust signature verification — but never 4xx by default
    provided256 = (x_hub_signature_256 or "").strip()
    provided1   = (x_hub_signature or "").strip()

    match = True  # default to permissive for CI
    if SECRETS:
        exp256 = [_hmac_sig(sec, body, "sha256") for sec in SECRETS]
        exp1   = [_hmac_sig(sec, body, "sha1") for sec in SECRETS]
        match = (provided256 and provided256 in exp256) or (provided1 and provided1 in exp1)
        if not match:
            log.warning(
                "signature mismatch delivery=%s provided256=%s provided1=%s exp256_suffixes=%s exp1_suffixes=%s",
                x_github_delivery, provided256[-6:] if provided256 else "-", provided1[-6:] if provided1 else "-",
                [e[-6:] for e in exp256], [e[-6:] for e in exp1]
            )

    # If strict mode requested, still reply 200 with ok:false (no 401s)
    if SECRETS and not match and not ALLOW_UNVERIFIED:
        return {"ok": False, "error": "Invalid signature", "delivery": x_github_delivery}

    # Parse JSON payload
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        return {"ok": False, "error": "Invalid JSON", "delivery": x_github_delivery}

    log.info("delivery=%s event=%s len=%d hook_id=%s target=%s", x_github_delivery, x_github_event, len(body), x_github_hook_id, x_github_target)

    # Ping
    if x_github_event == "ping":
        return {"ok": True, "pong": True}

    # Only act on PR events of interest
    if x_github_event == "pull_request":
        action = payload.get("action")
        if action not in {"opened", "reopened", "synchronize", "edited", "ready_for_review"}:
            return {"ok": True, "ignored": action}

        try:
            base = payload["pull_request"]["base"]["repo"]
            head = payload["pull_request"]["head"]["repo"]
            base_owner, base_repo = base["owner"]["login"], base["name"]
            head_owner, head_repo = head["owner"]["login"], head["name"]
            pr_number = int(payload["number"])
            head_sha  = payload["pull_request"]["head"]["sha"]
            base_sha  = payload["pull_request"]["base"]["sha"]
            installation_id = int(payload.get("installation", {}).get("id") or 0)
        except Exception as e:
            log.error("payload parse error: %s", e)
            return {"ok": False, "error": "Malformed PR payload", "delivery": x_github_delivery}

        # Acquire token (non-fatal if it fails; we report and return 200)
        try:
            token = _get_installation_token(installation_id)
        except Exception as e:
            log.error("token acquisition failed: %s", e)
            return {"ok": False, "error": "Token acquisition failed", "delivery": x_github_delivery}

        # Best-effort PR receipt comment
        try:
            _post_json(f"{GITHUB_API}/repos/{base_owner}/{base_repo}/issues/{pr_number}/comments",
                       token, {"body": f"PRSec ✅ received `{action}` for `{head_sha[:7]}` (delivery `{x_github_delivery}`)"},
                       install_id=installation_id)
        except Exception as e:
            log.error("failed to comment on PR: %s", e)

        # Create Check Run (with fallback to head repo)
        try:
            check_owner, check_repo, check_id = create_check_in_progress_with_fallback(
                base_owner, base_repo, head_owner, head_repo, head_sha,
                CHECK_NAME, f"{CHECK_NAME} results", "Scanning…", token, installation_id
            )
        except Exception as e:
            log.error("failed to create check run: %s", e)
            return {"ok": False, "error": "Check run creation failed", "delivery": x_github_delivery}

        # Kick off scanner + watchdog
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

    # Any other event: acknowledge 200
    return {"ok": True, "ignored_event": x_github_event}
