"""
BEGINNER-FRIENDLY WALKTHROUGH COMMENTS
=====================================
This file defines a tiny web service (using FastAPI) that listens for GitHub
webhooks on the "/webhook" endpoint. When a Pull Request (PR) event arrives,
  1) Verify the webhook signature (to ensure the request is really from GitHub).
  2) Parse the JSON payload to learn which repo/PR/commit is involved.
  3) Acquire a GitHub token for the installation of this GitHub App.
  4) Post a "Check Run" to GitHub so users see a pending status on the PR.
  5) In a background task, download the PR's code (as a tarball) and run Semgrep
     (a code scanning tool). Then we publish results back to the Check Run.
  6) Also start a watchdog timer. If the scan gets stuck, we mark the Check Run
     as timed out so GitHub's UI doesn't show it as "forever in progress".

There is also a "/health" endpoint for quick health checks.

Notes for non-coders:
- A *function* is a named block of code that performs a job. We add short
  docstrings ("what this does") and inline comments ("why/how") to explain.
- "env var" (environment variable) = a setting provided from the outside,
  like a secret or a timeout. This keeps secrets out of code.
- "token" = a temporary key we use to call GitHub's API as our GitHub App.
- "Check Run" = the little status lines you see on a PR (e.g., checks passing).
- "Semgrep" = a tool that scans code for possible security or quality issues.
- "tarball" = a compressed bundle of files. GitHub can give us one for a commit.
"""

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

from dotenv import load_dotenv
load_dotenv(dotenv_path=".env")  # Load variables from .env if present (handy for local dev)

# --- analyzers ---
# We separate scanning logic into its own module (analyzers/semgrep_runner.py).
# These imports bring in helper functions we use after a scan completes.
from analyzers.semgrep_runner import (
    run_semgrep,            # actually runs Semgrep and returns findings
    to_github_annotations,  # converts findings into GitHub-friendly annotations
    summarize_findings,     # builds summary stats + markdown report
)

# PyJWT is optional; we handle the case where it's missing for environments where
# we don't need to mint app JWTs (JSON Web Tokens).
try:
    import jwt  # PyJWT
except Exception:  # pragma: no cover
    jwt = None

# ---------------- App / Logging ----------------
# FastAPI app object: this is the web server. Title/version appear in docs.
app = FastAPI(title="PRSec Webhook", version="2.1.0")

# Basic logging setup so we can see what's happening.
log = logging.getLogger("webhook")
logging.basicConfig(level=os.getenv("LOGLEVEL", "INFO"))
BOOT_TS = time.time()  # when the process started (for uptime in /health)

# ---------------- Config ----------------
# All the knobs you might want to tweak live in environment variables.
# This makes the service configurable without code changes.
GITHUB_API = os.getenv("GITHUB_API", "https://api.github.com").rstrip("/")

# Webhook secrets: used to verify requests truly came from GitHub. You can
# provide multiple secrets (comma-separated) to support rotation.
WEBHOOK_SECRET = (os.getenv("GITHUB_WEBHOOK_SECRET") or "").strip()
SECRETS = [s.strip() for s in (os.getenv("GITHUB_WEBHOOK_SECRETS") or WEBHOOK_SECRET).split(",") if s.strip()]
ALLOW_UNVERIFIED = os.getenv("ALLOW_UNVERIFIED_WEBHOOKS") == "1"  # for testing: accept bad/missing signatures

# GitHub App credentials (from your GitHub App settings)
APP_ID = (os.getenv("GITHUB_APP_ID") or "").strip()
APP_PEM_PATH = (os.getenv("GITHUB_APP_PRIVATE_KEY_PATH") or "").strip()
APP_PEM_INLINE = (os.getenv("GITHUB_APP_PRIVATE_KEY") or "").strip()  # allows putting key text directly in env

# Token fallback/debug: lets you hardcode an installation token for testing.
EXPLICIT_INSTALLATION_TOKEN = (os.getenv("EXPLICIT_INSTALLATION_TOKEN") or "").strip()
FORCE_EXPLICIT_TOKEN = os.getenv("FORCE_EXPLICIT_TOKEN") == "1"

# Timeouts / limits (seconds). Keep these modest so the webhook handler stays snappy.
HTTP_TIMEOUT_S       = int(os.getenv("HTTP_TIMEOUT_S", "25"))          # HTTP calls to GitHub
SEMGREP_TIMEOUT_S    = int(os.getenv("SEMGREP_TIMEOUT_S", "120"))       # each Semgrep run
PIPELINE_DEADLINE_S  = int(os.getenv("PIPELINE_DEADLINE_S", "90"))       # hard cap for pipeline; 0 disables
WATCHDOG_GRACE_S     = int(os.getenv("WATCHDOG_GRACE_S", "20"))          # extra seconds before watchdog fires

# Scan/reporting configuration
CHECK_NAME      = os.getenv("PRSEC_CHECK_NAME", "PRSec/Semgrep")          # name that appears in GitHub Checks
SEMGREP_CONFIG  = os.getenv("SEMGREP_CONFIG") or None                      # path/ruleset; if None we auto-pick
SEMGREP_EXCLUDE = [s for s in (os.getenv("SEMGREP_EXCLUDE") or "").split(",") if s]  # directories to skip
MAX_ANNOTS      = int(os.getenv("PRSEC_MAX_ANNOTATIONS", "200"))          # upper bound for annotations we send

# QUICK REFERENCE: Required env vars for production
# - GITHUB_WEBHOOK_SECRET or GITHUB_WEBHOOK_SECRETS (one or more secrets to verify webhooks)
# - GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY (or *_PATH) so we can mint JWTs and installation tokens
# Optional but recommended:
# - SEMGREP_CONFIG (your ruleset), SEMGREP_EXCLUDE (paths to skip)
# - PRSEC_MAX_ANNOTATIONS (prevent UI spam), PIPELINE_DEADLINE_S (avoid dangling checks)

# ---------------- Helpers ----------------
def _mask(s: str, keep: int = 6) -> str:
    """Return a partially masked version of a secret for logging (avoids leaks)."""
    if not s:
        return ""
    return s[:keep] + "…" + s[-keep:]

def _secure_eq(a: str, b: str) -> bool:
    """Constant-time string comparison to avoid timing attacks when checking signatures."""
    try:
        return hmac.compare_digest(a, b)
    except Exception:
        return False

def _hmac_sig(secret: str, body: bytes, algo: str) -> str:
    """Compute GitHub-style HMAC signature string for a request body.

    GitHub sends signatures like "sha256=abcdef...". We recreate this using our
    shared secret and verify it matches what GitHub provided.
    """
    algo = algo.lower()
    h = {"sha256": hashlib.sha256, "sha1": hashlib.sha1}[algo]
    return f"{algo}=" + hmac.new(secret.encode("utf-8"), body, h).hexdigest()

def _bearer(token: str) -> Dict[str, str]:
    """Standard headers for calling GitHub's REST API with a Bearer token."""
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "prsec-webhook/1.0",
    }

def _ca_bundle() -> str:
    """Where to find CA certificates so HTTPS requests can verify servers.

    certifi.where() gives us a known-good bundle if the system doesn't provide one.
    """
    return (
        os.getenv("REQUESTS_CA_BUNDLE")
        or os.getenv("SSL_CERT_FILE")
        or certifi.where()
    )

def _read_private_key() -> str:
    """Read the GitHub App private key, either from a file path or from an env var.

    The key must be in PEM format and include "-----BEGIN ... PRIVATE KEY-----" lines.
    """
    if APP_PEM_PATH:
        key = Path(APP_PEM_PATH).read_text()
    else:
        key = APP_PEM_INLINE.replace("\\n", "\n").strip()
    if not key.startswith("-----BEGIN") or "PRIVATE KEY" not in key:
        raise RuntimeError("GITHUB_APP_PRIVATE_KEY[_PATH] is not a valid PEM private key")
    return key

def _create_app_jwt() -> str:
    """Create a short-lived JWT that proves we are the GitHub App.

    We sign a JSON payload with our private key. GitHub accepts this and lets us
    mint an *installation token* (the token that actually talks to repos).
    """
    if not APP_ID:
        raise RuntimeError("GITHUB_APP_ID is missing")
    if jwt is None:
        raise RuntimeError("PyJWT not installed; pip install PyJWT")
    key = _read_private_key()
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 9 * 60, "iss": APP_ID}  # valid ~9 minutes
    token = jwt.encode(payload, key, algorithm="RS256")
    # PyJWT returns bytes in some old versions; normalize to str
    return token.decode() if isinstance(token, (bytes, bytearray)) else token

# ---- central GH request with 401 auto-retry (fresh installation token) ----
def _gh_request(
    method: str,
    url: str,
    token: str,
    install_id: Optional[int] = None,
    **kwargs,
) -> requests.Response:
    """Make a GitHub API request. If we get 401 (expired token), try to refresh once.

    This avoids failing a whole scan just because the token went stale mid-request.
    """
    r = requests.request(method, url, headers=_bearer(token), timeout=HTTP_TIMEOUT_S, verify=_ca_bundle(), **kwargs)
    if r.status_code == 401 and install_id:
        try:
            fresh = _get_installation_token(int(install_id))
            r = requests.request(method, url, headers=_bearer(fresh), timeout=HTTP_TIMEOUT_S, verify=_ca_bundle(), **kwargs)
        except Exception as e:
            log.error("401 retry: failed to mint fresh installation token: %s", e)
    return r

def _post_json(url: str, token: str, payload: dict, install_id: Optional[int] = None) -> dict:
    """POST JSON to GitHub and return the JSON response (or raise on error)."""
    r = _gh_request("POST", url, token, install_id=install_id, json=payload)
    try_json = None
    try:
        try_json = r.json()
    except Exception:
        try_json = None
    if r.status_code >= 400:
        log.error("POST %s -> %s %s body=%s resp=%s", url, r.status_code, r.reason, str(payload)[:400], (r.text or str(try_json))[:800])
    else:
        # Nice-to-have: log link to created resource if GitHub gives us one.
        loc = (try_json or {}).get("html_url") or r.headers.get("Location")
        log.info("POST %s -> %s %s", url, r.status_code, f"Created: {loc}" if loc else "OK")
    r.raise_for_status()
    return try_json or {}

def _patch_json(url: str, token: str, payload: dict, install_id: Optional[int] = None) -> dict:
    """PATCH JSON to GitHub and return the JSON response (or raise on error)."""
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
    """GET JSON from GitHub and return it (or raise on error)."""
    r = _gh_request("GET", url, token, install_id=install_id, params=params or {})
    if r.status_code >= 400:
        log.error("GET %s -> %s %s: %s", url, r.status_code, r.reason, r.text[:800])
    r.raise_for_status()
    return r.json()

def _get_installation_token(installation_id: int) -> str:
    """
    Get an installation token for the given installation id.

    Why two kinds of tokens?
      - App JWT: proves we are the App; used to request installation tokens.
      - Installation token: used to access repos for a specific installation.

    We prefer a token minted on the fly for the installation. If not possible,
    we fall back to a pre-provided token (mostly for testing).
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

# ---------- GitHub Checks helpers ----------
# These helper functions create/update GitHub Check Runs so users see feedback on the PR.

def _create_check_in_progress(owner: str, repo: str, head_sha: str, name: str,
                              title: str, summary: str, token: str,
                              install_id: Optional[int]) -> int:
    """Create a Check Run in the "in_progress" state on a given commit SHA."""
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
    """Try to create the Check Run on the base repo first; if permissions forbid it
    (e.g., PR from a fork), fall back to the head repo.

    Returns (owner, repo, check_id) of where the Check Run ended up.
    """
    try:
        check_id = _create_check_in_progress(base_owner, base_repo, head_sha, name, title, summary, token, install_id)
        return base_owner, base_repo, check_id
    except requests.HTTPError as e:
        rc = getattr(e.response, "status_code", 0)
        if rc in (403, 404, 422):  # common cases for forked PRs or missing perms
            log.info("check-run create fallback to head repo due to %s", rc)
            check_id = _create_check_in_progress(head_owner, head_repo, head_sha, name, title, summary, token, install_id)
            return head_owner, head_repo, check_id
        raise

def complete_check_run(owner: str, repo: str, check_id: int, conclusion: str,
                       title: str, summary: str, annotations: List[Dict[str, Any]],
                       token: str, install_id: Optional[int]) -> None:
    """Flip a Check Run to completed + attach summary and up to 50 annotations.

    GitHub limits each PATCH to 50 annotations. If we have more, we send them in
    additional batches below.
    """
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
    """Safety net: if a Check Run is still stuck "in_progress" after a grace
    period, mark it as "timed_out" so the PR UI doesn't hang forever.
    """
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
# Helpers to talk to GitHub about PR files and to download source code.

def list_changed_files(owner: str, repo: str, pr: int, token: str, install_id: Optional[int]) -> List[str]:
    """Return a list of file paths changed in the given PR.

    We page through results because large PRs can have hundreds of files.
    """
    files: List[str] = []
    page = 1
    while True:
        js = _get_json(f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr}/files", token,
                       params={"per_page": 100, "page": page}, install_id=install_id)
        if not js:
            break
        files.extend([x["filename"] for x in js if isinstance(x.get("filename"), str)])
        if len(js) < 100:
            break  # no more pages
        page += 1
    return files

def download_tarball(owner: str, repo: str, sha: str, token: str, install_id: Optional[int], workdir: Path) -> Path:
    """Download the repository at a specific commit (SHA) as a tar.gz and extract it.

    Returns the local path to the repo root directory extracted under `workdir`.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}/tarball/{sha}"
    r = _gh_request("GET", url, token, install_id=install_id, stream=True)
    if r.status_code >= 400:
        log.error("GET %s -> %s %s: %s", url, r.status_code, r.reason, r.text[:800])
    r.raise_for_status()

    # Read tar bytes into memory, then extract to a temp directory.
    tar_bytes = io.BytesIO(r.content)
    with tarfile.open(fileobj=tar_bytes, mode="r:gz") as tf:
        # SECURITY NOTE: We're extracting files from GitHub's tarball for a commit.
        # This content originates from the target repo; we trust GitHub's tarball
        # format here. In general, be careful with tar extraction (avoid path traversal).
        tf.extractall(workdir)
        # GitHub tarballs nest everything under a single top-level folder like
        # owner-repo-<sha>. We try to detect that folder.
        top = next((m for m in tf.getmembers() if m.isdir() and "/" not in m.name.strip("/")), None)
    if not top:
        # Fallback: pick the first directory created under workdir.
        subs = [p for p in workdir.iterdir() if p.is_dir()]
        if not subs:
            raise RuntimeError("Failed to locate repo root in tarball")
        return subs[0]
    return workdir / top.name

# ---------- Scanning pipeline (check-run only) ----------
# This is the heart of the app: it orchestrates downloading code, running Semgrep,
# and reporting results to GitHub Checks. It always completes the Check Run.

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
    """
    Run a scan and complete the corresponding GitHub Check Run.

    This function is run as a *background task* so the webhook response can return
    quickly to GitHub. No matter what happens (success or failure), we *complete*
    the Check Run so the PR UI doesn't show a stuck check.
    """
    # Default outputs in case anything goes wrong. We'll overwrite these on success.
    conclusion = "failure"
    title = f"{CHECK_NAME} results"
    summary = "Scan failed."
    annotations: List[Dict[str, Any]] = []

    def _safe_complete():
        """Attempt to complete the Check Run, even if earlier steps failed.

        - If sending annotations triggers a GitHub 422 error (e.g., bad locations),
          we retry without annotations so at least the check state flips.
        - We also log state before/after for visibility when debugging.
        """
        try:
            # (Best-effort) fetch current state for visibility
            try:
                jr = _get_json(f"{GITHUB_API}/repos/{check_owner}/{check_repo}/check-runs/{check_id}",
                               token, install_id=installation_id)
                log.info("pre-complete check status id=%s: %s/%s", check_id, jr.get("status"), jr.get("conclusion"))
            except Exception as e:
                log.warning("could not fetch check-run before completion: %s", e)

            # Always complete. If annotations are huge or invalid, cut to zero.
            try_ann = annotations[:MAX_ANNOTS] if annotations else []
            try:
                complete_check_run(check_owner, check_repo, check_id, conclusion, title, summary, try_ann,
                                   token, installation_id)
            except requests.HTTPError as e:
                # If annotations caused 422, retry with none so we at least flip the state
                if getattr(e.response, "status_code", 0) == 422:
                    log.warning("completion 422; retrying without annotations")
                    complete_check_run(check_owner, check_repo, check_id, conclusion, title, summary, [],
                                       token, installation_id)
                else:
                    raise

            try:
                jr = _get_json(f"{GITHUB_API}/repos/{check_owner}/{check_repo}/check-runs/{check_id}",
                               token, install_id=installation_id)
                log.info("post-complete check status id=%s: %s/%s", check_id, jr.get("status"), jr.get("conclusion"))
            except Exception as e:
                log.warning("could not fetch check-run after completion: %s", e)

        except Exception as e:
            log.error("final completion failed: %s", e)

    try:
        # Create a temporary working directory that gets auto-deleted at the end.
        with tempfile.TemporaryDirectory(prefix="prsec_") as td:
            tdp = Path(td)

            # 1) Download the tarball for the commit being tested (the PR "head").
            repo_root = download_tarball(head_owner, head_repo, head_sha, token, installation_id, tdp)

            # 2) Ask GitHub for the list of changed files in this PR.
            try:
                changed = list_changed_files(base_owner, base_repo, pr, token, installation_id)
            except Exception as e:
                log.error("failed to list changed files: %s", e)
                changed = []

            # If listing failed or there were no changes reported, scan Python files as a fallback.
            paths = changed or [str(p.relative_to(repo_root)) for p in repo_root.rglob("*.py")]

            # 3) Only keep paths that actually exist in the downloaded tarball.
            #    If none exist (e.g., PR changed only docs), scan Python files as a fallback.
            existing = [p for p in paths if (repo_root / p).exists()]
            if not existing:
                existing = [str(p.relative_to(repo_root)) for p in repo_root.rglob("*.py")]

            # 4) Decide which Semgrep config to use:
            #    - If SEMGREP_CONFIG env var is set, use it.
            #    - Else, if repo contains .semgrep.yaml/.yml, use that.
            #    - Else, default to a known ruleset so we never run with zero rules.
            cfg = SEMGREP_CONFIG
            if not cfg:
                for name in (".semgrep.yaml", ".semgrep.yml"):
                    cand = repo_root / name
                    if cand.exists():
                        cfg = str(cand)
                        break
            if not cfg:
                cfg = "p/security-audit"  # default ruleset (Semgrep's curated security pack)

            # 5) Build excludes:
            ex = SEMGREP_EXCLUDE if SEMGREP_EXCLUDE else [".venv", "venv", ".git"]

            log.info("SEMGREP_CONFIG=%s EXCLUDE=%s", cfg, ex)
            log.info("PR changed files: %s", changed)
            log.info("Semgrep scan root=%s paths_count=%d sample=%s",
                     repo_root, len(existing), existing[:10])

            # 6) Run Semgrep. If it fails, we log and continue (the check will be marked failure).
            findings: List[Dict[str, Any]] = []
            try:
                findings = run_semgrep(
                    paths=existing,           # scan only relevant files
                    repo_root=str(repo_root),
                    config=cfg,               # guaranteed non-empty by logic above
                    exclude=ex,
                    timeout_s=SEMGREP_TIMEOUT_S,
                )
            except Exception as e:
                log.error("semgrep invocation failed: %s", e)

            # 7) Summarize results and prepare annotations for GitHub.
            counts, summary_md = summarize_findings(findings)
            annotations = to_github_annotations(findings)[:MAX_ANNOTS]

            # 8) Decide overall conclusion: success if zero findings; failure otherwise.
            if sum(counts.values()) == 0:
                conclusion = "success"
                summary = "No issues found"
            else:
                conclusion = "failure"
                summary = "Issues detected"

            # 9) If Semgrep gave us a nice markdown summary, use it as the check body.
            if summary_md:
                summary = summary_md

    except Exception as e:
        # Any unexpected exception leads to a failure conclusion with a terse summary.
        log.error("pipeline error: %s", e)
        # conclusion already 'failure'; summary already set
    finally:
        # 10) Always complete the Check Run, no matter what happened above.
        _safe_complete()


# ---------------- Startup / Health ----------------
@app.on_event("startup")
def _startup_log_routes() -> None:
    """On startup, log the registered routes and how many webhook secrets we have.

    This helps confirm configuration on boot without poking endpoints manually.
    """
    try:
        from starlette.routing import Route
        for r in app.router.routes:
            if isinstance(r, Route):
                log.info("route registered: %s methods=%s", r.path, sorted(r.methods))
        log.info("webhook secrets configured: %d", len(SECRETS))
    except Exception:
        # We don't want startup to fail due to logging issues.
        pass

@app.get("/health", include_in_schema=False)
def health() -> Dict[str, Any]:
    """Simple liveness probe: returns uptime and whether a webhook secret exists."""
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
    """
    Main webhook handler for GitHub events.

    We only *act* on pull_request events (opened/updated/etc.). For pings we
    reply with a simple pong. For other events, we acknowledge and ignore.
    """
    # Read the raw request body (bytes). We use the exact bytes for signature verification.
    body: bytes = await request.body()

    # Signature verification (sha256/sha1). If no secrets configured, accept with a warning.
    provided = x_hub_signature_256 or x_hub_signature
    if not SECRETS:
        log.warning("no webhook secrets configured; accepting delivery=%s without verification", x_github_delivery)
    else:
        if not provided:
            # If secrets are configured but no signature header is provided, reject the request.
            raise HTTPException(status_code=400, detail="Signature required")
        # GitHub can send either sha256=... or older sha1=... style signatures.
        if provided.startswith("sha256="):
            algo = "sha256"
        elif provided.startswith("sha1="):
            algo = "sha1"
        else:
            raise HTTPException(status_code=400, detail="Unsupported signature prefix")
        # Compare the provided signature against signatures computed using each known secret.
        if not any(_secure_eq(provided, _hmac_sig(sec, body, algo)) for sec in SECRETS):
            # For troubleshooting, we log only the last 6 hex characters (suffix) of expected signatures.
            suffixes = [_hmac_sig(sec, body, algo)[-6:] for sec in SECRETS]
            log.warning("signature mismatch delivery=%s algo=%s provided_suffix=%s tried=%d expected_suffixes=%s",
                        x_github_delivery, algo, (provided or "")[-6:], len(SECRETS), suffixes)
            if not ALLOW_UNVERIFIED:
                # In production, reject mismatches. In test mode, we may continue.
                raise HTTPException(status_code=401, detail="Invalid signature")
            log.warning("continuing despite signature mismatch (ALLOW_UNVERIFIED_WEBHOOKS=1)")

    # Parse JSON payload. If it's not valid JSON, tell the client (GitHub) it's a bad request.
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    log.info("delivery=%s event=%s len=%d hook_id=%s target=%s", x_github_delivery, x_github_event, len(body), x_github_hook_id, x_github_target)

    # Handle a simple ping (GitHub uses this to test the webhook URL).
    if x_github_event == "ping":
        return {"ok": True, "pong": True}

    # We only run scans on pull_request events with specific actions.
    if x_github_event == "pull_request":
        action = payload.get("action")
        if action not in {"opened", "reopened", "synchronize", "edited", "ready_for_review"}:
            # Not a relevant action—acknowledge and exit politely.
            return {"ok": True, "ignored": action}

        # Extract base/head repo info (handles fork PRs).
        base = payload["pull_request"]["base"]["repo"]
        head = payload["pull_request"]["head"]["repo"]
        base_owner, base_repo = base["owner"]["login"], base["name"]
        head_owner, head_repo = head["owner"]["login"], head["name"]

        pr_number = int(payload["number"])
        head_sha  = payload["pull_request"]["head"]["sha"]
        base_sha  = payload["pull_request"]["base"]["sha"]
        installation_id = int(payload.get("installation", {}).get("id") or 0)

        # Acquire a token for this installation. If we can't, fail fast; we can't talk to GitHub.
        try:
            token = _get_installation_token(installation_id)
        except Exception as e:
            log.error("token acquisition failed: %s", e)
            raise HTTPException(status_code=500, detail="Token acquisition failed")

        # Post a quick receipt comment on the PR (best-effort; failures are non-fatal).
        try:
            _post_json(f"{GITHUB_API}/repos/{base_owner}/{base_repo}/issues/{pr_number}/comments",
                       token, {"body": f"PRSec ✅ received `{action}` for `{head_sha[:7]}` (delivery `{x_github_delivery}`)"},
                       install_id=installation_id)
        except Exception as e:
            log.error("failed to comment on PR: %s", e)

        # Create an in-progress Check Run immediately so users see activity.
        try:
            check_owner, check_repo, check_id = create_check_in_progress_with_fallback(
                base_owner, base_repo, head_owner, head_repo, head_sha,
                CHECK_NAME, f"{CHECK_NAME} results", "Scanning…", token, installation_id
            )
        except Exception as e:
            log.error("failed to create check run: %s", e)
            raise HTTPException(status_code=500, detail="Check run creation failed")

        # Kick off the actual scan (which will eventually complete the check run),
        # and a watchdog to force-close the check if it gets stuck.
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

        # Respond to GitHub right away; the background tasks continue running.
        return {"ok": True, "event": "pull_request", "action": action, "pr": pr_number, "head": head_sha, "base": base_sha}

    # Any other event type is acknowledged but not processed.
    return {"ok": True, "ignored_event": x_github_event}
