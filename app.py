# FastAPI PR Security Reviewer (Python 3.9+ compatible)
import hashlib, hmac, json, os, re, uuid
from typing import List, Tuple, Optional

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse

load_dotenv()

# --- Config from environment (.env) ---
WEBHOOK_SECRET = (os.getenv("WEBHOOK_SECRET") or "").encode()  # GitHub App webhook secret
GITHUB_TOKEN   = os.getenv("GITHUB_TOKEN") or ""               # PAT or Installation Access Token
USE_CHECKS_API = (os.getenv("USE_CHECKS_API") or "").lower() in {"1","true","yes"}  # optional

# --- App ---
app = FastAPI()

# ---------- Helpers ----------
def verify_signature(secret: bytes, body: bytes, sig_header: Optional[str]) -> None:
    """Validate X-Hub-Signature-256 if a secret is configured."""
    if not secret:
        return
    if not sig_header or not sig_header.startswith("sha256="):
        raise HTTPException(status_code=400, detail="Missing or malformed X-Hub-Signature-256")
    sent = sig_header.split("=", 1)[1]
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sent):
        raise HTTPException(status_code=401, detail="Invalid signature")

def gh_headers() -> dict:
    if not GITHUB_TOKEN:
        raise RuntimeError("GITHUB_TOKEN not set")
    return {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "pr-security-reviewer",
    }

def get_pr_files(owner: str, repo: str, pr_number: int) -> List[dict]:
    files, page = [], 1
    while True:
        url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files?per_page=100&page={page}"
        r = requests.get(url, headers=gh_headers(), timeout=20)
        r.raise_for_status()
        batch = r.json()
        files.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return files

# Very small heuristic rule set (diff-based)
DANGEROUS_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("eval()", re.compile(r"\beval\s*\(")),
    ("exec()", re.compile(r"\bexec\s*\(")),
    ("subprocess shell=True", re.compile(r"subprocess\.\w+\(.*shell\s*=\s*True")),
    ("os.system()", re.compile(r"\bos\.system\s*\(")),
    ("Hardcoded secret", re.compile(r"(AWS|AKIA|SECRET|PASSWORD|TOKEN)\s*[:=]\s*[\"'][^\"']+[\"']")),
]

def run_checks(files: List[dict]):
    findings: List[str] = []
    for f in files:
        patch, filename = f.get("patch"), f.get("filename")
        if not patch:  # binary or too-large patch omitted
            continue
        for rule_name, pat in DANGEROUS_PATTERNS:
            for m in pat.finditer(patch):
                line = patch.count("\n", 0, m.start()) + 1
                findings.append(f"- {rule_name} in `{filename}` (diff line ~{line})")
    status = "success" if not findings else "failure"
    return status, findings

def set_commit_status(owner: str, repo: str, sha: str, state: str, desc: str, target_url: Optional[str] = None):
    """Statuses appear in PR Conversation (not Checks tab)."""
    url = f"https://api.github.com/repos/{owner}/{repo}/statuses/{sha}"
    payload = {"state": state, "context": "pr-security-reviewer", "description": desc[:140]}
    if target_url:
        payload["target_url"] = target_url
    r = requests.post(url, headers=gh_headers(), json=payload, timeout=20)
    print("[status] POST", url, r.status_code, r.text[:300])
    r.raise_for_status()

def post_pr_comment(owner: str, repo: str, pr_number: int, body: str):
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
    r = requests.post(url, headers=gh_headers(), json={"body": body}, timeout=20)
    print("[comment] POST", url, r.status_code, r.text[:300])
    r.raise_for_status()

def create_check_run(owner: str, repo: str, head_sha: str, conclusion: str, summary: str, details: str = ""):
    """
    Optional: Shows results in the PR 'Checks' tab.
    Requires: GitHub App installation token with Checks: Read & write.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/check-runs"
    payload = {
        "name": "PR Security Reviewer",
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,  # success | failure | neutral | cancelled | timed_out | action_required | skipped
        "output": {"title": "PR Security Reviewer", "summary": summary, "text": details[:65535]},
    }
    headers = gh_headers()
    headers["Accept"] = "application/vnd.github+json"
    r = requests.post(url, headers=headers, json=payload, timeout=20)
    print("[checks] POST", url, r.status_code, r.text[:300])
    r.raise_for_status()

# ---------- HTTP ----------
@app.get("/healthz", response_class=PlainTextResponse)
def healthz():
    return "ok"

INTERESTING_ACTIONS = {"opened", "synchronize", "reopened", "ready_for_review"}

@app.post("/webhook", response_class=PlainTextResponse)
async def webhook(request: Request):

    body = await request.body()
    verify_signature(WEBHOOK_SECRET, body, request.headers.get("X-Hub-Signature-256"))
    print("DEBUG GITHUB_TOKEN loaded?", bool(GITHUB_TOKEN))

    event = request.headers.get("X-GitHub-Event", "unknown")
    delivery = request.headers.get("X-GitHub-Delivery", str(uuid.uuid4()))
    print(f"[webhook] event={event} delivery={delivery} bytes={len(body)}")
    if event != "pull_request":
        return "ignored"

    payload = json.loads(body.decode("utf-8"))
    action = payload.get("action")
    if action not in INTERESTING_ACTIONS:
        return "ignored"

    pr = payload["pull_request"]
    base, head = pr["base"], pr["head"]
    owner = base["repo"]["owner"]["login"]
    repo  = base["repo"]["name"]
    pr_number = pr["number"]
    head_sha = head["sha"]

    print(f"[pr] {owner}/{repo}#{pr_number} action={action} head={head_sha[:7]}")

    try:
        # 1) Files in this PR
        files = get_pr_files(owner, repo, pr_number)
        print(f"[pr] files={len(files)}")

        # 2) Run checks
        status, findings = run_checks(files)

        # 3) Report (Statuses API always; Checks API optional)
        desc = "No risky patterns found" if status == "success" else f"{len(findings)} potential issue(s)"
        set_commit_status(owner, repo, head_sha, status, desc)

        if USE_CHECKS_API:
            if status == "success":
                create_check_run(owner, repo, head_sha, "success", "No risky patterns found.")
            else:
                details = "The following patterns were detected in the diff:\n\n" + "\n".join(findings)
                create_check_run(owner, repo, head_sha, "failure", f"{len(findings)} potential issue(s)", details)

        # 4) Comment only when there are findings (to reduce noise)
        if findings:
            body = (
                "### PR Security Reviewer Findings\n"
                "The following patterns were detected in the diff:\n\n" +
                "\n".join(findings) +
                "\n\n> Note: Diff-based heuristic scan. Please review and remediate if applicable."
            )
            post_pr_comment(owner, repo, pr_number, body)

        return "ok"

    except requests.HTTPError as e:
        # Try to surface a red status if we fail mid-flight
        try:
            set_commit_status(owner, repo, head_sha, "error", "Reviewer failed to run")
        except Exception:
            pass
        print("[error]", e.response.status_code, e.response.text)
        raise HTTPException(status_code=500, detail="Processing error")
