from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import PlainTextResponse
import json, os, logging
from verify import verify_signature
from github import GitHubClient
from analyzer.rules import Analyzer

app = FastAPI()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

@app.get("/healthz", response_class=PlainTextResponse)
def healthz():
    return "ok"

@app.post("/webhook")
async def webhook(request: Request):
    body = await request.body()
    headers = {k.lower(): v for k, v in request.headers.items()}

    # 1) Verify signature
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(status_code=500, detail="Server misconfigured: missing GITHUB_WEBHOOK_SECRET")
    if not verify_signature(headers, body, secret):
        raise HTTPException(status_code=401, detail="Invalid signature")

    event = headers.get("x-github-event")
    payload = json.loads(body)

    if event == "pull_request" and payload.get("action") in {"opened", "synchronize", "reopened"}:
        repo = payload["repository"]["full_name"]  # owner/repo
        owner = payload["repository"]["owner"]["login"]
        name  = payload["repository"]["name"]
        pr_number = payload["number"]
        head_sha = payload["pull_request"]["head"]["sha"]
        installation_id = (payload.get("installation") or {}).get("id")

        gh = GitHubClient(owner, name, installation_id)

        # 2) Fetch changed files (limited pagination for MVP)
        files = gh.get_pr_files(pr_number, per_page=100, max_pages=5)

        # 3) Analyze added lines only
        analyzer = Analyzer()
        findings = []
        for f in files:
            patch = f.get("patch")
            filename = f.get("filename")
            if not patch:
                continue
            findings.extend(analyzer.scan_patch(filename, patch))

        # 4) Report: commit status + single PR comment
        summary = analyzer.summarize(findings)
        state = "success" if summary["total"] == 0 else "failure"
        gh.set_commit_status(head_sha, state=state, context="prsec", description=summary["status_line"], target_url=None)

        # Use a single issue comment for MVP (inline requires diff position mapping)
        body_lines = ["## PR Security Reviewer\n", summary["status_line"], "\n"]
        if findings:
            body_lines.append("**Findings:**\n")
            for fx in findings[:30]:  # avoid very long comments
                body_lines.append(f"- `{fx['rule']}` in `{fx['file']}` line {fx['line']}: {fx['message']}")
                if fx.get("suggestion"):
                    body_lines.append(f"  \n  Fix: `{fx['suggestion']}`")
        else:
            body_lines.append("No issues detected in added lines.")

        gh.post_issue_comment(pr_number, "\n".join(body_lines))
        return {"ok": True, "findings": summary}

    return {"ok": True, "info": "event ignored"}