import os
import re
import json
import hmac
import hashlib
from importlib import reload

import pytest
import requests
from fastapi.testclient import TestClient

HEX40 = re.compile(r"^[0-9a-f]{40}$")


def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@pytest.mark.integration
@pytest.mark.skipif(
    os.getenv("RUN_INTEGRATION") != "1",
    reason="Set RUN_INTEGRATION=1 to run integration test (requires real GitHub access).",
)
def test_pull_request_flow_integration():
    # Required env
    owner   = os.getenv("IT_OWNER")
    repo    = os.getenv("IT_REPO")
    prnum_s = os.getenv("IT_PR")
    if not (owner and repo and prnum_s and prnum_s.isdigit()):
        pytest.skip("Missing env: IT_OWNER, IT_REPO, IT_PR")
    prnum = int(prnum_s)

    # Webhook secret (ensure app sees it on import)
    secret = os.getenv("GITHUB_WEBHOOK_SECRET") or "testsecret"
    os.environ["GITHUB_WEBHOOK_SECRET"] = secret
    os.environ["GITHUB_WEBHOOK_SECRETS"] = secret

    # Token for GitHub API + app (prefer installation token)
    explicit_token = os.getenv("EXPLICIT_INSTALLATION_TOKEN")
    api_token = explicit_token or os.getenv("GITHUB_TOKEN")
    if explicit_token:
        os.environ["FORCE_EXPLICIT_TOKEN"] = "1"  # app will use EXPLICIT_INSTALLATION_TOKEN

    # Import app after env is set
    import app as appmod
    reload(appmod)
    client = TestClient(appmod.app)

    # Try to fetch authoritative SHAs (optional)
    expected_head = expected_base = None
    if api_token:
        scheme = "token" if api_token.startswith(("ghp_", "github_pat_")) else "Bearer"
        try:
            r = requests.get(
                f"https://api.github.com/repos/{owner}/{repo}/pulls/{prnum}",
                headers={"Authorization": f"{scheme} {api_token}", "Accept": "application/vnd.github+json"},
                timeout=30,
            )
            r.raise_for_status()
            pj = r.json()
            expected_head, expected_base = pj["head"]["sha"], pj["base"]["sha"]
        except Exception:
            expected_head = expected_base = None

    # Build payload for the new handler
    head_sha = expected_head or ("0" * 40)
    base_sha = expected_base or ("0" * 40)

    payload = {
        "action": "opened",
        "number": prnum,
        "pull_request": {
            "number": prnum,
            "head": {
                "sha": head_sha,
                "repo": {"name": repo, "owner": {"login": owner}},
            },
            "base": {
                "sha": base_sha,
                "repo": {"name": repo, "owner": {"login": owner}},
            },
        },
        "repository": {
            "name": repo,
            "full_name": f"{owner}/{repo}",
            "owner": {"login": owner},
        },
    }

    inst = os.getenv("IT_INSTALLATION_ID")
    if inst and inst.isdigit():
        payload["installation"] = {"id": int(inst)}

    body = json.dumps(payload).encode()
    headers = {
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "int-123",
        "X-Hub-Signature-256": _sign(secret, body),
        "Content-Type": "application/json",
    }

    resp = client.post("/webhook", content=body, headers=headers)
    assert resp.status_code == 200, resp.text
    j = resp.json()

    # Response shape from the new app
    assert j["ok"] is True
    assert j["event"] == "pull_request"
    assert j["action"] == "opened"
    assert j["pr"] == prnum
    assert HEX40.match(j["head"]), f"bad head sha: {j.get('head')}"
    assert HEX40.match(j["base"]), f"bad base sha: {j.get('base')}"

    if expected_head:
        assert j["head"] == expected_head
    if expected_base:
        assert j["base"] == expected_base
