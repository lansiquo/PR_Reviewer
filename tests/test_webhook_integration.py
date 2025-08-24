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
    secret  = os.getenv("GITHUB_WEBHOOK_SECRET", "testsecret")
    owner   = os.getenv("IT_OWNER")
    repo    = os.getenv("IT_REPO")
    prnum_s = os.getenv("IT_PR")

    if not (owner and repo and prnum_s and prnum_s.isdigit()):
        pytest.skip("Missing env: IT_OWNER, IT_REPO, IT_PR")
    prnum = int(prnum_s)

    # Only include installation id if valid; otherwise let server resolve it
    inst = os.getenv("IT_INSTALLATION_ID")
    if inst and not inst.isdigit():
        inst = None

    os.environ["GITHUB_WEBHOOK_SECRET"] = secret

    import app as appmod
    reload(appmod)

    client = TestClient(appmod.app)

    payload = {
        "action": "opened",
        "number": prnum,
        "pull_request": {"number": prnum},  # server will fetch authoritative SHAs
        "repository": {
            "name": repo,
            "full_name": f"{owner}/{repo}",
            "owner": {"login": owner},
        },
    }
    if inst:
        payload["installation"] = {"id": int(inst)}

    body = json.dumps(payload).encode()
    headers = {
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "int-123",
        "X-Hub-Signature-256": _sign(secret, body),
        "Content-Type": "application/json",
    }

    # Optionally fetch SHAs from GitHub for strict comparison (if a token present)
    expected_head = expected_base = None
    tok = os.getenv("EXPLICIT_INSTALLATION_TOKEN") or os.getenv("GITHUB_TOKEN")
    if tok:
        scheme = "token" if tok.startswith(("ghp_", "github_pat_")) else "Bearer"
        try:
            r = requests.get(
                f"https://api.github.com/repos/{owner}/{repo}/pulls/{prnum}",
                headers={"Authorization": f"{scheme} {tok}", "Accept": "application/vnd.github+json"},
                timeout=30,
            )
            r.raise_for_status()
            pj = r.json()
            expected_head, expected_base = pj["head"]["sha"], pj["base"]["sha"]
        except Exception:
            expected_head = expected_base = None  # fall back to hex-only checks

    resp = client.post("/webhook", data=body, headers=headers)
    assert resp.status_code == 200, resp.text
    j = resp.json()
    assert j["ok"] is True
    assert j["pr"] == prnum
    assert HEX40.match(j["head"]), f"bad head sha: {j['head']}"
    assert HEX40.match(j["base"]), f"bad base sha: {j['base']}"
    if expected_head:
        assert j["head"] == expected_head
    if expected_base:
        assert j["base"] == expected_base
    assert isinstance(j["changed_count"], int)
