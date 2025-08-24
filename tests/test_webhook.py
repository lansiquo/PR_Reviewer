# tests/test_webhook.py
import os, json, hmac, hashlib
from importlib import reload
from fastapi.testclient import TestClient

def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

def test_pull_request_flow(monkeypatch):
    # Set secret and re-import app to pick it up
    os.environ["GITHUB_WEBHOOK_SECRET"] = "testsecret"

    import app as appmod
    reload(appmod)  # re-read env into WEBHOOK_SECRET

    # Mock token acquisition
    monkeypatch.setattr(appmod, "get_installation_token", lambda _id: "dummy-token")

    # Stub GitHub client so no real network calls happen
    class DummyGH(appmod.GitHubClient):
        def __init__(self, token: str, base_url: str = appmod.GITHUB_API):
            pass
        def get_pr_shas(self, owner: str, repo: str, pr_number: int):
            return ("base123", "head456")
        def get_changed_files(self, owner: str, repo: str, pr_number: int):
            return [
                {"filename": "app.py", "status": "modified", "patch": "@@..."},
                {"filename": "README.md", "status": "added", "patch": "@@..."},
                {"filename": "logo.png", "status": "added"}  # skipped (binary, no patch)
            ]

    monkeypatch.setattr(appmod, "GitHubClient", DummyGH)

    client = TestClient(appmod.app)

    payload = {
        "action": "opened",
        "number": 42,
        "pull_request": {"number": 42, "head": {"sha": "head456"}},
        "repository": {
            "name": "demo-repo",
            "full_name": "octo/demo-repo",
            "owner": {"login": "octo"}
        },
        "installation": {"id": 123456}
    }
    body = json.dumps(payload).encode()
    headers = {
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "test-123",
        "X-Hub-Signature-256": _sign("testsecret", body),
        "Content-Type": "application/json",
    }

    resp = client.post("/webhook", data=body, headers=headers)
    assert resp.status_code == 200, resp.text
    j = resp.json()
    assert j["ok"] is True
    assert j["pr"] == 42
    assert j["base"] == "base123"
    assert j["head"] == "head456"
    assert j["changed_count"] == 2
    assert "app.py" in j["changed_paths"]
    assert "README.md" in j["changed_paths"]
    assert "logo.png" not in j["changed_paths"]
