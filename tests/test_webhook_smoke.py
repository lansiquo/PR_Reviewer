import os
import json
import hmac
import hashlib
from importlib import reload

from fastapi.testclient import TestClient


def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_webhook_smoke(monkeypatch):
    # Make signature verification pass (app supports either var)
    os.environ["GITHUB_WEBHOOK_SECRET"] = "testsecret"
    os.environ["GITHUB_WEBHOOK_SECRETS"] = "testsecret"

    import app as appmod
    reload(appmod)

    # --- Hard stubs: no network, no semgrep, no sleeps ---

    # Never mint/fetch real tokens
    monkeypatch.setattr(appmod, "_get_installation_token", lambda *a, **k: "dummy-token", raising=True)

    # No outbound GitHub calls (comments)
    monkeypatch.setattr(appmod, "_post_json", lambda *a, **k: {}, raising=True)

    # Do not actually create a check run (return fake owner/repo/id)
    monkeypatch.setattr(
        appmod,
        "create_check_in_progress_with_fallback",
        lambda *a, **k: ("octo", "demo-repo", 123),
        raising=True,
    )

    # Avoid filesystem/network in the pipeline and watchdog sleeps
    monkeypatch.setattr(appmod, "run_semgrep_pipeline", lambda *a, **k: None, raising=True)
    monkeypatch.setattr(appmod, "watchdog_timeout_check", lambda *a, **k: None, raising=True)

    client = TestClient(appmod.app)

    # Payload structure that the handler expects
    payload = {
        "action": "opened",
        "number": 42,
        "installation": {"id": 999},
        "pull_request": {
            "head": {
                "sha": "head456",
                "repo": {"name": "demo-repo", "owner": {"login": "octo"}},
            },
            "base": {
                "sha": "base123",
                "repo": {"name": "demo-repo", "owner": {"login": "octo"}},
            },
        },
    }
    body = json.dumps(payload).encode()
    headers = {
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "smoke-123",
        "X-Hub-Signature-256": _sign("testsecret", body),
        "Content-Type": "application/json",
    }

    resp = client.post("/webhook", content=body, headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "ok": True,
        "event": "pull_request",
        "action": "opened",
        "pr": 42,
        "head": "head456",
        "base": "base123",
    }
