import os
import json
import hmac
import hashlib
from importlib import reload

from fastapi.testclient import TestClient


def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_webhook_smoke(monkeypatch):
    # Set flags BEFORE importing the app so module-level toggles are picked up.
    os.environ["GITHUB_WEBHOOK_SECRET"] = "testsecret"
    os.environ["PRSEC_SKIP_CHECKOUT"] = "1"
    os.environ["PRSEC_SKIP_SEMGREP"] = "1"

    import app as appmod
    reload(appmod)

    # Belt-and-suspenders: also set flags on the imported module.
    appmod.PRSEC_SKIP_CHECKOUT = True
    appmod.PRSEC_SKIP_SEMGREP = True

    # --- Hard stubs: NO network, NO git, NO semgrep ---

    # 1) Never mint/fetch real tokens
    monkeypatch.setattr(appmod, "get_installation_token",
                        lambda *a, **k: "dummy-token", raising=True)

    # 2) Replace GitHub client with a stub
    class DummyGH(appmod.GitHubClient):
        def __init__(self, *a, **k):  # ignore token/base_url
            pass
        def get_pr_shas(self, owner: str, repo: str, pr_number: int):
            return ("base123", "head456")
        def get_changed_files(self, owner: str, repo: str, pr_number: int):
            return [
                {"filename": "app.py", "status": "modified", "patch": "@@..."},
                {"filename": "README.md", "status": "added", "patch": "@@..."},
                {"filename": "logo.png", "status": "added"},  # skipped (binary/no patch)
            ]

    monkeypatch.setattr(appmod, "GitHubClient", DummyGH, raising=True)

    # 3) Never run real git (even though checkout is skipped, keep this safe)
    monkeypatch.setattr(appmod, "ensure_repo_checkout",
                        lambda *a, **k: "/tmp/fake-repo", raising=True)

    # 4) Ensure semgrep path check can't fail and stub runners in case flags change
    monkeypatch.setattr(appmod.shutil, "which",
                        lambda *_: "/usr/bin/semgrep", raising=False)
    monkeypatch.setattr(appmod, "run_semgrep", lambda **kw: [], raising=True)
    monkeypatch.setattr(appmod, "summarize_findings",
                        lambda f: ({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, "summary"),
                        raising=True)
    monkeypatch.setattr(appmod, "to_github_annotations", lambda *a, **k: [], raising=True)

    # ---- exercise the endpoint ----
    client = TestClient(appmod.app)

    payload = {
        "action": "opened",
        "number": 42,
        "pull_request": {"number": 42},
        "repository": {
            "name": "demo-repo",
            "full_name": "octo/demo-repo",
            "owner": {"login": "octo"},
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
    j = resp.json()
    assert j["ok"] is True
    assert j["pr"] == 42
    assert j["base"] == "base123"
    assert j["head"] == "head456"
    assert j["changed_count"] == 2
    assert "app.py" in j["changed_paths"]
    assert "README.md" in j["changed_paths"]
    assert "logo.png" not in j["changed_paths"]
