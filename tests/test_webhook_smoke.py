import os
import json
import hmac
import hashlib
from importlib import reload

from fastapi.testclient import TestClient


def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_webhook_smoke(monkeypatch):
    # Minimal env so signature check passes
    os.environ["GITHUB_WEBHOOK_SECRET"] = "testsecret"

    import app as appmod
    reload(appmod)

    # ---- Hard stubs: NO network, NO git, NO semgrep ----

    # 1) Never mint/fetch real tokens
    monkeypatch.setattr(appmod, "get_installation_token", lambda *a, **k: "dummy-token", raising=True)

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

    # 3) Never run real git
    monkeypatch.setattr(appmod, "ensure_repo_checkout", lambda *a, **k: "/tmp/fake-repo", raising=True)

    # 4) Pretend semgrep exists and returns no findings
    #    (app checks shutil.which("semgrep") before calling run_semgrep)
    monkeypatch.setattr(appmod.shutil, "which", lambda *_: "/usr/bin/semgrep", raising=False)

    # stub the semgrep runner functions
    import analyzers.semgrep_runner as sr
    monkeypatch.setattr(sr, "run_semgrep", lambda **kwargs: [], raising=True)
    monkeypatch.setattr(sr, "summarize_findings",
                        lambda f: ({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, "summary"),
                        raising=True)
    monkeypatch.setattr(sr, "to_github_annotations", lambda *a, **k: [], raising=True)

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
