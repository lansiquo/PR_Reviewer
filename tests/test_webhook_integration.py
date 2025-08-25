import os
import re
import json
import hmac
import hashlib
from importlib import reload
from pathlib import Path

import pytest
import requests
from fastapi.testclient import TestClient

HEX40 = re.compile(r"^[0-9a-f]{40}$")


def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


class _Resp:
    def __init__(self, status_code=200, json_obj=None, text="", headers=None, content=b""):
        self.status_code = status_code
        self._json = json_obj
        self.text = text
        self.reason = "OK" if status_code < 400 else "Error"
        self.headers = headers or {}
        self.content = content

    def json(self):
        if self._json is None:
            raise ValueError("No JSON")
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(response=self)


@pytest.mark.integration
@pytest.mark.skipif(
    os.getenv("RUN_INTEGRATION") != "1",
    reason="Set RUN_INTEGRATION=1 to run integration test.",
)
def test_pull_request_flow_integration(monkeypatch, tmp_path):
    # Required env for payload
    owner   = os.getenv("IT_OWNER") or "someone"
    repo    = os.getenv("IT_REPO") or "some-repo"
    prnum_s = os.getenv("IT_PR") or "123"
    if not prnum_s.isdigit():
        pytest.skip("IT_PR must be a number")
    prnum = int(prnum_s)

    # Webhook secret (ensure app sees it on import)
    secret = os.getenv("GITHUB_WEBHOOK_SECRET") or "testsecret"
    os.environ["GITHUB_WEBHOOK_SECRET"] = secret
    os.environ["GITHUB_WEBHOOK_SECRETS"] = secret

    # Prevent any real outbound by providing a fake token and forcing its use
    os.environ["EXPLICIT_INSTALLATION_TOKEN"] = "test_token"
    os.environ["FORCE_EXPLICIT_TOKEN"] = "1"

    # Import app after env is set
    import app as appmod
    reload(appmod)

    # ---- Monkeypatch network & FS helpers so no real GitHub is contacted ----

    # Always return a token (already forced), but stub anyway
    monkeypatch.setattr(appmod, "_get_installation_token", lambda _id: "test_token")

    # Fake GH HTTP: minimal endpoints used by the handler & pipeline
    def _fake_gh_request(method, url, token, install_id=None, **kwargs):
        if method == "POST" and url.endswith("/check-runs"):
            # Create check-run
            return _Resp(201, {"id": 987, "html_url": "https://example/check/987"})
        if method == "POST" and "/issues/" in url and url.endswith("/comments"):
            return _Resp(201, {"html_url": "https://example/comment/1"})
        if method == "GET" and "/pulls/" in url and url.endswith("/files"):
            # Pretend PR changed one file
            return _Resp(200, [{"filename": "bad.py"}])
        if method == "GET" and "/check-runs/" in url:
            # For watchdog / status reads
            return _Resp(200, {"status": "in_progress", "conclusion": None})
        if method == "PATCH" and "/check-runs/" in url:
            return _Resp(200, {"ok": True})
        # Tarball fetch isn't used because we stub download_tarball below
        return _Resp(200, {"ok": True})

    monkeypatch.setattr(appmod, "_gh_request", _fake_gh_request)

    # Provide a local "repo" directory instead of downloading a tarball
    def _fake_download_tarball(_o, _r, _sha, _tok, _inst, workdir: Path) -> Path:
        root = workdir / "repo"
        root.mkdir(parents=True, exist_ok=True)
        (root / "bad.py").write_text("print('hi')\n")
        return root

    monkeypatch.setattr(appmod, "download_tarball", _fake_download_tarball)

    # Make Semgrep runner a no-op (we’re not asserting on findings here)
    monkeypatch.setattr(
        appmod, "run_semgrep",
        lambda paths, repo_root, config, exclude, timeout_s: []
    )

    client = TestClient(appmod.app)

    # Optionally discover real SHAs (kept, but harmless if missing token)
    expected_head = expected_base = None
    api_token = os.getenv("GITHUB_TOKEN")
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

    head_sha = expected_head or ("0" * 40)
    base_sha = expected_base or ("0" * 40)

    payload = {
        "action": "opened",
        "number": prnum,
        "pull_request": {
            "number": prnum,
            "head": {"sha": head_sha, "repo": {"name": repo, "owner": {"login": owner}}},
            "base": {"sha": base_sha, "repo": {"name": repo, "owner": {"login": owner}}},
        },
        "repository": {"name": repo, "full_name": f"{owner}/{repo}", "owner": {"login": owner}},
    }

    inst = os.getenv("IT_INSTALLATION_ID")
    if inst and inst.isdigit():
        payload["installation"] = {"id": int(inst)}
    else:
        # Don’t include installation; our stubbed token covers the path
        payload.pop("installation", None)

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

    # Response shape from the app
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
