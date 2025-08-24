import os, requests
from datetime import datetime, timezone, timedelta
import jwt  # pip install PyJWT cryptography

APP_ID = os.getenv("GITHUB_APP_ID")
PK_PATH = os.getenv("GITHUB_PRIVATE_KEY_PATH")
OWNER = os.getenv("IT_OWNER"); REPO = os.getenv("IT_REPO")

if not all([APP_ID, PK_PATH, OWNER, REPO]):
    raise SystemExit("Set GITHUB_APP_ID, GITHUB_PRIVATE_KEY_PATH, IT_OWNER, IT_REPO in .env")

with open(PK_PATH, "r") as f:
    key = f.read()

now = datetime.now(timezone.utc)
payload = {"iat": int(now.timestamp()) - 60, "exp": int((now + timedelta(minutes=9)).timestamp()), "iss": APP_ID}
app_jwt = jwt.encode(payload, key, algorithm="RS256")

h = {"Authorization": f"Bearer {app_jwt}", "Accept": "application/vnd.github+json"}
# resolve installation id for this repo
r = requests.get(f"https://api.github.com/repos/{OWNER}/{REPO}/installation", headers=h, timeout=30)
r.raise_for_status(); inst_id = r.json()["id"]

# exchange for installation token
r = requests.post(f"https://api.github.com/app/installations/{inst_id}/access_tokens", headers=h, timeout=30)
r.raise_for_status(); print(r.json()["token"])
