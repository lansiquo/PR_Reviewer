import os, time, json, requests
import certifi
import jwt  # PyJWT

APP_ID = os.environ["GITHUB_APP_ID"]
APP_PEM = os.environ["GITHUB_APP_PRIVATE_KEY"].replace("\\n", "\n").strip()
INSTALLATION_ID = int(os.environ["INSTALLATION_ID"])
GITHUB_API = os.getenv("GITHUB_API", "https://api.github.com").rstrip("/")

now = int(time.time())
payload = {"iat": now - 60, "exp": now + 9 * 60, "iss": APP_ID}
app_jwt = jwt.encode(payload, APP_PEM, algorithm="RS256")
if isinstance(app_jwt, (bytes, bytearray)):
    app_jwt = app_jwt.decode()

r = requests.post(
    f"{GITHUB_API}/app/installations/{INSTALLATION_ID}/access_tokens",
    headers={"Authorization": f"Bearer {app_jwt}", "Accept": "application/vnd.github+json"},
    timeout=20,
    verify=os.getenv("REQUESTS_CA_BUNDLE") or os.getenv("SSL_CERT_FILE") or certifi.where(),
)
r.raise_for_status()
print(json.dumps(r.json(), indent=2))
