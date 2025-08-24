import os, json, hmac, hashlib, uuid, requests
from dotenv import load_dotenv

load_dotenv()
secret = os.getenv("WEBHOOK_SECRET", "")
url = "http://127.0.0.1:8000/webhook"
payload = {"zen": "Keep it logically awesome."}
body = json.dumps(payload, separators=(",", ":")).encode()

sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
headers = {
    "Content-Type": "application/json",
    "X-GitHub-Event": "ping",
    "X-GitHub-Delivery": str(uuid.uuid4()),
    "X-Hub-Signature-256": f"sha256={sig}",
}
r = requests.post(url, data=body, headers=headers, timeout=10)
print(r.status_code, r.text)
