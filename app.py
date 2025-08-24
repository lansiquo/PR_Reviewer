# app.py
import hashlib, hmac, json, logging, os, sys
from typing import Optional
from fastapi import FastAPI, Request, Header
from fastapi.responses import JSONResponse

logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("webhook")

WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "").encode()

app = FastAPI()

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.post("/webhook")
async def webhook(
    request: Request,
    x_github_event: Optional[str] = Header(default=None),
    x_hub_signature_256: Optional[str] = Header(default=None),
    x_github_delivery: Optional[str] = Header(default=None),
):
    body: bytes = await request.body()
    log.info("delivery=%s event=%s len=%d", x_github_delivery, x_github_event, len(body))

    # Signature check only if secret is set
    if WEBHOOK_SECRET:
        if not (x_hub_signature_256 and x_hub_signature_256.startswith("sha256=")):
            return JSONResponse({"ok": False, "error": "missing_or_bad_signature_header"}, status_code=400)
        digest = hmac.new(WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(f"sha256={digest}", x_hub_signature_256):
            return JSONResponse({"ok": False, "error": "signature_mismatch"}, status_code=401)

    payload = {}
    if body:
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            log.warning("Non-JSON body (len=%d)", len(body))

    # Cheap router; never index into missing keys
    if x_github_event == "ping":
        return JSONResponse({"ok": True, "pong": True}, status_code=200)

    if x_github_event == "push":
        repo = (payload.get("repository") or {}).get("full_name")
        ref = payload.get("ref")
        log.info("push repo=%s ref=%s", repo, ref)

    if x_github_event == "pull_request":
        action = payload.get("action")
        number = (payload.get("pull_request") or {}).get("number")
        log.info("pull_request action=%s number=%s", action, number)

    return JSONResponse({"ok": True, "event": x_github_event, "received": bool(payload)}, status_code=200)
