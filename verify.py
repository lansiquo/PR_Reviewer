import hmac, hashlib

def verify_signature(headers: dict, body: bytes, secret: str) -> bool:
    sig = headers.get("x-hub-signature-256")
    if not sig or not sig.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)