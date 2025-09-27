# bad.py - intentionally insecure sample for training/detection
# DO NOT RUN ON A PUBLIC/PRODUCTION SYSTEM
# Can you see me

import os
import subprocess
import sqlite3
import pickle
import hashlib
import ssl
import smtplib
import random       # insecure randomness for security-sensitive ops
from http.server import HTTPServer, BaseHTTPRequestHandler

# ---------- Hardcoded credentials (detectable secret) ----------
DB_PATH = "/tmp/app.db"
ADMIN_PASSWORD = "P@ssw0rd123"   # hardcoded secret
SMTP_PASSWORD = "emailpass"      # hardcoded secret

# ---------- Insecure TLS (disables certificate verification) ----------
ssl._create_default_https_context = ssl._create_unverified_context

# ---------- Insecure random & weak hashing ----------
def create_token(user_id):
    # using random.random() and md5 is insecure for tokens/crypto
    r = random.random()
    token = hashlib.md5(f"{user_id}-{r}".encode()).hexdigest()
    return token

# ---------- SQL Injection (string formatting used directly) ----------
def add_user_insecure(username, password):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # vulnerable: direct string interpolation into SQL
    cur.execute(f"INSERT INTO users(username, password) VALUES ('{username}', '{password}')")
    conn.commit()
    conn.close()

# ---------- Command injection via shell=True ----------
def list_files(path):
    # vulnerable to command injection if 'path' is attacker-controlled
    cmd = f"ls -la {path}"
    return subprocess.check_output(cmd, shell=True).decode()

# ---------- Unsafe deserialization ----------
def load_session(data_bytes):
    # unsafe: loading pickles from untrusted sources can execute code
    return pickle.loads(data_bytes)

# ---------- Using eval on user input ----------
def calculate(user_expr):
    # absolutely unsafe: eval on arbitrary user input
    return eval(user_expr)

# ---------- Path traversal (unsanitized path join) ----------
def read_user_file(username, filename):
    # vulnerable to path traversal (e.g., filename='../../etc/passwd')
    user_dir = os.path.join("/home/users", username)
    with open(os.path.join(user_dir, filename), "r") as f:
        return f.read()

# ---------- Writing temp files insecurely (predictable names & broad perms) ----------
def write_cache(data):
    path = "/tmp/cache_file"
    # insecure permissions - world-writable file
    with open(path, "w") as f:
        f.write(data)
    os.chmod(path, 0o666)

# ---------- Insecure SMTP usage (plaintext auth) ----------
def send_email(to_addr, subject, body):
    server = smtplib.SMTP("smtp.example.com", 25)
    server.login("noreply@example.com", SMTP_PASSWORD)
    message = f"Subject: {subject}\n\n{body}"
    server.sendmail("noreply@example.com", to_addr, message)
    server.quit()

# ---------- Debug endpoint exposing sensitive data ----------
class BadHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # exposes secrets via debug endpoint
        if self.path.startswith("/debug"):
            self.send_response(200)
            self.end_headers()
            info = {
                "db_path": DB_PATH,
                "admin_password": ADMIN_PASSWORD,
                "token": create_token("admin")
            }
            self.wfile.write(pickle.dumps(info))
            return

        # unsafe eval on query parameter
        if self.path.startswith("/calc?expr="):
            expr = self.path.split("expr=", 1)[1]
            result = calculate(expr)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(str(result).encode())
            return

        # insecure file read
        if self.path.startswith("/file?"):
            # /file?u=alice&f=notes.txt
            qs = dict(x.split("=") for x in self.path.lstrip("/file?").split("&"))
            content = read_user_file(qs.get("u", ""), qs.get("f", ""))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(content.encode())
            return

        self.send_response(404)
        self.end_headers()

def run_server():
    server = HTTPServer(("0.0.0.0", 8080), BadHandler)
    print("Starting bad server on :8080")
    server.serve_forever()


if __name__ == "__main__":
    # create DB for the example (insecurely)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    conn.commit()
    conn.close()
    run_server()
