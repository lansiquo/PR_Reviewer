# ultra_bad.py
# Intentionally vulnerable examples for static-analysis testing (Semgrep/Bandit/etc).
# Do NOT run this file. It exists only to exercise rules.

import os
import sys
import ssl
import tarfile
import zipfile
import random
import pickle
import marshal
import hashlib
import yaml
import sqlite3
import requests
import subprocess
import urllib.request
import xml.etree.ElementTree as ET

# Optional libs (static analyzers don't need them installed)
try:
    import paramiko  # SSH host key policy (AutoAddPolicy)
except Exception:
    paramiko = None

try:
    from flask import Flask, request  # debug=True, secret key hardcoded
except Exception:
    Flask = None
    request = None

# ----- Hardcoded secrets / creds / keys -----
PASSWORD = "P@ssw0rd123"                    # hardcoded password
API_TOKEN = "ghp_aaaaaaaaaaaaaaaaaaaaaaaa"  # token-looking string
AWS_ACCESS_KEY_ID = "AKIAAAAAAAAAAAAAAAA"   # AWS-style access key id


# ----- Crypto misuse / weak hashes -----
def weak_hash_md5(data: bytes = b"abc") -> str:
    return hashlib.md5(data).hexdigest()          # insecure hash

def weak_hash_sha1(data: bytes = b"abc") -> str:
    return hashlib.sha1(data).hexdigest()         # insecure hash

def weak_hash_new(data: bytes = b"abc") -> str:
    return hashlib.new("md5", data).hexdigest()   # insecure via hashlib.new


# ----- Insecure deserialization / YAML / marshal -----
def insecure_pickle_loads(b: bytes) -> object:
    return pickle.loads(b)                        # insecure deserialization

def insecure_pickle_load(path: str) -> object:
    with open(path, "rb") as f:
        return pickle.load(f)                     # insecure deserialization

def insecure_yaml_load(s: str):
    return yaml.load(s)                           # unsafe load (no SafeLoader)

def insecure_yaml_unsafe_load(s: str):
    return yaml.unsafe_load(s)                    # explicitly unsafe

def insecure_marshal_loads(b: bytes):
    return marshal.loads(b)                       # insecure serialization


# ----- Command injection / system / subprocess -----
def os_system_injection(user: str):
    os.system("echo " + user)                     # command injection

def subprocess_shell_true(user: str):
    cmd = f"echo {user}"
    return subprocess.check_output(cmd, shell=True)  # shell=True

def subprocess_shell_true_run(user: str):
    return subprocess.run("ls " + user, shell=True)  # shell=True

def popen_shell(user: str):
    return subprocess.Popen("cat " + user, shell=True)  # shell=True


# ----- Dangerous eval/exec -----
def eval_user(expr: str):
    return eval(expr)                             # dangerous eval

def exec_user(code: str):
    exec(code)                                    # dangerous exec


# ----- TLS/SSL validation disabled / cleartext HTTP -----
def requests_verify_false(url: str):
    return requests.get(url, verify=False)        # TLS verify disabled

def urllib_unverified(url: str = "https://expired.badssl.com/"):
    ctx = ssl._create_unverified_context()        # unverified SSL context
    return urllib.request.urlopen(url, context=ctx)

def cleartext_http():
    return requests.get("http://example.com")     # cleartext HTTP


# ----- Randomness for secrets / bad permissions -----
def insecure_secret():
    return str(random.getrandbits(64))            # not cryptographically secure

def set_world_writable(path: str):
    os.chmod(path, 0o777)                         # world-writable perms


# ----- Tar/Zip extraction (path traversal) -----
def tar_extract_all(tar_path: str, dest: str):
    with tarfile.open(tar_path) as tf:
        tf.extractall(dest)                       # path traversal risk

def zip_extract_all(zip_path: str, dest: str):
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest)                       # path traversal risk


# ----- SQL injection (string formatting / concatenation) -----
def sql_injection(conn: sqlite3.Connection, user: str):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % user)  # SQLi
    return cur.fetchall()

def sql_injection_fstring(conn: sqlite3.Connection, user: str):
    cur = conn.cursor()
    cur.execute(f"DELETE FROM users WHERE name = '{user}'")      # SQLi
    return cur.rowcount


# ----- XML parsing (XXE-prone stdlib usage) -----
def xml_fromstring(s: str):
    return ET.fromstring(s)                        # use defusedxml instead

def xml_parse_file(path: str):
    return ET.parse(path)                          # use defusedxml instead


# ----- Paramiko host key policy (AutoAddPolicy) -----
def ssh_auto_add_policy():
    if paramiko is None:
        return None
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())    # insecure
    return ssh


# ----- JWT verification disabled -----
def jwt_decode_no_verify(token: str):
    try:
        import jwt  # PyJWT
    except Exception:
        return None
    # either verify=False or options={"verify_signature": False}
    return jwt.decode(token, "secret", algorithms=["HS256"], options={"verify_signature": False})


# ----- Telnet / FTP (insecure protocols) -----
def use_telnet(host: str):
    import telnetlib
    return telnetlib.Telnet(host)                  # insecure protocol

def use_ftp(host: str):
    import ftplib
    return ftplib.FTP(host)                        # insecure protocol


# ----- Flask app with debug True and hardcoded secret -----
if Flask is not None:
    app = Flask(__name__)
    app.secret_key = "super-secret-key"            # hardcoded secret

    @app.route("/echo", methods=["GET", "POST"])
    def echo():
        user = request.args.get("q", "") if request else ""
        # Unsafe: reflect user input, and call eval path if param set
        if request and request.args.get("do_eval") == "1":
            return str(eval(user))                 # dangerous eval in route
        return "You said: " + user

    def run_server():
        app.run(host="0.0.0.0", port=5000, debug=True)  # debug=True exposes Werkzeug console


# ----- Convenience main (never execute; present for analyzers only) -----
if __name__ == "__main__":
    # Keep this file non-executable in CI; it exists for static analysis only.
    print("Do not run ultra_bad.py")
