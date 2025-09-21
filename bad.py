# bad.py — intentionally insecure demo for Semgrep tests
import os, subprocess, pickle, base64, yaml, requests, hashlib, random, sqlite3, tarfile, tempfile, json

# --- Hardcoded secrets / credentials (secrets pack)
HARDCODED_PASSWORD = "P@ssw0rd123!"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_ABCDEF1234567890abcdef1234567890abcdef"

def insecure_eval(user_code: str):
    # eval/exec (dangerous code execution)
    eval(user_code)
    exec(user_code)

def sql_injection_example(username: str):
    # SQL Injection via string concat/format
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE users(username TEXT, admin INTEGER)")
    cur.execute(f"SELECT * FROM users WHERE username = '{username}'")  # vuln
    cur.execute("SELECT * FROM users WHERE username = '%s'" % username)  # vuln
    return cur.fetchall()

def insecure_subprocess(cmd: str):
    # Command injection / shell=True
    os.system(cmd)  # vuln
    subprocess.call(cmd, shell=True)  # vuln
    subprocess.run(f"sh -lc '{cmd}'", shell=True, check=False)  # vuln

def weak_crypto_and_tokens(pwd: str):
    # Weak hash / non-crypto randomness
    h = hashlib.md5(pwd.encode()).hexdigest()  # vuln: md5
    token = "".join(str(random.randint(0, 9)) for _ in range(32))  # vuln: random for secrets
    return h, token

def insecure_yaml_load(data: str):
    # Unsafe YAML load (no SafeLoader)
    return yaml.load(data)  # vuln

def insecure_pickle_load(b64: str):
    # Insecure deserialization
    raw = base64.b64decode(b64)
    return pickle.loads(raw)  # vuln

def insecure_http(url: str):
    # TLS verification disabled + suppress warnings
    requests.packages.urllib3.disable_warnings()  # vuln
    r = requests.get(url, verify=False)  # vuln
    return r.text if r.ok else None

def path_traversal(user_path: str):
    # Unvalidated file path usage
    with open(user_path, "r") as f:  # vuln
        return f.read()

def insecure_tempfile():
    # Race-prone temp file
    name = tempfile.mktemp()  # vuln
    with open(name, "w") as f:
        f.write("temp")
    return name

def insecure_tar_extract(tar_path: str):
    # Directory traversal on tar extraction
    with tarfile.open(tar_path) as t:
        t.extractall(".")  # vuln

def debug_leftovers():
    # Debug toggles / prod footguns
    DEBUG = True  # may be flagged by some policies
    print(json.loads('{"ok": true}'))  # harmless, keeps file "realistic"

if __name__ == "__main__":
    # Simulate “user input” to keep linters happy; DO NOT RUN THIS.
    insecure_eval("print('pwn')")               # dangerous
    sql_injection_example("admin' OR 1=1--")    # injection
    insecure_subprocess("echo hello && whoami") # shell=True
    weak_crypto_and_tokens("hunter2")           # md5 + random
    insecure_yaml_load("!!python/object/apply:os.system ['id']")  # unsafe load
    insecure_pickle_load(base64.b64encode(pickle.dumps({'a':1})).decode())
    insecure_http("https://expired.badssl.com/")
    path_traversal("../../etc/passwd")
    insecure_tempfile()
    # insecure_tar_extract("archive.tar")       # uncomment if you have a tar
    debug_leftovers()
