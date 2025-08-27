# Change please
# # bad.py
# Intentionally-insecure snippets for Semgrep testing. (touched to trigger scan)
# Do NOT import or run in production.
###

import subprocess
import hashlib
import pickle
import yaml
import requests
import tempfile
import random
import os
import tarfile

def vulnerable_demo(user_input: str, user_cmd: str, yaml_str: str, blob: bytes, tar_path: str, url: str):
    eval(user_input)                                   # ❌ eval() — code execution (bandit:B307)
    subprocess.run("ls " + user_cmd, shell=True)       # ❌ shell=True injection (B602/B603)
    hashlib.md5(b"password").hexdigest()               # ❌ weak hash MD5 (B303)
    yaml.load(yaml_str)                                # ❌ unsafe YAML load (B506) → use yaml.safe_load
    pickle.loads(blob)                                 # ❌ unsafe deserialization (B301)
    requests.get(url, verify=False)                    # ❌ TLS verify disabled (B501)
    with tarfile.open(tar_path, "r") as tf:
        tf.extractall("/tmp/out")                      # ❌ path traversal risk (B202)
    tmp = tempfile.mktemp()                            # ❌ insecure temp file (B306)
    token = str(random.random())                       # ❌ non-crypto RNG for secrets (B311)
    return token


def insecure_md5():
    # Weak hash (cryptographic)
    return hashlib.md5(b"abc").hexdigest()


def insecure_yaml_load(s: str):
    # Unsafe YAML load (no Loader)
    return yaml.load(s)  # noqa: PYYAML-load


def insecure_pickle_loads(b: bytes):
    # Insecure deserialization
    return pickle.loads(b)


def subprocess_shell(user_arg: str):
    # Shell injection risk
    cmd = f"echo {user_arg}"
    return subprocess.check_output(cmd, shell=True)  # noqa: S602


def eval_usage(expr: str):
    # Dangerous eval
    return eval(expr)  # noqa: S307


def disable_cert_validation(url: str):
    # SSL verification disabled
    return requests.get(url, verify=False)  # noqa: B501


def mktemp_race():
    # Insecure temp file creation (TOCTOU)
    tmp = tempfile.mktemp()
    with open(tmp, "w") as f:
        f.write("hi")
    return tmp


def insecure_random_token():
    # Non-cryptographic randomness for secrets
    return str(random.random())


def tar_extract_all(tar_path: str, dest: str):
    # Path traversal via tarfile extraction
    with tarfile.open(tar_path) as tf:
        tf.extractall(dest)  # noqa: S202


if __name__ == "__main__":
    # Keep this file non-executable in CI; it only exists for static analysis.
    pass
