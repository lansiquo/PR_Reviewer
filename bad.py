# bad.py
# Intentionally insecure snippets for Semgrep testing.
# Do NOT import or run in production.

import hashlib
import os
import pickle
import random
import subprocess
import tarfile
import tempfile

import requests
import yaml


def insecure_md5() -> str:
    # Weak hash (cryptographic)
    return hashlib.md5(b"abc").hexdigest()


def insecure_yaml_load(s: str):
    # Unsafe YAML load (no Loader)
    return yaml.load(s)


def insecure_pickle_loads(b: bytes):
    # Insecure deserialization
    return pickle.loads(b)


def subprocess_shell(user_arg: str) -> bytes:
    # Shell injection risk
    cmd = f"echo {user_arg}"
    return subprocess.check_output(cmd, shell=True)


def eval_usage(expr: str):
    # Dangerous eval
    return eval(expr)


def disable_cert_validation(url: str):
    # SSL verification disabled
    return requests.get(url, verify=False)


def mktemp_race() -> str:
    # Insecure temp file creation (TOCTOU)
    tmp = tempfile.mktemp()
    with open(tmp, "w") as f:
        f.write("hi")
    return tmp


def insecure_random_token() -> str:
    # Non-cryptographic randomness for secrets
    return str(random.random())


def tar_extract_all(tar_path: str, dest: str) -> None:
    # Path traversal via tarfile extraction
    with tarfile.open(tar_path) as tf:
        tf.extractall(dest)


def os_system_injection(arg: str) -> int:
    # Another command injection primitive
    return os.system("ls " + arg)


if __name__ == "__main__":
    # Keep non-executable in CI; exists purely for static analysis.
    pass
