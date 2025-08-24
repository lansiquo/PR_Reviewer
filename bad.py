import subprocess, hashlib, yaml, pickle
subprocess.run("ls -la", shell=True)
hashlib.md5(b"secret").hexdigest()
yaml.load("a: 1")
pickle.loads(b"cos\nsystem\n(S'ls'\ntR.")
