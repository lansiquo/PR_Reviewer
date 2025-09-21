##### Dev setup
1. Use Python 3.11+ (recommended).
2. Create a virtualenv and install dev deps:
   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -U pip
   pip install -r requirements-dev.txt 2>/dev/null || true