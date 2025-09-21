# PR Security Reviewer (MVP)

FastAPI service that receives GitHub App webhooks, scans PR diffs with simple rules, and posts a status + comment.

## Quickstart
1. `python -m venv .venv && source .venv/bin/activate`
2. `pip install -r requirements.txt`
3. Copy `.env.example` → `.env` and fill in values (or export env vars).
4. Run locally: `uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}`
5. Use `ngrok http 8000` and set your GitHub App webhook URL to the public ngrok URL `/webhook`.
6. Install the App into a repo and open a PR with changes.

## Notes
- Uses **commit statuses** for simplicity. You can upgrade to **Checks API** for rich annotations later.
- Only scans **added lines** in supported files.
- No code is stored; logs redact sensitive values.# naughty push
