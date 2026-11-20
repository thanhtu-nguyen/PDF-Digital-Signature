#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
exec .venv/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
