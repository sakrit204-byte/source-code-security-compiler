#!/usr/bin/env sh
set -e
cd "$(dirname "$0")"
if [ ! -f frontend/dist/index.html ]; then
  (cd frontend && npm install && npm run build)
fi
python3 -m pip install -q -r backend/requirements.txt
cd backend && python3 app.py
