#!/bin/bash
set -e
cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
  python3 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt
else
  source venv/bin/activate
fi

# Ensure upload dir
mkdir -p uploads

echo "Starting Static Code Scanner on http://0.0.0.0:8000"
echo "Docs: http://localhost:8000/docs"
echo "Default admin: admin@scanner.local / admin123"
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
