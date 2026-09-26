#!/usr/bin/env bash
# Start the Recon Monitor web app (dev server).
set -e
cd "$(dirname "$0")/.."
exec .venv/bin/python manage.py runserver 0.0.0.0:8000
