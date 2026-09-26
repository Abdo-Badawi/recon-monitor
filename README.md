# Recon Monitor — Continuous Reconnaissance & Attack-Surface Monitoring

Authorized security testing only. Every active operation passes through scope validation.

## Quickstart (dev, SQLite, no Redis needed)

```bash
git clone https://github.com/Abdo-Badawi/recon-monitor.git
cd recon-monitor
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
# open http://127.0.0.1:8000/dashboard/
```

Full guide (run, production, **all keys/tokens**): [`docs/setup.md`](docs/setup.md).

Celery runs **eager** by default (`CELERY_TASK_ALWAYS_EAGER=True`), so scans execute
in-process without Redis. For production set `CELERY_TASK_ALWAYS_EAGER=False` and
provide `REDIS_URL` + Postgres `DATABASE_URL`.

## Production (docker compose)

```bash
cd docker && docker compose up --build
```

Architecture: Nginx → Django/Daphne → PostgreSQL + Redis → Celery workers → recon tools → event engine → WebSocket + Discord.

## Workflow

Add Target → scope + authorization validated → INITIAL_BASELINE discovery chain
(subdomains → DNS → ports → HTTP → URLs → JS → tech/CVE → nuclei) → BASELINE_COMPLETE
summary → continuous event-driven monitoring with immediate Discord alerts.

Key rules: per-target kill-switch (pause stops only that target), authorization expiry
auto-pauses, scope changes emit SCOPE_CHANGED + audit, secrets are redacted in Discord,
HIGH/CRITICAL bypass batching, baseline suppresses NEW_* floods.

## Docs

- `docs/architecture.md`, `docs/database.md`, `docs/deployment.md`, `docs/alerting.md`, `docs/operations.md`
- Spec files: `01-workflow-en.md`, `02-project-structure-en.md`, `03-description-en.md`
