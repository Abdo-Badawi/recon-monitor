# Deployment

See `docker/docker-compose.yml`. Env vars: DJANGO_SECRET_KEY, DATABASE_URL, REDIS_URL,
DISCORD_WEBHOOK_URL, DJANGO_DEBUG, ALLOWED_HOSTS, CELERY_TASK_ALWAYS_EAGER.
Health: `/health/` (HTML) and `Accept: application/json`. Tools health: `/settings/system/`.
