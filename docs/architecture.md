# Architecture

```text
Browser --HTTP/WS--> Django/Daphne --ORM--> PostgreSQL (state)
                              \--broker--> Redis --> Celery workers --> recon tools
Workers --> ingest (state compare) --> Event --> DB + WebSocket + Discord + dependents
```

- Django = application layer (web/API/UI). Celery = async execution. Redis = broker/cache.
- PostgreSQL = persistent state. Channels = realtime UI. Discord = notifications.
- Recon tools are external binaries behind adapters (`services/tool_adapters/`); missing
  tools yield SKIPPED, never crash the pipeline.
- Discovery frequency is independent from alert latency: events alert immediately.
