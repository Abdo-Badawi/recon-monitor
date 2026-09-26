# Operations

- Onboard target: Add Target → configure scope rules → baseline runs automatically.
- Revoked auth: set status PAUSED (kill-switch) or let authorization_expires_at auto-pause.
- Stuck job: Jobs → Retry/Cancel. Resume: re-run stage; completed state is preserved.
- CVE freshness: Monitoring page shows cvelistV5 last_synced; `sync_cve_database` runs every 6h.
- Tool missing: Settings → System shows MISSING; pipeline skips that source gracefully.
