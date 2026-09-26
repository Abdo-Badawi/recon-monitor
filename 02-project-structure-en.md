# Project Structure — recon-monitor

Full project layout (loosely-coupled modules; every external tool gets its own adapter).

```text
recon-monitor/
│
├── config/
│   ├── config.yaml               # global settings (concurrency, timeouts, schedules...)
│   ├── ports.yaml                # configurable port ranges
│   ├── severity-rules.yaml       # rules that decide each event's severity
│   └── tools-paths.yaml          # paths to external tool binaries
│
├── scope/
│   ├── scope.yaml                # roots / allowed_domains / excluded_hosts / allowed_ips
│   └── scope.schema.json         # validation schema for the scope file
│
├── src/
│   └── recon_monitor/
│       │
│       ├── core/
│       │   ├── scheduler.py          # independent scheduling per job
│       │   ├── job_runner.py         # runs jobs + STARTED/COMPLETED/FAILED/PARTIAL/SKIPPED
│       │   ├── checkpoint.py         # state persistence + resume capability
│       │   ├── event_queue.py        # the event-driven core
│       │   └── health_check.py       # tool availability/version checks at startup
│       │
│       ├── scope/
│       │   ├── validator.py          # Scope Validator — mandatory gate before any active op
│       │   └── loader.py             # loads/parses scope files
│       │
│       ├── discovery/
│       │   ├── passive/
│       │   │   ├── subfinder_adapter.py
│       │   │   ├── amass_adapter.py
│       │   │   ├── findomain_adapter.py
│       │   │   ├── assetfinder_adapter.py
│       │   │   ├── crtsh_adapter.py
│       │   │   └── knockpy_adapter.py
│       │   ├── active/
│       │   │   ├── puredns_adapter.py
│       │   │   ├── dnsx_adapter.py
│       │   │   └── ffuf_vhost_adapter.py
│       │   └── normalizer.py         # hostname normalization + dedup
│       │
│       ├── dns/
│       │   ├── resolver.py
│       │   ├── record_tracker.py     # A/AAAA/CNAME/NS/MX/TXT + history
│       │   └── events.py             # NEW_DNS_RECORD, DNS_RECORD_CHANGED, NEW_IP, IP_REMOVED
│       │
│       ├── network/
│       │   ├── naabu_adapter.py
│       │   └── port_tracker.py       # NEW_OPEN_PORT, PORT_CLOSED, PORT_STATE_CHANGED
│       │
│       ├── http/
│       │   ├── httpx_adapter.py
│       │   ├── service_tracker.py    # NEW_HTTP_SERVICE, HTTP_SERVICE_CHANGED/REMOVED
│       │   └── tls_metadata.py
│       │
│       ├── urls/
│       │   ├── historical/
│       │   │   ├── gau_adapter.py
│       │   │   ├── waybackurls_adapter.py
│       │   │   └── waymore_adapter.py
│       │   ├── crawling/
│       │   │   └── katana_adapter.py
│       │   ├── content_discovery/
│       │   │   ├── ffuf_adapter.py
│       │   │   ├── dirsearch_adapter.py
│       │   │   └── gobuster_adapter.py
│       │   ├── url_normalizer.py     # raw_url + canonical_url
│       │   └── api_classifier.py     # REST/GraphQL/Admin/Auth/... endpoints
│       │
│       ├── javascript/
│       │   ├── downloader.py
│       │   ├── hasher.py             # SHA256 + JS_CHANGED detection
│       │   ├── beautifier.py
│       │   ├── analyzers/
│       │   │   ├── jsluice_adapter.py
│       │   │   ├── linkfinder_adapter.py
│       │   │   ├── secretfinder_adapter.py
│       │   │   ├── custom_regex_rules.py
│       │   │   ├── semgrep_adapter.py
│       │   │   └── retirejs_adapter.py
│       │   └── findings_normalizer.py
│       │
│       ├── technology/
│       │   ├── fingerprinter.py
│       │   └── version_tracker.py    # NEW_TECHNOLOGY, TECH_VERSION_CHANGED, TECHNOLOGY_REMOVED
│       │
│       ├── cve/
│       │   ├── cvelist_sync.py       # syncs CVEProject/cvelistV5
│       │   ├── vendor_advisories.py
│       │   ├── version_matcher.py    # affected-version matching
│       │   └── candidate_tracker.py  # NEW_CVE_CANDIDATE, CVE_STATUS_CHANGED, CVE_VALIDATED
│       │
│       ├── security/
│       │   ├── nuclei_adapter.py
│       │   └── finding_tracker.py    # NEW_SECURITY_FINDING, FINDING_CHANGED, FINDING_RESOLVED
│       │
│       ├── storage/
│       │   ├── models.py             # Assets, Subdomains, DNS, IPs, Ports, HTTP, URLs, Endpoints, JS, Tech, CVEs, Findings, Events
│       │   ├── db.py                 # database connection layer
│       │   ├── raw_store.py          # stores raw tool output
│       │   ├── snapshot_store.py     # point-in-time snapshots
│       │   └── history_store.py      # change log over time
│       │
│       ├── correlation/
│       │   ├── graph_builder.py      # builds the Asset Graph (Domain→Sub→IP→Port→HTTP→URL→Tech→CVE)
│       │   └── change_detector.py    # compares new state against stored state
│       │
│       ├── monitoring/
│       │   ├── event_generator.py
│       │   ├── deduplicator.py       # event fingerprinting
│       │   └── reconciliation.py     # periodic full-state reconciliation
│       │
│       ├── alerts/
│       │   ├── discord_alerter.py    # immediate Discord notifications
│       │   ├── severity_rules.py     # INFO/LOW/MEDIUM/HIGH/CRITICAL
│       │   └── formatter.py          # message formatting
│       │
│       └── reports/
│           ├── json_reports.py       # assets.json, subdomains.json, dns.json...
│           └── summary_report.py     # summary.md (human-readable)
│
├── data/
│   ├── raw/                          # raw tool output, untouched
│   ├── normalized/                   # canonical entities after cleanup/merging
│   ├── snapshots/                    # full point-in-time system state
│   ├── history/                      # full change log (audit trail)
│   └── reports/                      # final human/machine-readable reports
│
├── scripts/
│   ├── setup_tools.sh                # install/check external tools
│   └── init_db.py
│
├── tools/
│   └── (references/definitions for the external tools used)
│
├── tests/
│   ├── test_scope_validation.py
│   ├── test_host_normalization.py
│   ├── test_url_normalization.py
│   ├── test_event_deduplication.py
│   ├── test_state_comparison.py
│   ├── test_js_hashing.py
│   ├── test_js_change_detection.py
│   ├── test_cve_version_matching.py
│   ├── test_alert_severity.py
│   ├── test_discord_formatting.py
│   ├── test_tool_failure_handling.py
│   └── test_resume_checkpoint.py
│
├── deploy/
│   ├── docker-compose.yml
│   └── systemd/ (optional, for continuous operation)
│
├── docs/
│   ├── architecture.md
│   └── decisions.md                  # architectural decision log
│
├── .env.example                      # no real secrets
├── .gitignore
├── requirements.txt / pyproject.toml
└── README.md
```

---

## Notes on the Structure

- **Every external tool gets its own adapter** (SubfinderAdapter, AmassAdapter, HttpxAdapter, NucleiAdapter...) so any tool can be swapped without touching the rest of the system.
- **The real `.env` must never be committed to Git** — only `.env.example` ships in the repo.
- **`data/` is clearly partitioned**: raw ≠ normalized ≠ snapshots ≠ history ≠ reports — each has a distinct purpose.
- **GitHub/GitLab discovery is not part of the core structure** — if added later, it should live as a fully separate module (e.g. `src/recon_monitor/repo_discovery/`) with no dependency on the core pipeline.
- Suggested CLI (final naming is an implementation detail):
```bash
recon-monitor scan
recon-monitor monitor
recon-monitor reconcile
recon-monitor update-cves
recon-monitor healthcheck
```

---

## Suggested Improvements (not in the original spec)

- **`docs/runbooks/` folder**: add operational runbooks (e.g. "what to do when a CRITICAL CVE fires", "how to onboard a new authorized root domain") — this pays off fast once the system is actually running unattended.
- **`config/environments/` split**: separate `dev.yaml` / `staging.yaml` / `prod.yaml` overlays on top of `config.yaml`, so testing against a lab target never risks touching production scope by accident.
- **`alerts/channels/` instead of a single `discord_alerter.py`**: keep Discord as the default, but structure it as one channel implementation among others (Slack, email, webhook) behind a common interface — cheap to do now, painful to retrofit later.
- **`storage/migrations/`**: add a schema-migration folder from day one; a stateful system like this will need schema changes as new entity fields get added, and ad-hoc DB edits are risky against live historical data.
