# Continuous Recon & Attack Surface Monitoring — Full Project Description

## 1. What Is This Project?

An automated, continuous system for monitoring the external attack surface of explicitly authorized targets only (authorized security testing). Its goal is to maintain an always-current picture of everything relevant to a target: subdomains, DNS, IPs, ports, HTTP services, URLs, API endpoints, JavaScript files, technologies and their versions, potential vulnerabilities (CVEs), and security findings — and the moment something new or meaningfully changed appears, compare it against stored history and send an **immediate** alert to Discord.

This is not "run tools and merge their output" — it's a **living monitoring platform** built around:

```text
Discovery → Normalize → Correlate → Compare with State
   → Detect Change → Generate Event → Trigger Dependent Analysis
   → Immediate Alert → Persist Everything
```

---

## 2. The Scope Rule — The Most Important Rule in the Project

Before any active operation (actually probing the target), the request must pass through the **Scope Validator**:

```text
Input → Scope Validator → Allowed?
                            ├── Yes → Execute
                            └── No  → Skip + Log
```

The scope file defines:
- Allowed root domains
- Allowed subdomains
- Allowed IP ranges
- Explicit exclusions (excluded hosts)
- Rate limits / concurrency limits / timeouts
- Per-tool safety settings

**The system must never expand its own target scope automatically, under any circumstance.**

---

## 3. Workflow Stages (Functional Summary)

| Stage | Function | Tools |
|---|---|---|
| Subdomain discovery | Passive + Active | subfinder, Amass, Findomain, Assetfinder, crt.sh, Knockpy, puredns, dnsx, ffuf |
| DNS analysis | Track all records and link them to IPs | dnsx |
| Port scanning | Discover open ports and track their state | naabu |
| HTTP probing | Collect data for every HTTP/HTTPS service (all status codes) | httpx |
| URL discovery | Historical + Crawling + Content Discovery | gau, waybackurls, waymore, katana, ffuf, dirsearch, gobuster |
| API classification | Identify REST/GraphQL/Admin/Auth endpoints | internal logic |
| JavaScript analysis | Extract endpoints/secrets/dependencies from every JS file | JSluice, LinkFinder, SecretFinder, Semgrep, Retire.js |
| Technology fingerprinting | Identify the technology and version in use | Headers/HTML/JS/TLS fingerprinting |
| CVE correlation | Match version against known vulnerability databases | CVEProject/cvelistV5, Vendor Advisories |
| Security validation | Confirm the potential vulnerability practically | Nuclei |
| Compare & persist | Compare every new observation against prior state and store everything | State/Correlation DB |
| Alerting | Send an immediate alert on any meaningful change | Discord Webhook |

---

## 4. How Data Is Stored

The system is **fully stateful** — no scan is ever treated as fully independent from the previous one. Every entity carries `first_seen`, `last_seen`, `last_changed`.

### Data directory layout:

```text
data/
├── raw/           → raw output of every tool, untouched
├── normalized/     → canonical entities after cleanup and merging
├── snapshots/      → a full system-state snapshot at a given point in time
├── history/        → a log of every change over time (audit trail)
└── reports/        → final human- and machine-readable reports
```

### Entities stored in the central database (Central State):

```text
assets, subdomains, dns_records, ips, ports, http_services,
urls, api_endpoints, javascript_assets, technologies,
versions, cves, findings, events
```

### Provenance Principle
Every discovered piece of information carries its exact source:

```json
{
  "hostname": "api.example.com",
  "sources": [
    {"tool": "subfinder", "timestamp": "...", "confidence": "high"},
    {"tool": "crtsh", "timestamp": "...", "confidence": "medium"}
  ]
}
```

### Building the Asset Graph
The system builds a hierarchical relationship graph that answers "why is this CVE attributed to this exact asset":

```text
example.com → api.example.com → 1.2.3.4 → 443
  → https://api.example.com → Express → version X → CVE candidate
```

---

## 5. Change Detection & Immediate Alerting (The Most Important Part)

### The core distinction between Immediate and Periodic:

| Periodic | Immediate |
|---|---|
| Running discovery again | A new subdomain appears |
| Refreshing DNS | A new port opens |
| Recrawling websites | A new HTTP service appears |
| Updating the CVE database | A new endpoint appears |
| Re-checking technologies | A JS file changes or a new one appears |
| Reconciliation (full-state matching) | A technology version changes |
| Cleaning up stale state | A new CVE candidate appears |
| | A new security finding appears |

```text
✅ The correct way:
Scheduler → Discovery → Compare with prior state → EVENT → 🚨 Immediate alert

❌ The wrong way (forbidden):
Scheduler → wait 6 hours → send one batched report
```

In other words: **the instant a difference between the new scan and the stored state shows something new or meaningfully changed (e.g. a new subdomain or a CVE candidate), an event is generated immediately and pushed to Discord at that same moment — with no waiting for the next full cycle.**

### Real example — a new subdomain appears:

```text
new-api.example.com appears
   → NEW_SUBDOMAIN → 🚨 Immediate Discord Alert
   → DNS Resolution → NEW_IP
   → Port Scan → NEW_OPEN_PORT
   → HTTP Probing → NEW_HTTP_SERVICE
   → URL Discovery → NEW_URL
   → JS Discovery → NEW_JS
   → JS Analysis → Technology + Version Detection
   → CVE Correlation → CVE Candidate
   → Nuclei Validation → Security Finding
   → 🚨 Discord Alert
```

All of this runs asynchronously and in parallel, without blocking other targets being monitored at the same time.

### Preventing Alert Spam (Deduplication)
Every event gets a unique fingerprint:
```text
event_type + asset + normalized_value
```
Example: `NEW_SUBDOMAIN|api.example.com` → only one alert, unless a genuinely meaningful change happens afterward.

### Discord Alert Format

```text
🚨 NEW SUBDOMAIN
Asset: api.example.com
Root: example.com
Source: subfinder + crt.sh
First Seen: 2026-09-26 01:22 UTC
```

```text
⚠️ NEW CVE CANDIDATE
Asset: https://example.com
Technology: ExampleProduct
Version: 1.2.3
CVE: CVE-XXXX-XXXXX
Reason: The detected version falls within the affected range.
Status: Candidate — requires further validation
```

> The system **never** declares a vulnerability "confirmed" unless real evidence (via Nuclei or manual verification) supports that conclusion. A version match alone is not enough.

---

## 6. Fault Tolerance Principle

A single tool failure **never** takes down the whole system:

```text
subfinder fails → log the failure → continue with the other sources (Amass, crt.sh...)
```

Every job carries a state: `STARTED / COMPLETED / FAILED / PARTIAL / SKIPPED`, and the system supports:
- Timeouts, retries, and exponential backoff
- Tool availability/version checks at startup
- Continuing with whatever modules are available when a given tool is missing

### Resume Capability
If the process crashes, the last successfully completed stage is saved and work resumes from there instead of starting over.

```text
Target: example.com
Completed: subdomain enum, DNS resolution, port scan
Incomplete: HTTP probing
Resume from: HTTP probing
```

---

## 7. Reporting

Both machine-readable and human-readable reports are generated periodically:

```text
assets.json, subdomains.json, dns.json, ports.json, http.json,
urls.json, endpoints.json, javascript.json, js-findings.json,
technologies.json, cves.json, security-findings.json,
changes.json, summary.md
```

Every report must clearly distinguish: `new / changed / removed / unchanged / candidate / confirmed / unknown`.

---

## 8. Priority Order When Goals Conflict

```text
1. Scope safety
2. Correctness
3. Persistent state
4. Event-driven architecture
5. Immediate important alerts
6. Low false positives
7. Reliability
8. Performance
9. Convenience
```

---

## 9. What Is Excluded From the Core Project

**GitHub/GitLab repository discovery is not part of the core pipeline at all.** The core workflow starts at:

```text
ROOT DOMAIN → SUBDOMAIN DISCOVERY
```

GitHub/GitLab discovery can be added later as a fully independent module, unrelated to the core, and is never required for the system to function.

---

## 10. Final Acceptance Criteria

### Discovery
- [ ] Passive/Active Subdomain Enumeration
- [ ] DNS Resolution
- [ ] Port Discovery
- [ ] HTTP Probing
- [ ] Historical URL Discovery + Crawling + Content Discovery

### Intelligence
- [ ] URL Normalization + API Classification
- [ ] JS Discovery/Hashing/Change Detection/Route Extraction
- [ ] Secret Candidate Detection + Dependency Detection
- [ ] Technology Fingerprinting + Version Detection
- [ ] CVE Correlation + Nuclei Validation

### Monitoring
- [ ] Persistent State + Historical Snapshots
- [ ] Change Detection + Event Generation + Deduplication
- [ ] **Immediate Discord alerts (not periodic every 6 hours)**
- [ ] Periodic Reconciliation + Failure Recovery + Resume Capability

### Engineering
- [ ] Modular architecture + configuration
- [ ] Scope enforcement everywhere
- [ ] Structured logging + tests + documentation + tool health checks

---

## Suggested Improvements (not in the original spec)

- **Immediate alerts still need a sane throttle, not just dedup.** Dedup stops the *same* event repeating, but a first-time scan of a large target, or a flaky DNS provider, can produce a burst of genuinely distinct `NEW_*` events all at once. Consider a short burst window (e.g. 5–10s) that batches truly simultaneous low/info-severity events into one Discord message, while `HIGH`/`CRITICAL` findings always bypass the batching and go out instantly.
- **Add a "scope change" event type.** When the scope file itself is edited (a root added/removed, an exclusion added), that's a security-relevant event worth its own audit trail and Discord notice — right now the spec tracks changes to the *target* but not changes to the *authorization boundary* itself.
- **Track CVE database freshness explicitly.** Store `cve_db_last_synced` and surface it in the health check / summary report — silently correlating against a stale CVE feed for weeks would quietly degrade the whole CVE-candidate pipeline without anyone noticing.
- **Redact secrets in Discord messages.** For `SecretFinder`/regex-based findings, never post the raw matched string in the alert body — post a masked preview (e.g. first/last 3 chars) and require pulling the full evidence from the DB/report, since Discord channels are a much wider blast radius than the internal DB.
- **Per-target kill-switch.** An operational control to instantly pause active scanning against one specific root domain (e.g. if a client revokes authorization mid-engagement) without stopping the whole monitoring platform.
