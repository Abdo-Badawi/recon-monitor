# Continuous Recon & Attack Surface Monitoring — Full Workflow

> Important: This system is intended **only for authorized security testing** against explicitly approved scopes. Every active operation must pass through the Scope Validator first.

---

## 1. Core Idea

This is not "run tools and dump output" — it's a **State-Driven + Event-Driven** system:

```text
DISCOVERY
   ↓
NORMALIZE
   ↓
CORRELATE
   ↓
COMPARE WITH HISTORICAL STATE
   ↓
DETECT CHANGE
   ↓
GENERATE EVENT
   ↓
TRIGGER DEPENDENT ANALYSIS
   ↓
IMMEDIATE ALERT (Discord)
   ↓
PERSIST EVERYTHING
```

The key distinction: **discovery can be periodic, but alerting must be event-driven and immediate** — there is no waiting for a 6-hour batch report.

---

## 2. Main End-to-End Workflow

```text
Authorized Root Domain
        │
        ▼
   Scope Validation ──────► Rejected? → Log + Skip
        │ Allowed
        ▼
Subdomain Enumeration
        │
        ├── Passive
        │     ├── subfinder
        │     ├── Amass (passive mode)
        │     ├── Findomain
        │     ├── Assetfinder
        │     ├── crt.sh
        │     └── Knockpy
        │
        └── Active (only after scope check)
              ├── puredns
              ├── dnsx
              └── ffuf (authorized vhost/subdomain discovery)
                    │
                    ▼
          Normalize + Deduplicate Hostnames
                    │
                    ▼
             DNS Resolution (dnsx)
                    │
                    ▼
              Port Discovery (naabu)
                    │
                    ▼
              HTTP Probing (httpx)
                    │
                    ▼
          URL / Endpoint Discovery
                    │
          ┌─────────┼─────────┐
          ▼         ▼         ▼
        gau     waybackurls   waymore
                              │
                              ▼
                    Crawling (katana)
                              │
                              ▼
                 Content Discovery
             (ffuf / dirsearch / gobuster)
                    │
                    ▼
             URL Normalization
                    │
                    ▼
              API Classification
                    │
                    ▼
             JavaScript Analysis Pipeline
                    │
          ┌─────────┼─────────────┐
          ▼         ▼             ▼
       JSluice  LinkFinder    SecretFinder
          │         │             │
          └──────┬──┴─────────────┘
                 ▼
        Semgrep (Static/Semantic Analysis)
                 │
                 ▼
        Retire.js (Vulnerable JS Libraries)
                 │
                 ▼
       Technology / Version Detection
                 │
                 ▼
             CVE Correlation
                 │
        ┌────────┴─────────┐
        ▼                  ▼
 CVEProject/cvelistV5   Vendor Advisories
        │                  │
        └────────┬─────────┘
                 ▼
        Affected-Version Matching
                 │
                 ▼
           CVE Candidate
                 │
                 ▼
         Nuclei (Validation)
                 │
                 ▼
        Security Validation Result
                 │
                 ▼
        State / Correlation Database
                 │
                 ▼
           Change Detection
                 │
                 ▼
          Event Generation
                 │
                 ▼
     ⚡ Immediate Discord Alert ⚡
```

---

## 3. Subdomain Enumeration — Detail

### Passive (no direct target interaction)
- **subfinder**, **Amass (passive)**, **Findomain**, **Assetfinder**, **crt.sh**, **Knockpy**
- No single source is assumed to be complete — merge everything while preserving provenance for every hostname.

```json
{
  "hostname": "api.example.com",
  "sources": ["subfinder", "crtsh"],
  "first_seen": "...",
  "last_seen": "..."
}
```

### Active (only after scope validation)
- **puredns**, **dnsx**, **ffuf** (authorized vhost/subdomain brute-forcing)
- The orchestration layer decides which tool fits the target/scope — never blast every tool at every target.

### Normalization (mandatory before storage)
- Lowercase
- Strip trailing dot
- IDNA normalization
- Syntax validation
- Deduplicate while preserving source + timestamps

Example: `API.Example.COM.`, `api.example.com.`, and `api.example.com` must all collapse to one canonical asset: `api.example.com`.

---

## 4. DNS Resolution

Using `dnsx` and the project's resolver layer, track:
- A / AAAA / CNAME / NS / MX / TXT and other relevant records
- Hostname ↔ IP relationships

```text
api.example.com
      │
      ├── CNAME → api.cloudflare.example
      ├── A     → 1.2.3.4
      └── AAAA  → ...
```

### Events:
```text
NEW_DNS_RECORD
DNS_RECORD_CHANGED
NEW_IP
IP_REMOVED
```

---

## 5. Port Discovery (naabu)

Track: IP / Port / Protocol / State / first_seen / last_seen / last_changed.

Port ranges must be configurable — do not assume only common ports matter.

### Events:
```text
NEW_OPEN_PORT
PORT_CLOSED
PORT_STATE_CHANGED
```

---

## 6. HTTP Probing (httpx)

Collect: URL, Scheme, Host, Port, Status Code, Title, Redirect Chain, Server Header, TLS Info, Tech Fingerprints, Content-Type, Size, IP.

**Critical:** don't store only 200s — every status code (301, 302, 401, 403, 404, 405, 429, 500, 502, 503...) carries useful attack-surface information.

### Events:
```text
NEW_HTTP_SERVICE
HTTP_SERVICE_CHANGED
HTTP_SERVICE_REMOVED
```

---

## 7. URL / Endpoint Discovery

- **Historical:** gau, waybackurls, waymore
- **Crawling:** katana
- **Content Discovery:** ffuf, dirsearch, gobuster

Every URL retains its provenance, then:

### URL Normalization
Keep both:
```text
raw_url
canonical_url
```
Account for: Scheme, Host, Port, Path, Query Params, Fragment, Trailing Slash, Case — without discarding useful query parameters.

### API Classification
Classify: REST / JSON / GraphQL / Versioned APIs / Auth Endpoints / Admin Endpoints / Internal-looking endpoints / HTTP Methods / Params / Content-Types.

Example patterns: `/api/`, `/api/v1/`, `/api/v2/`, `/graphql`, `/rest/`, `/swagger/`, `/openapi.json`

### Events:
```text
NEW_URL
NEW_API_ENDPOINT
API_ENDPOINT_CHANGED
```

---

## 8. JavaScript Intelligence Pipeline (detail)

```text
Discovered JS URL
      ↓
Download
      ↓
Validate Content-Type / Extension
      ↓
SHA256 Hash
      ↓
Deduplicate
      ↓
Store Original File
      ↓
Beautify / Unminify
      ↓
Parallel Analysis:
      ├── JSluice        (extracts endpoints/intel)
      ├── LinkFinder      (routes/paths/API refs)
      ├── SecretFinder    (secret/token candidates)
      ├── Custom Regex Rules
      ├── Semgrep         (static/semantic analysis)
      └── Retire.js       (vulnerable JS libraries)
      ↓
Normalize Findings
      ↓
Correlate
      ↓
Store in DB
```

> Gitleaks and TruffleHog are optional for source-code/repo inputs, but not mandatory for every downloaded browser JS file.

### JS Hash Monitoring (change detection)

```text
app.js  old_sha256 = AAA
app.js  new_sha256 = BBB

AAA != BBB → JS_CHANGED
```

Then automatically:
1. Download the new version
2. Store it
3. Beautify
4. Re-run JS analysis
5. Compare old vs new routes
6. Compare secrets
7. Compare dependencies
8. Compare findings
9. Generate an alert if the change is actually meaningful

### False Positive Handling
Every finding must carry:
```text
type, asset, location, evidence, confidence, source, first_seen, last_seen, status
```
Possible states: `candidate` / `confirmed` / `false_positive` / `resolved` / `unknown`

### Events:
```text
NEW_JS
JS_CHANGED
```

---

## 9. Technology Fingerprinting & Version Detection

Sources: HTTP Headers, HTML, JavaScript, Cookies, TLS, Response Patterns, Framework Signatures, httpx output.

```json
{
  "asset": "https://example.com",
  "product": "ExampleProduct",
  "vendor": "ExampleVendor",
  "version": "1.2.3",
  "confidence": 0.91,
  "evidence": "..."
}
```

### Events:
```text
NEW_TECHNOLOGY
TECH_VERSION_CHANGED
TECHNOLOGY_REMOVED
```

---

## 10. CVE Correlation (no shortcuts)

**Never** use the naive logic: "Product X exists → CVE X exists → therefore vulnerable." Always go through the full chain:

```text
Technology
   ↓
Vendor/Product Normalization
   ↓
Version Identification
   ↓
CVE Database Lookup (CVEProject/cvelistV5 + Vendor Advisories)
   ↓
Affected-Version Matching
   ↓
CVE Candidate
   ↓
Evidence Correlation
   ↓
Nuclei / Validation
   ↓
Final State
```

States: `candidate` / `potentially_affected` / `validated` / `not_affected` / `unknown`

Version match alone is **never enough** to declare a confirmed vulnerability.

### Events:
```text
NEW_CVE_CANDIDATE
CVE_STATUS_CHANGED
CVE_VALIDATED
```

---

## 11. Nuclei — Validation Layer

Runs only on assets that passed scope validation.

```json
{
  "template": "...",
  "asset": "...",
  "severity": "medium",
  "matched_at": "...",
  "timestamp": "...",
  "status": "new"
}
```

### Events:
```text
NEW_SECURITY_FINDING
FINDING_CHANGED
FINDING_RESOLVED
```

---

## 12. Full Example Event Chain — a New Subdomain Appears

```text
new-api.example.com appears
        ↓
Subdomain Discovery
        ↓
NEW_SUBDOMAIN → 🚨 Immediate Discord Alert
        ↓
DNS Resolution → NEW_IP
        ↓
Port Scan → NEW_OPEN_PORT
        ↓
HTTP Probing → NEW_HTTP_SERVICE
        ↓
URL Discovery → NEW_URL
        ↓
JS Discovery → NEW_JS
        ↓
JS Analysis → Technology Detection → Version Detection
        ↓
CVE Correlation → CVE Candidate
        ↓
Nuclei Validation → Security Finding
        ↓
🚨 Discord Alert
```

This pipeline runs asynchronously and never blocks unrelated targets.

---

## 13. Immediate vs Periodic — The Critical Distinction

| Type | Covers |
|---|---|
| **Periodic** | Running discovery, DNS refresh, recrawling, CVE DB updates, re-checking technologies, reconciliation, cleaning stale state |
| **Immediate** | New subdomain, new port, new HTTP service, new endpoint, new/changed JS, tech/version change, new CVE candidate, new security finding |

```text
✅ Correct:
Scheduler → Discovery → Compare with previous state → EVENT → 🚨 Immediate alert

❌ Wrong (forbidden):
Scheduler → wait 6 hours → send a batched report
```

---

## 14. Event Deduplication

Every event gets a fingerprint:
```text
event_type + asset + normalized_value
```
Example: `NEW_SUBDOMAIN|api.example.com` → produces only one alert unless a meaningful change happens later.

---

## 15. Full Event Type List

```text
NEW_SUBDOMAIN

NEW_DNS_RECORD
DNS_RECORD_CHANGED

NEW_IP
IP_REMOVED

NEW_OPEN_PORT
PORT_CLOSED

NEW_HTTP_SERVICE
HTTP_SERVICE_CHANGED

NEW_URL
NEW_API_ENDPOINT

NEW_JS
JS_CHANGED

NEW_TECHNOLOGY
TECH_VERSION_CHANGED

NEW_CVE_CANDIDATE
CVE_VALIDATED

NEW_SECURITY_FINDING
FINDING_CHANGED
FINDING_RESOLVED
```

---

## 16. Scheduler — Independent Jobs

```text
Subdomain Discovery    → periodic
DNS Resolution         → periodic
Port Discovery         → periodic
HTTP Probing           → periodic
URL Discovery          → periodic
JS Analysis            → event-triggered + periodic
Technology Detection   → periodic + event-triggered
CVE Update             → periodic
CVE Correlation        → event-triggered
Nuclei Validation      → event-triggered + periodic
Reconciliation         → periodic
```

Every job is independent — there is no single global 6-hour cycle governing everything.

---

## 17. Explicit Exclusion from the Core Pipeline

**GitHub/GitLab repository discovery is not part of the core workflow at all.** It can be added later as a completely independent module, but the main pipeline starts at:

```text
ROOT DOMAIN → SUBDOMAIN DISCOVERY
```

---

## 18. Core Design Principle (repeated because it matters most)

```text
DISCOVERY → NORMALIZE → CORRELATE → COMPARE WITH STATE
   → DETECT CHANGE → GENERATE EVENT → TRIGGER ANALYSIS
   → IMMEDIATE ALERT → PERSIST
```

This is a living monitoring system, not a "run tools and merge output" script — it compares every new observation against stored history and fires an immediate alert the moment something meaningful appears or changes.

---

## Suggested Improvements (not in the original spec)

- **Alert rate-limiting per severity**: even with dedup, a noisy target (e.g. wildcard DNS, CDN churn) could still flood Discord. Add a per-severity rate cap (e.g. max N `INFO` alerts/hour, batched into a single digest message) while `HIGH`/`CRITICAL` always go out immediately, uncapped.
- **Wildcard DNS detection**: before trusting active subdomain brute-force results, detect wildcard DNS on the root domain — otherwise every bruteforced label will "resolve" and pollute state with false subdomains.
- **Confidence-weighted alerting**: let severity rules also factor in `confidence` (from provenance/tech-fingerprint), not just event type, so a single-source low-confidence finding doesn't page the same as a multi-source high-confidence one.
- **Secrets handling**: findings from SecretFinder/regex rules should never be posted to Discord in raw form — redact/truncate the evidence in the alert and require pulling full evidence from the DB, to avoid leaking live credentials into a chat channel.
- **Kill-switch / pause per target**: an operational control to instantly pause active scanning against a specific root domain (e.g. if the client revokes authorization mid-engagement) without stopping the whole platform.
