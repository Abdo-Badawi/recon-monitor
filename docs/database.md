# Database

Models: Target, ScopeRule, Asset, Subdomain, DNSRecord, IPAddress, Port, HTTPService,
URLAsset, APIEndpoint, JavaScriptAsset, JavaScriptVersion, JavaScriptFinding, Technology,
CVE, SecurityFinding, Event, Alert, ScanJob, JobLog, AuditLog, Baseline, CVESyncState, DiscordBatch.

Relationships: Target → all entities; Event → Target + (asset_type, asset_id, asset_value).
History via first_seen/last_seen/last_changed + JavaScriptVersion snapshots.
Run `python manage.py makemigrations && python manage.py migrate`.
