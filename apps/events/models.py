"""Event engine models: persistent events + alert deliveries."""
from django.db import models


class Event(models.Model):
    EVENT_TYPES = [
        ("NEW_SUBDOMAIN", "New subdomain"), ("NEW_DNS_RECORD", "New DNS record"),
        ("DNS_RECORD_CHANGED", "DNS record changed"), ("NEW_IP", "New IP"), ("IP_REMOVED", "IP removed"),
        ("NEW_OPEN_PORT", "New open port"), ("PORT_CLOSED", "Port closed"),
        ("PORT_STATE_CHANGED", "Port state changed"), ("NEW_HTTP_SERVICE", "New HTTP service"),
        ("HTTP_SERVICE_CHANGED", "HTTP service changed"), ("HTTP_SERVICE_REMOVED", "HTTP service removed"),
        ("NEW_URL", "New URL"), ("NEW_API_ENDPOINT", "New API endpoint"),
        ("API_ENDPOINT_CHANGED", "API endpoint changed"), ("NEW_JS", "New JS"), ("JS_CHANGED", "JS changed"),
        ("NEW_TECHNOLOGY", "New technology"), ("TECH_VERSION_CHANGED", "Tech version changed"),
        ("TECHNOLOGY_REMOVED", "Technology removed"), ("NEW_CVE_CANDIDATE", "New CVE candidate"),
        ("CVE_STATUS_CHANGED", "CVE status changed"), ("CVE_VALIDATED", "CVE validated"),
        ("NEW_SECURITY_FINDING", "New security finding"), ("FINDING_CHANGED", "Finding changed"),
        ("FINDING_RESOLVED", "Finding resolved"), ("SCOPE_CHANGED", "Scope changed"),
        ("AUTHORIZATION_EXPIRED", "Authorization expired"),         ("BASELINE_STARTED", "Baseline started"),
        ("BASELINE_COMPLETED", "Baseline completed"), ("JOB_FAILED", "Job failed"),
        ("JOB_STALLED", "Job stalled"), ("SUBDOMAIN_REMOVED", "Subdomain removed"),
        ("URL_CHANGED", "URL changed"), ("JS_ANALYSIS_STARTED", "JS analysis started"),
        ("JS_ANALYSIS_COMPLETED", "JS analysis completed"),
    ]
    SEV_CHOICES = [("INFO", "Info"), ("LOW", "Low"), ("MEDIUM", "Medium"), ("HIGH", "High"), ("CRITICAL", "Critical")]

    event_type = models.CharField(max_length=32, db_index=True)
    target = models.ForeignKey("targets.Target", null=True, blank=True, on_delete=models.CASCADE, related_name="events")
    asset_type = models.CharField(max_length=32, default="", blank=True)
    asset_id = models.IntegerField(null=True, blank=True)
    asset_value = models.CharField(max_length=2048, default="", blank=True, db_index=True)
    severity = models.CharField(max_length=16, choices=SEV_CHOICES, default="INFO", db_index=True)
    confidence = models.CharField(max_length=16, default="unknown")
    source = models.CharField(max_length=128, default="", blank=True)
    evidence = models.JSONField(default=dict, blank=True)
    fingerprint = models.CharField(max_length=128, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["event_type", "created_at"]), models.Index(fields=["target", "created_at"])]

    def __str__(self):
        return f"{self.event_type} {self.asset_value[:60]}"


class Alert(models.Model):
    STATUS_PENDING = "PENDING"
    STATUS_SENT = "SENT"
    STATUS_BATCHED = "BATCHED"
    STATUS_SUPPRESSED = "SUPPRESSED"
    STATUS_FAILED = "FAILED"
    STATUS_SKIPPED = "SKIPPED"
    STATUS_THROTTLED = "THROTTLED"
    STATUS_DEDUPLICATED = "DEDUPLICATED"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"), (STATUS_SENT, "Sent"), (STATUS_BATCHED, "Batched"),
        (STATUS_SUPPRESSED, "Suppressed"), (STATUS_FAILED, "Failed"),
        (STATUS_SKIPPED, "Skipped"), (STATUS_THROTTLED, "Throttled"),
        (STATUS_DEDUPLICATED, "Deduplicated"),
    ]
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="alerts")
    channel = models.CharField(max_length=32, default="discord")
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True)
    payload_preview = models.TextField(default="", blank=True)
    response = models.TextField(default="", blank=True)  # discord response / delivery receipt
    error = models.TextField(default="", blank=True)  # failure reason
    created_at = models.DateTimeField(auto_now_add=True)
    sent_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.channel}:{self.status} for event {self.event_id}"
