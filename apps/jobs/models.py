"""Scan job tracking + structured logs."""
from django.db import models


class ScanJob(models.Model):
    STATUS_QUEUED = "QUEUED"
    STATUS_RUNNING = "RUNNING"
    STATUS_COMPLETED = "COMPLETED"
    STATUS_FAILED = "FAILED"
    STATUS_PARTIAL = "PARTIAL"
    STATUS_CANCELLED = "CANCELLED"
    STATUS_PAUSED = "PAUSED"
    STATUS_SKIPPED = "SKIPPED"
    STATUS_CHOICES = [
        (STATUS_QUEUED, "Queued"), (STATUS_RUNNING, "Running"), (STATUS_COMPLETED, "Completed"),
        (STATUS_FAILED, "Failed"), (STATUS_PARTIAL, "Partial"), (STATUS_CANCELLED, "Cancelled"),
        (STATUS_PAUSED, "Paused"), (STATUS_SKIPPED, "Skipped"),
    ]
    target = models.ForeignKey("targets.Target", on_delete=models.CASCADE, related_name="jobs")
    parent = models.ForeignKey("self", null=True, blank=True, on_delete=models.SET_NULL,
                               related_name="children")  # which job triggered this one
    asset_type = models.CharField(max_length=32, default="", blank=True, db_index=True)
    asset_value = models.CharField(max_length=1024, default="", blank=True)
    trigger = models.CharField(max_length=32, default="manual",
                               db_index=True)  # manual/scheduled/event/baseline/reconcile
    job_type = models.CharField(max_length=64, db_index=True)  # subdomain_enum/dns/ports/http/urls/js/tech/cve/nuclei/reconcile/baseline
    stage = models.CharField(max_length=64, default="", blank=True)
    current_stage = models.CharField(max_length=64, default="", blank=True, db_index=True)
    tool = models.CharField(max_length=64, default="", blank=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_QUEUED, db_index=True)
    progress = models.IntegerField(default=0)
    command_redacted = models.TextField(default="", blank=True)
    run_id = models.CharField(max_length=64, default="", blank=True, db_index=True)
    baseline_mode = models.BooleanField(default=False)
    checkpoint = models.JSONField(default=dict, blank=True)
    worker = models.CharField(max_length=128, default="", blank=True)
    error = models.TextField(default="", blank=True)
    stats = models.JSONField(default=dict, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"#{self.pk} {self.job_type} {self.target.root_domain} [{self.status}]"

    @property
    def duration(self):
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None


class JobLog(models.Model):
    LEVEL_DEBUG = "DEBUG"
    LEVEL_INFO = "INFO"
    LEVEL_WARNING = "WARNING"
    LEVEL_ERROR = "ERROR"
    LEVEL_CHOICES = [(LEVEL_DEBUG, "Debug"), (LEVEL_INFO, "Info"), (LEVEL_WARNING, "Warning"), (LEVEL_ERROR, "Error")]
    job = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name="logs")
    level = models.CharField(max_length=16, choices=LEVEL_CHOICES, default=LEVEL_INFO, db_index=True)
    stage = models.CharField(max_length=64, default="", blank=True)
    tool = models.CharField(max_length=64, default="", blank=True, db_index=True)
    message = models.TextField()
    duration_ms = models.IntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["created_at"]


class JSAnalysisJob(models.Model):
    """Dedicated JS analysis job with per-stage progress (QUEUED..COMPLETED/PARTIAL/FAILED)."""

    STAGES = ["QUEUED", "DOWNLOADING", "HASHING", "DEDUPLICATING", "BEAUTIFYING",
              "JSLUICE", "LINKFINDER", "SECRETFINDER", "SEMGREP", "RETIREJS",
              "AGGREGATING", "COMPLETED", "FAILED", "PARTIAL"]
    STATUS_QUEUED = "QUEUED"
    STATUS_RUNNING = "RUNNING"
    STATUS_COMPLETED = "COMPLETED"
    STATUS_PARTIAL = "PARTIAL"
    STATUS_FAILED = "FAILED"
    STATUS_CHOICES = [
        (STATUS_QUEUED, "Queued"), (STATUS_RUNNING, "Running"), (STATUS_COMPLETED, "Completed"),
        (STATUS_PARTIAL, "Partial"), (STATUS_FAILED, "Failed"),
    ]
    target = models.ForeignKey("targets.Target", on_delete=models.CASCADE, related_name="js_jobs")
    js = models.ForeignKey("assets.JavaScriptAsset", on_delete=models.CASCADE, related_name="analysis_jobs")
    parent_job = models.ForeignKey(ScanJob, null=True, blank=True, on_delete=models.SET_NULL,
                                   related_name="js_analyses")
    trigger = models.CharField(max_length=32, default="NEW_JS", db_index=True)  # NEW_JS/JS_CHANGED/recheck/manual
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_QUEUED, db_index=True)
    current_stage = models.CharField(max_length=32, default="QUEUED", db_index=True)
    progress = models.IntegerField(default=0)
    stages = models.JSONField(default=dict, blank=True)  # stage -> COMPLETED/FAILED/SKIPPED/pending
    stats = models.JSONField(default=dict, blank=True)  # endpoints/secrets/dependencies/semgrep/retire counts
    error = models.TextField(default="", blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"JS#{self.pk} {self.js.js_url[:60]} [{self.status}/{self.current_stage}]"


class JSAnalysisLog(models.Model):
    job = models.ForeignKey(JSAnalysisJob, on_delete=models.CASCADE, related_name="logs")
    level = models.CharField(max_length=16, default="INFO", db_index=True)
    stage = models.CharField(max_length=32, default="", blank=True, db_index=True)
    tool = models.CharField(max_length=64, default="", blank=True)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["created_at"]
