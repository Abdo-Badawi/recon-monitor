"""Central event flow: persist -> websocket -> dependent analysis -> discord.

Worker -> Parser -> Normalizer -> State comparison -> Event -> DB ->
  Celery event handler -> {Dashboard WebSocket, Dependent analysis, Discord}
"""
import hashlib
import logging

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.utils import timezone

logger = logging.getLogger(__name__)

SEVERITY_BY_EVENT = {
    "NEW_SUBDOMAIN": "LOW", "NEW_DNS_RECORD": "INFO", "DNS_RECORD_CHANGED": "LOW",
    "NEW_IP": "LOW", "IP_REMOVED": "INFO", "NEW_OPEN_PORT": "MEDIUM",
    "PORT_CLOSED": "INFO", "PORT_STATE_CHANGED": "LOW", "NEW_HTTP_SERVICE": "LOW",
    "HTTP_SERVICE_CHANGED": "LOW", "HTTP_SERVICE_REMOVED": "INFO", "NEW_URL": "INFO",
    "NEW_API_ENDPOINT": "LOW", "API_ENDPOINT_CHANGED": "LOW", "NEW_JS": "INFO",
    "JS_CHANGED": "MEDIUM", "NEW_TECHNOLOGY": "LOW", "TECH_VERSION_CHANGED": "MEDIUM",
    "TECHNOLOGY_REMOVED": "INFO", "NEW_CVE_CANDIDATE": "HIGH", "CVE_STATUS_CHANGED": "MEDIUM",
    "CVE_VALIDATED": "HIGH", "NEW_SECURITY_FINDING": "HIGH", "FINDING_CHANGED": "MEDIUM",
    "FINDING_RESOLVED": "INFO", "SCOPE_CHANGED": "MEDIUM", "AUTHORIZATION_EXPIRED": "HIGH",
    "BASELINE_STARTED": "INFO", "BASELINE_COMPLETED": "INFO", "JOB_FAILED": "MEDIUM",
}


def make_fingerprint(event_type: str, asset_value: str, extra: str = "") -> str:
    base = f"{event_type}|{(asset_value or '').strip().lower()}|{(extra or '').strip().lower()}"
    return hashlib.sha256(base.encode()).hexdigest()[:32]


def is_baseline_suppressed(target) -> bool:
    """During INITIAL_BASELINE, suppress normal NEW_* discord alerts (still persist events)."""
    return getattr(target, "baseline_status", "") == "INITIAL_BASELINE"


def emit_event(event_type, target=None, asset_type="", asset_id=None, asset_value="",
               source="", evidence=None, severity=None, confidence="unknown", extra_fp=""):
    """Create event (dedup by fingerprint), broadcast WS, trigger discord + dependents. Returns (event, created)."""
    from apps.events.models import Event

    fingerprint = make_fingerprint(event_type, asset_value or "", extra_fp)
    sev = severity or SEVERITY_BY_EVENT.get(event_type, "INFO")
    existing = Event.objects.filter(fingerprint=fingerprint).first()
    if existing:
        return existing, False
    event = Event.objects.create(
        event_type=event_type, target=target, asset_type=asset_type, asset_id=asset_id,
        asset_value=asset_value or "", severity=sev, confidence=confidence,
        source=source or "", evidence=evidence or {}, fingerprint=fingerprint,
    )
    broadcast_event(event)
    # Dependent analysis triggers (async via celery; eager in dev)
    try:
        from apps.jobs import tasks as job_tasks

        job_tasks.handle_event_dependents.delay(event.id)
    except Exception as e:
        logger.warning("dependent dispatch failed: %s", e)
    # Discord (baseline-aware)
    try:
        from apps.alerts import tasks as alert_tasks

        if target is not None and is_baseline_suppressed(target) and event_type.startswith("NEW_"):
            from apps.events.models import Alert

            Alert.objects.create(event=event, channel="discord", status="SUPPRESSED",
                                 payload_preview="suppressed during INITIAL_BASELINE")
        else:
            alert_tasks.send_discord_alert.delay(event.id)
    except Exception as e:
        logger.warning("discord dispatch failed: %s", e)
    return event, True


def broadcast_event(event):
    try:
        layer = get_channel_layer()
        payload = {
            "type": "event.created",
            "id": event.id, "event_type": event.event_type,
            "asset_value": event.asset_value, "severity": event.severity,
            "target": event.target.root_domain if event.target else "",
            "target_id": event.target_id, "created_at": event.created_at.isoformat(),
        }
        async_to_sync(layer.group_send)("events", {"type": "event_message", "data": payload})
        if event.target_id:
            async_to_sync(layer.group_send)(f"target_{event.target_id}", {"type": "event_message", "data": payload})
    except Exception as e:
        logger.warning("websocket broadcast failed: %s", e)


def broadcast_job_like(job):
    """Generic progress broadcast for ScanJob and JSAnalysisJob."""
    try:
        layer = get_channel_layer()
        target = getattr(job, "target", None)
        payload = {"type": "job.progress", "id": job.id,
                   "job_type": getattr(job, "job_type", "js_analysis"),
                   "status": job.status, "progress": getattr(job, "progress", 0),
                   "stage": getattr(job, "current_stage", ""),
                   "target": target.root_domain if target else "",
                   "target_id": target.id if target else None}
        async_to_sync(layer.group_send)("jobs", {"type": "event_message", "data": payload})
    except Exception as e:
        logger.warning("job broadcast failed: %s", e)


broadcast_job = broadcast_job_like  # backwards-compatible alias
