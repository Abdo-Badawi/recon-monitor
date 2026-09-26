"""Periodic monitoring tasks (celery beat): reconcile, CVE sync, auth expiry, JS recheck."""
import logging

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)


@shared_task(name="apps.monitoring.tasks.generate_export", queue="recon")
def generate_export(export_job_id):
    from apps.monitoring.exports import run_export_job

    return run_export_job(export_job_id)


@shared_task(name="apps.monitoring.tasks.detect_stalled_jobs", queue="recon")
def detect_stalled_jobs():
    """Flag RUNNING jobs with no progress/log activity for 30+ minutes -> JOB_STALLED."""
    from datetime import timedelta

    from apps.jobs.models import JobLog, ScanJob
    from services.event_engine.engine import emit_event

    cutoff = timezone.now() - timedelta(minutes=30)
    stalled = 0
    for job in ScanJob.objects.filter(status=ScanJob.STATUS_RUNNING, started_at__lt=cutoff):
        last_log = job.logs.order_by("-created_at").first()
        last_activity = last_log.created_at if last_log else job.started_at
        if last_activity and last_activity < cutoff and not job.stats.get("stalled_flagged"):
            stats = dict(job.stats or {})
            stats["stalled_flagged"] = True
            job.stats = stats
            job.save(update_fields=["stats"])
            emit_event("JOB_STALLED", target=job.target, asset_value=f"job #{job.id} {job.job_type}",
                       source="monitoring", severity="MEDIUM",
                       evidence={"job_id": job.id, "job_type": job.job_type,
                                 "running_since": str(job.started_at)})
            stalled += 1
    return {"stalled": stalled}


@shared_task(name="apps.monitoring.tasks.reconcile_all")
def reconcile_all():
    from apps.jobs.tasks import reconcile_target
    from apps.targets.models import Target

    queued = 0
    for t in Target.objects.filter(status=Target.STATUS_ACTIVE):
        if t.is_scannable:
            reconcile_target.delay(t.id)
            queued += 1
    return {"queued": queued}


@shared_task(name="apps.monitoring.tasks.sync_cve_database")
def sync_cve_database():
    """Sync CVEProject/cvelistV5 (shallow) + vendor advisories stub; store freshness; re-correlate."""
    import subprocess

    from apps.monitoring.models import CVESyncState

    state, _ = CVESyncState.objects.get_or_create(source="cvelistV5")
    # Try git sync if available; never fail hard.
    try:
        import os
        import shutil

        dest = "/tmp/cvelistV5"
        if shutil.which("git"):
            if not os.path.exists(dest):
                subprocess.run(["git", "clone", "--depth", "1",
                                "https://github.com/CVEProject/cvelistV5.git", dest],
                               timeout=600, capture_output=True)
            else:
                subprocess.run(["git", "-C", dest, "pull", "--ff-only"], timeout=600, capture_output=True)
            count = 0
            for _, _, files in os.walk(os.path.join(dest, "cves")):
                count += sum(1 for f in files if f.endswith(".json"))
                if count > 0:
                    break
            state.record_count = count
            state.info = {"path": dest}
        else:
            state.info = {"note": "git unavailable; using bundled KB"}
    except Exception as e:
        state.info = {"error": str(e)[:300]}
    state.last_synced = timezone.now()
    state.save()
    # Re-correlate all known technologies against (bundled or synced) KB
    try:
        from apps.assets.models import Technology
        from services.correlation.ingest import correlate_cves_for_tech

        n = 0
        for tech in Technology.objects.select_related("target").all()[:2000]:
            try:
                correlate_cves_for_tech(tech)
                n += 1
            except Exception:
                continue
        return {"synced": str(state.last_synced), "recorrelated": n}
    except Exception as e:
        return {"synced": str(state.last_synced), "error": str(e)[:300]}


@shared_task(name="apps.monitoring.tasks.check_authorization_expiry")
def check_authorization_expiry():
    from datetime import timedelta

    from apps.targets.models import Target
    from services.event_engine.engine import emit_event

    now = timezone.now()
    paused = 0
    for t in Target.objects.filter(status=Target.STATUS_ACTIVE).exclude(authorization_expires_at=None):
        if t.authorization_expires_at <= now and t.authorization_status != Target.AUTH_EXPIRED:
            t.authorization_status = Target.AUTH_EXPIRED
            t.status = Target.STATUS_PAUSED
            t.save(update_fields=["authorization_status", "status"])
            emit_event("AUTHORIZATION_EXPIRED", target=t, asset_value=t.root_domain,
                       source="monitoring", severity="HIGH",
                       evidence={"expired_at": str(t.authorization_expires_at)})
            paused += 1
        elif t.authorization_expires_at <= now + timedelta(days=t.auth_warning_days):
            emit_event("AUTHORIZATION_EXPIRED", target=t, asset_value=t.root_domain,
                       source="monitoring", severity="MEDIUM",
                       evidence={"warning": True, "expires_at": str(t.authorization_expires_at)})
    return {"paused": paused}


@shared_task(name="apps.monitoring.tasks.recheck_javascript")
def recheck_javascript(target_id=None):
    """Event-triggered + periodic JS rehash: re-download, detect JS_CHANGED."""
    import ssl
    import urllib.request

    from apps.assets.models import JavaScriptAsset
    from apps.targets.models import Target
    from services.correlation.ingest import ingest_js

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    qs = JavaScriptAsset.objects.select_related("target").all()
    if target_id:
        qs = qs.filter(target_id=target_id)
    changed = 0
    for js in qs[:200]:
        if not js.target.is_scannable:
            continue
        try:
            req = urllib.request.Request(js.js_url, headers={"User-Agent": "recon-monitor/1.0"})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
                body = r.read()[:2000000]
            _, outcome = ingest_js(js.target, js.js_url, body, source="recheck")
            if outcome == "JS_CHANGED":
                changed += 1
        except Exception:
            continue
    return {"changed": changed}
