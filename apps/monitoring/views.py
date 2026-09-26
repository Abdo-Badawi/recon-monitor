from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404, redirect, render

from apps.core.permissions import audit, require_operator, require_viewer
from apps.targets.models import Target

from .models import Baseline, CVESyncState, ExportJob


@login_required
def monitoring_index(request):
    return render(request, "monitoring/index.html",
                  {"baselines": Baseline.objects.select_related("target").all(),
                   "cve_state": CVESyncState.objects.all()})


@login_required
def workers(request):
    """Worker/queue visibility: inspect active workers when possible (eager-aware)."""
    from django.conf import settings as djsettings

    info = {"eager": getattr(djsettings, "CELERY_TASK_ALWAYS_EAGER", True),
            "broker": getattr(djsettings, "CELERY_BROKER_URL", ""),
            "queues": ["recon", "js_analysis", "cve", "notifications"],
            "routes": getattr(djsettings, "CELERY_TASK_ROUTES", {}),
            "beat": getattr(djsettings, "CELERY_BEAT_SCHEDULE", {}),
            "active": [], "registered": [], "error": ""}
    if not info["eager"]:
        try:
            from config.celery import app as celery_app

            insp = celery_app.control.inspect(timeout=5)
            info["active"] = insp.active() or {}
            info["registered"] = sorted((insp.registered() or {}).get("celery@worker", []) or [])
        except Exception as e:
            info["error"] = str(e)[:300]
    else:
        info["error"] = "Eager mode: tasks execute in-process (no separate workers). Set CELERY_TASK_ALWAYS_EAGER=False with Redis for real workers."
    return render(request, "monitoring/workers.html", info)


@require_viewer
def export_index(request, target_id):
    t = get_object_or_404(Target, pk=target_id)
    jobs = t.exports.order_by("-created_at")[:30]
    return render(request, "monitoring/exports.html",
                  {"target": t, "jobs": jobs, "types": ExportJob.EXPORT_TYPES})


@require_operator
def export_create(request, target_id):
    from django.views.decorators.http import require_POST

    t = get_object_or_404(Target, pk=target_id)
    if request.method == "POST":
        etype = request.POST.get("export_type", "subdomains")
        fmt = request.POST.get("format", "txt")
        if etype == "snapshot":
            fmt = "zip"
        filters = {}
        if request.POST.get("active_only"):
            filters["active_only"] = True
        if request.POST.get("since"):
            filters["since"] = request.POST.get("since")
        job = ExportJob.objects.create(target=t, export_type=etype, format=fmt,
                                       filters=filters, created_by=request.user)
        audit(request, "export.created", job, new=f"{etype}.{fmt}")
        from apps.monitoring.tasks import generate_export

        generate_export.delay(job.id)
        return redirect("export-index", target_id=t.id)
    return redirect("export-index", target_id=t.id)


@require_viewer
def export_history(request):
    jobs = ExportJob.objects.select_related("target").order_by("-created_at")[:50]
    return render(request, "monitoring/export_history.html", {"jobs": jobs})


@require_viewer
def export_download(request, pk):
    import os

    job = get_object_or_404(ExportJob, pk=pk)
    if job.status != ExportJob.STATUS_COMPLETED or not job.file_path or not os.path.exists(job.file_path):
        raise Http404("export not ready")
    return FileResponse(open(job.file_path, "rb"), as_attachment=True)
