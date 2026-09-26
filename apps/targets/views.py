from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.core.permissions import audit, require_admin, require_operator, require_viewer

from .forms import TargetForm
from .models import Target


@require_viewer
def target_list(request):
    qs = Target.objects.all().order_by("root_domain")
    status = request.GET.get("status", "")
    if status:
        qs = qs.filter(status=status)
    q = request.GET.get("q", "")
    if q:
        qs = qs.filter(root_domain__icontains=q)
    return render(request, "targets/list.html", {"targets": qs, "status": status, "q": q})


@require_viewer
def target_detail(request, pk):
    from datetime import timedelta

    from django.utils import timezone

    from apps.jobs.models import JSAnalysisJob, ScanJob

    t = get_object_or_404(Target, pk=pk)
    # pipeline visibility: latest job per stage + running counts
    pipeline_stages = ["subdomain_enum", "dns", "ports", "http", "urls", "nuclei", "reconcile"]
    pipeline = []
    for stage in pipeline_stages:
        latest = t.jobs.filter(job_type=stage).order_by("-created_at").first()
        running = t.jobs.filter(job_type=stage, status__in=["QUEUED", "RUNNING"]).count()
        pipeline.append({"stage": stage, "status": latest.status if latest else "IDLE",
                         "running": running, "updated": latest.created_at if latest else None})
    js_running = JSAnalysisJob.objects.filter(target=t, status__in=["QUEUED", "RUNNING"]).count()
    pipeline.append({"stage": "js_analysis", "status": f"{js_running} RUNNING" if js_running else "IDLE",
                     "running": js_running, "updated": None})
    last_change = t.events.order_by("-created_at").first()
    ctx = {
        "target": t,
        "overview": {
            "subdomains": t.subdomains.filter(is_active=True).count(),
            "ips": t.ips.filter(is_active=True).count(),
            "ports": t.ports.filter(state="open").count(),
            "http": t.http_services.count(),
            "urls": t.urls.count(),
            "apis": t.api_endpoints.count(),
            "js": t.js_assets.count(),
            "techs": t.technologies.count(),
            "cves": t.cves.exclude(status="not_affected").count(),
            "findings": t.findings.exclude(status="RESOLVED").exclude(status="FALSE_POSITIVE").count(),
            "running_jobs": t.jobs.filter(status__in=["QUEUED", "RUNNING"]).count(),
            "last_change": last_change.created_at if last_change else None,
        },
        "pipeline": pipeline,
        "new_24h": t.events.filter(created_at__gte=timezone.now() - timedelta(hours=24)).count(),
        "target": t,
        "subdomains": t.subdomains.filter(is_active=True).order_by("hostname")[:50],
        "subdomain_count": t.subdomains.filter(is_active=True).count(),
        "ports": t.ports.filter(state="open").order_by("ip", "port")[:50],
        "http": t.http_services.order_by("-last_seen")[:20],
        "urls": t.urls.order_by("-last_seen")[:20],
        "apis": t.api_endpoints.order_by("-last_seen")[:20],
        "js": t.js_assets.order_by("-last_seen")[:20],
        "techs": t.technologies.order_by("product")[:30],
        "cves": t.cves.order_by("-first_seen")[:20],
        "findings": t.findings.order_by("-first_seen")[:20],
        "events": t.events.order_by("-created_at")[:30],
        "jobs": t.jobs.order_by("-created_at")[:20],
        "rules": t.scope_rules.all(),
    }
    return render(request, "targets/detail.html", ctx)


@require_viewer
def target_changes(request, target_id):
    from apps.events.views import changes as changes_view

    return changes_view(request, target_id=target_id)


@require_operator
def target_create(request):
    if request.method == "POST":
        form = TargetForm(request.POST)
        if form.is_valid():
            t = form.save()
            audit(request, "target.created", t, new=t.root_domain)
            from apps.jobs.tasks import baseline_target

            baseline_target.delay(t.id)
            return redirect("target-detail", pk=t.pk)
    else:
        form = TargetForm()
    return render(request, "targets/form.html", {"form": form, "title": "Add target"})


@require_operator
def target_edit(request, pk):
    t = get_object_or_404(Target, pk=pk)
    old = t.status
    if request.method == "POST":
        form = TargetForm(request.POST, instance=t)
        if form.is_valid():
            form.save()
            audit(request, "target.edited", t, old=old, new=t.status)
            return redirect("target-detail", pk=t.pk)
    else:
        form = TargetForm(instance=t)
    return render(request, "targets/form.html", {"form": form, "title": f"Edit {t.root_domain}"})


@require_operator
@require_POST
def target_pause(request, pk):
    t = get_object_or_404(Target, pk=pk)
    t.status = Target.STATUS_PAUSED
    t.save(update_fields=["status"])
    t.jobs.filter(status__in=["QUEUED", "RUNNING"]).update(status="PAUSED")
    audit(request, "target.paused", t)
    return redirect("target-detail", pk=pk)


@require_operator
@require_POST
def target_resume(request, pk):
    t = get_object_or_404(Target, pk=pk)
    t.status = Target.STATUS_ACTIVE
    t.save(update_fields=["status"])
    t.jobs.filter(status="PAUSED").update(status="QUEUED")
    audit(request, "target.resumed", t)
    return redirect("target-detail", pk=pk)


@require_admin
@require_POST
def target_delete(request, pk):
    t = get_object_or_404(Target, pk=pk)
    audit(request, "target.deleted", t, old=t.root_domain)
    t.delete()
    return redirect("target-list")


@require_operator
@require_POST
def target_scan(request, pk):
    t = get_object_or_404(Target, pk=pk)
    audit(request, "job.started", t, new="baseline" if t.baseline_status != "BASELINE_COMPLETE" else "scan")
    from apps.jobs import tasks as jt

    if t.baseline_status != "BASELINE_COMPLETE":
        jt.baseline_target.delay(t.id)
    else:
        jt.discover_subdomains.delay(t.id)
        jt.resolve_dns.delay(t.id)
    return redirect("target-detail", pk=pk)
