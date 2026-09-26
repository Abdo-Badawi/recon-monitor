from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.core.permissions import audit, require_operator, require_viewer

from .models import JobLog, ScanJob


@require_viewer
def job_list(request):
    qs = ScanJob.objects.select_related("target").order_by("-created_at")
    status = request.GET.get("status", "")
    if status:
        qs = qs.filter(status=status)
    jtype = request.GET.get("type", "")
    if jtype:
        qs = qs.filter(job_type=jtype)
    page = Paginator(qs, 25).get_page(request.GET.get("page", 1))
    return render(request, "jobs/list.html", {"page": page, "status": status, "jtype": jtype})


@require_viewer
def job_detail(request, pk):
    job = get_object_or_404(ScanJob, pk=pk)
    logs = job.logs.order_by("created_at")[:500]
    return render(request, "jobs/detail.html", {"job": job, "logs": logs})


@require_operator
@require_POST
def job_cancel(request, pk):
    job = get_object_or_404(ScanJob, pk=pk)
    job.status = ScanJob.STATUS_CANCELLED
    job.save(update_fields=["status"])
    audit(request, "job.cancelled", job)
    return redirect("job-detail", pk=pk)


@require_operator
@require_POST
def job_retry(request, pk):
    from . import tasks as jt

    job = get_object_or_404(ScanJob, pk=pk)
    audit(request, "job.retried", job)
    mapping = {"subdomain_enum": jt.discover_subdomains, "dns": jt.resolve_dns, "ports": jt.scan_ports,
               "http": jt.probe_http, "urls": jt.discover_urls, "nuclei": jt.run_nuclei,
               "reconcile": jt.reconcile_target}
    task = mapping.get(job.job_type)
    if task:
        task.delay(job.target_id)
    return redirect("job-list")


@require_viewer
def log_list(request):
    qs = JobLog.objects.select_related("job", "job__target").order_by("-created_at")
    level = request.GET.get("level", "")
    if level:
        qs = qs.filter(level=level)
    tool = request.GET.get("tool", "")
    if tool:
        qs = qs.filter(tool=tool)
    page = Paginator(qs, 50).get_page(request.GET.get("page", 1))
    return render(request, "jobs/logs.html", {"page": page, "level": level, "tool": tool})
