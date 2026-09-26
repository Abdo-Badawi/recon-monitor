from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.shortcuts import render

from apps.assets.models import (CVE, HTTPService, IPAddress, JavaScriptAsset, Port,
                                SecurityFinding, Subdomain)
from apps.events.models import Event
from apps.jobs.models import ScanJob
from apps.targets.models import Target


@login_required
def dashboard(request):
    sev_filter = request.GET.get("severity", "")
    events = Event.objects.select_related("target").order_by("-created_at")[:30]
    jobs = ScanJob.objects.select_related("target").order_by("-created_at")[:10]
    ctx = {
        "counts": {
            "targets": Target.objects.count(),
            "subdomains": Subdomain.objects.filter(is_active=True).count(),
            "ips": IPAddress.objects.filter(is_active=True).count(),
            "ports": Port.objects.filter(state="open").count(),
            "http": HTTPService.objects.count(),
            "js": JavaScriptAsset.objects.count(),
            "cves": CVE.objects.exclude(status="not_affected").count(),
            "findings": SecurityFinding.objects.exclude(status="RESOLVED").exclude(status="FALSE_POSITIVE").count(),
        },
        "events": events,
        "jobs": jobs,
        "targets": Target.objects.all()[:20],
        "findings_by_sev": list(SecurityFinding.objects.values("severity").annotate(n=Count("id")).order_by("severity")),
        "job_counts": {s: ScanJob.objects.filter(status=s).count() for s, _ in ScanJob.STATUS_CHOICES},
    }
    return render(request, "dashboard/index.html", ctx)
