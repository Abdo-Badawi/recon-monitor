from django.shortcuts import render

from apps.core.permissions import require_viewer
from apps.targets.models import Target

from .models import Event


def _since_filter(qs, since):
    from datetime import timedelta

    from django.utils import timezone

    now = timezone.now()
    mapping = {"1h": timedelta(hours=1), "6h": timedelta(hours=6), "24h": timedelta(hours=24),
               "7d": timedelta(days=7), "today": timedelta(hours=24)}
    if since in mapping:
        return qs.filter(created_at__gte=now - mapping[since])
    return qs


@require_viewer
def event_list(request):
    qs = Event.objects.select_related("target").order_by("-created_at")
    etype = request.GET.get("type", "")
    if etype:
        qs = qs.filter(event_type=etype)
    sev = request.GET.get("severity", "")
    if sev:
        qs = qs.filter(severity=sev)
    target_id = request.GET.get("target", "")
    if target_id:
        qs = qs.filter(target_id=target_id)
    from django.core.paginator import Paginator

    page = Paginator(qs, 30).get_page(request.GET.get("page", 1))
    return render(request, "events/list.html",
                  {"page": page, "etype": etype, "severity": sev, "target_id": target_id,
                   "targets": Target.objects.all(),
                   "event_types": sorted({e for e, _ in Event.EVENT_TYPES})})


@require_viewer
def changes(request, target_id=None):
    """Global or per-target What's New with time-range filters."""
    from django.core.paginator import Paginator

    qs = Event.objects.select_related("target").order_by("-created_at")
    if target_id:
        qs = qs.filter(target_id=target_id)
    else:
        tid = request.GET.get("target", "")
        if tid:
            qs = qs.filter(target_id=tid)
            target_id = tid
    since = request.GET.get("since", "24h")
    if since == "since_baseline" and target_id:
        try:
            t = Target.objects.get(pk=target_id)
            if t.baseline_completed_at:
                qs = qs.filter(created_at__gte=t.baseline_completed_at)
        except Target.DoesNotExist:
            pass
    else:
        qs = _since_filter(qs, since)
    etype = request.GET.get("type", "")
    if etype:
        qs = qs.filter(event_type=etype)
    page = Paginator(qs, 30).get_page(request.GET.get("page", 1))
    # summary counts by type
    from django.db.models import Count

    summary = list(qs.values("event_type").annotate(n=Count("id")).order_by("-n")[:20])
    ctx = {"page": page, "since": since, "etype": etype, "target_id": target_id or "",
           "targets": Target.objects.all(), "summary": summary,
           "event_types": sorted({e for e, _ in Event.EVENT_TYPES})}
    if target_id:
        ctx["target"] = Target.objects.filter(pk=target_id).first()
    return render(request, "events/changes.html", ctx)
