from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import render

from apps.events.models import Alert


@login_required
def alerts_index(request):
    qs = Alert.objects.select_related("event", "event__target").order_by("-created_at")
    status = request.GET.get("status", "")
    if status:
        qs = qs.filter(status=status)
    sev = request.GET.get("severity", "")
    if sev:
        qs = qs.filter(event__severity=sev)
    page = Paginator(qs, 30).get_page(request.GET.get("page", 1))
    return render(request, "alerts/index.html",
                  {"page": page, "status": status, "severity": sev,
                   "statuses": [s for s, _ in Alert.STATUS_CHOICES]})
