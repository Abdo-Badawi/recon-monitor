from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import render

from .models import AuditLog


@login_required
def audit_list(request):
    qs = AuditLog.objects.select_related("user").order_by("-created_at")
    page = Paginator(qs, 30).get_page(request.GET.get("page", 1))
    return render(request, "audit/list.html", {"page": page})
