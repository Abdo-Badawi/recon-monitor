from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import JsonResponse
from django.shortcuts import redirect, render


def home(request):
    if request.user.is_authenticated:
        return redirect("dashboard")
    return redirect("login")


def health(request):
    from django.db import connection

    from services.tool_adapters.adapters import tool_health

    db_ok = True
    try:
        with connection.cursor() as c:
            c.execute("SELECT 1")
    except Exception:
        db_ok = False
    tools = tool_health()
    ok_tools = sum(1 for t in tools if t["status"] == "OK")
    payload = {"status": "ok" if db_ok else "degraded", "database": "ok" if db_ok else "error",
               "tools": {"ok": ok_tools, "total": len(tools), "detail": tools}}
    if request.headers.get("Accept", "").startswith("application/json"):
        return JsonResponse(payload)
    return render(request, "core/health.html", payload)


@login_required
def global_search(request):
    q = request.GET.get("q", "").strip()
    ctx = {"q": q, "results": []}
    if q:
        from apps.assets.models import (APIEndpoint, CVE, HTTPService, IPAddress, JavaScriptAsset,
                                         Port, SecurityFinding, Subdomain, Technology, URLAsset)
        from apps.events.models import Event

        results = []
        for label, qs, field in [
            ("Subdomain", Subdomain.objects.filter(hostname__icontains=q)[:10], "hostname"),
            ("IP", IPAddress.objects.filter(ip__icontains=q)[:10], "ip"),
            ("Port", Port.objects.filter(ip__icontains=q)[:10], "ip"),
            ("HTTP", HTTPService.objects.filter(url__icontains=q)[:10], "url"),
            ("URL", URLAsset.objects.filter(canonical_url__icontains=q)[:10], "canonical_url"),
            ("API", APIEndpoint.objects.filter(url__icontains=q)[:10], "url"),
            ("JS", JavaScriptAsset.objects.filter(js_url__icontains=q)[:10], "js_url"),
            ("Tech", Technology.objects.filter(product__icontains=q)[:10], "product"),
            ("CVE", CVE.objects.filter(cve_id__icontains=q)[:10], "cve_id"),
            ("Finding", SecurityFinding.objects.filter(title__icontains=q)[:10], "title"),
            ("Event", Event.objects.filter(asset_value__icontains=q)[:10], "asset_value"),
        ]:
            for obj in qs:
                results.append({"type": label, "value": getattr(obj, field, str(obj))[:150], "id": obj.pk})
        ctx["results"] = results
    if request.headers.get("Accept", "").startswith("application/json"):
        return JsonResponse({"q": q, "results": ctx["results"]})
    return render(request, "core/search.html", ctx)
