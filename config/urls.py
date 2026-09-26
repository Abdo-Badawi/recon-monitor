from django.contrib import admin
from django.urls import include, path

from apps.core import views as core_views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", core_views.home, name="home"),
    path("health/", core_views.health, name="health"),
    path("search/", core_views.global_search, name="global-search"),
    path("accounts/", include("apps.accounts.urls")),
    path("dashboard/", include("apps.dashboard.urls")),
    path("targets/", include("apps.targets.urls")),
    path("scope/", include("apps.scope.urls")),
    path("assets/", include("apps.assets.urls")),
    path("subdomains/", include("apps.assets.urls_subdomains")),
    path("ports/", include("apps.assets.urls_ports")),
    path("http/", include("apps.assets.urls_http")),
    path("urls/", include("apps.assets.urls_urls")),
    path("apis/", include("apps.assets.urls_apis")),
    path("javascript/", include("apps.assets.urls_js")),
    path("technologies/", include("apps.assets.urls_tech")),
    path("cves/", include("apps.assets.urls_cves")),
    path("findings/", include("apps.assets.urls_findings")),
    path("events/", include("apps.events.urls")),
    path("changes/", include("apps.events.urls_changes")),
    path("jobs/", include("apps.jobs.urls")),
    path("logs/", include("apps.jobs.urls_logs")),
    path("monitoring/", include("apps.monitoring.urls")),
    path("alerts/", include("apps.alerts.urls")),
    path("audit/", include("apps.audit.urls")),
    path("settings/", include("apps.core.urls_settings")),
    path("api/", include("apps.core.api_urls")),
]
