from django.urls import path

from . import views

urlpatterns = [
    path("", views.monitoring_index, name="monitoring-index"),
    path("workers/", views.workers, name="workers"),
    path("exports/", views.export_history, name="export-history"),
    path("exports/<int:pk>/download/", views.export_download, name="export-download"),
    path("targets/<int:target_id>/exports/", views.export_index, name="export-index"),
    path("targets/<int:target_id>/exports/create/", views.export_create, name="export-create"),
]
