from django.urls import path

from . import views

urlpatterns = [
    path("", views.event_list, name="event-list"),
    path("changes/", views.changes, name="changes"),
]
