from django.urls import path

from . import views

urlpatterns = [path("", views.changes, name="changes")]
