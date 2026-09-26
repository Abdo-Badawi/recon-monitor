from django.urls import path

from . import views

urlpatterns = [path("", views.cve_list, name="cve-list")]
