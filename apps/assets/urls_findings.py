from django.urls import path

from . import views

urlpatterns = [path("", views.finding_list, name="finding-list")]
