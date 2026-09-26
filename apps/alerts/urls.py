from django.urls import path

from . import views

urlpatterns = [path("", views.alerts_index, name="alerts-index")]
