from django.urls import path

from . import views

urlpatterns = [path("", views.port_list, name="port-list")]
