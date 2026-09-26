from django.urls import path

from . import views

urlpatterns = [path("", views.http_list, name="http-list")]
