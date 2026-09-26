from django.urls import path

from . import views

urlpatterns = [path("", views.subdomain_list, name="subdomain-list")]
