from django.urls import path

from . import views

urlpatterns = [path("", views.url_list, name="url-list")]
