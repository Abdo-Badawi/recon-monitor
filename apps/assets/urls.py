from django.urls import path

from . import views

urlpatterns = [
    path("", views.asset_index, name="asset-list"),
    path("<int:pk>/", views.asset_detail, name="asset-detail"),
    path("ips/", views.ip_list, name="ip-list"),
]
