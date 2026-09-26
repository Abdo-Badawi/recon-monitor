from django.urls import path

from . import views

urlpatterns = [
    path("", views.js_list, name="js-list"),
    path("<int:pk>/diff/", views.js_diff, name="js-diff"),
    path("<int:pk>/scan/", views.js_scan_detail, name="js-scan"),
]
