from django.urls import path

from . import views_settings

urlpatterns = [
    path("", views_settings.settings_index, name="settings-index"),
    path("system/", views_settings.system_status, name="settings-system"),
]
