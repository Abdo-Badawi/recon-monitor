from django.urls import path

from . import views

urlpatterns = [
    path("", views.job_list, name="job-list"),
    path("<int:pk>/", views.job_detail, name="job-detail"),
    path("<int:pk>/cancel/", views.job_cancel, name="job-cancel"),
    path("<int:pk>/retry/", views.job_retry, name="job-retry"),
]
