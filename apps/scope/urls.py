from django.urls import path

from . import views

urlpatterns = [
    path("", views.scope_index, name="scope-index"),
    path("add/", views.scope_add, name="scope-add"),
    path("<int:pk>/delete/", views.scope_delete, name="scope-delete"),
]
