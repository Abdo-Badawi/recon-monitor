from django.urls import path

from .consumers import LiveConsumer

websocket_urlpatterns = [
    path("ws/events/", LiveConsumer.as_asgi()),
    path("ws/jobs/", LiveConsumer.as_asgi()),
    path("ws/targets/<int:target_id>/", LiveConsumer.as_asgi()),
]
