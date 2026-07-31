from django.urls import path
from apps.common.consumers import PushConsumer

websocket_urlpatterns = [
    path("ws/push", PushConsumer.as_asgi()),
]
