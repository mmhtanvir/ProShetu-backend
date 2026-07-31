from django.urls import path
from . import views

urlpatterns = [
    path("call/signal", views.signal, name="call-signal"),
    path("call/poll", views.poll, name="call-poll"),
]
