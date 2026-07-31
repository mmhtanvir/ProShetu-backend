from django.urls import path
from . import views

urlpatterns = [
    path("coord/<str:geohash>", views.get_deltas, name="get-deltas"),
    path("coord/<str:geohash>/publish", views.post_delta, name="post-delta"),
]
