from django.urls import path
from . import views

urlpatterns = [
    path("challenge", views.challenge, name="challenge"),
    path("register", views.register, name="register"),
    path("prekeys", views.upload_prekeys, name="upload-prekeys"),
    path("prekeys/<uuid:mailbox_id>", views.fetch_prekeys, name="fetch-prekeys"),
]
