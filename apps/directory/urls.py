from django.urls import path
from . import views

urlpatterns = [
    path("challenge", views.challenge, name="challenge"),
    path("register", views.register, name="register"),
    path("recover", views.recover, name="recover"),
    path("prekeys", views.upload_prekeys, name="upload-prekeys"),
    path("fcm/token", views.update_fcm_token, name="fcm-token"),
    path("prekeys/<uuid:mailbox_id>", views.fetch_prekeys, name="fetch-prekeys"),
    path("backup", views.upload_backup, name="upload-backup"),
    path("backup/fetch", views.fetch_backup, name="fetch-backup"),
]
