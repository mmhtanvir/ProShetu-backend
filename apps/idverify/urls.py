from django.urls import path
from . import views

urlpatterns = [
    path("idv/document", views.ingest_document, name="idv-document"),
    path("idv/verify", views.verify, name="idv-verify"),
    path("idv/status", views.verification_status, name="idv-status"),
]
