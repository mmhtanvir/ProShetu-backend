from django.urls import path
from . import views

urlpatterns = [
    path("sms/request", views.request_code, name="sms-request"),
    path("sms/verify", views.verify_code, name="sms-verify"),
    path("sms/lookup", views.lookup_by_phone, name="sms-lookup"),
]
