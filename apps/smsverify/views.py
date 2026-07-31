from rest_framework import status
from rest_framework.decorators import (
    api_view, authentication_classes, permission_classes, throttle_classes,
)
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from drf_spectacular.utils import extend_schema, inline_serializer
from rest_framework import serializers as drf_serializers

from .models import PhoneVerification, RegistrationToken, hash_msisdn
from .sender import get_sender


class SmsThrottle(ScopedRateThrottle):
    scope = "sms"


@extend_schema(tags=["sms"], summary="Send a 6-digit code (stores only its hash)",
    request=inline_serializer("SmsRequest", {"msisdn": drf_serializers.CharField()}),
    responses=inline_serializer("SmsRequested", {"verification_id": drf_serializers.IntegerField()}))
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@throttle_classes([SmsThrottle])
def request_code(request):
    """Send a 6-digit code to a phone number. Stores only its hash."""
    msisdn = str(request.data.get("msisdn", "")).strip()
    if not msisdn or len(msisdn) < 6:
        return Response({"detail": "valid msisdn required"},
                        status=status.HTTP_400_BAD_REQUEST)
    rec, code = PhoneVerification.start(msisdn)
    get_sender().send_code(msisdn, code)
    # Return only the verification id; never echo the code.
    return Response({"verification_id": rec.id}, status=status.HTTP_201_CREATED)


@extend_schema(tags=["sms"], summary="Verify code -> single-use registration token",
    request=inline_serializer("SmsVerify", {
        "verification_id": drf_serializers.IntegerField(),
        "code": drf_serializers.CharField()}),
    responses=inline_serializer("SmsToken", {"registration_token": drf_serializers.CharField()}))
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@throttle_classes([SmsThrottle])
def verify_code(request):
    """Verify a code; on success issue a single-use registration token."""
    vid = request.data.get("verification_id")
    code = str(request.data.get("code", ""))
    try:
        rec = PhoneVerification.objects.get(id=vid)
    except PhoneVerification.DoesNotExist:
        return Response({"detail": "unknown verification"},
                        status=status.HTTP_404_NOT_FOUND)
    if not rec.try_code(code):
        return Response({"detail": "invalid or expired code"},
                        status=status.HTTP_400_BAD_REQUEST)
    token = RegistrationToken.issue()
    return Response({"registration_token": token.token})
