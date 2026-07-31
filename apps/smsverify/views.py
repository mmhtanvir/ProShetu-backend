from rest_framework import status
from rest_framework.decorators import (
    api_view, authentication_classes, permission_classes, throttle_classes,
)
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from drf_spectacular.utils import extend_schema, inline_serializer
from rest_framework import serializers as drf_serializers

from .models import (
    PhoneDirectoryEntry, PhoneVerification, RegisteredNumber,
    RegistrationToken, hash_msisdn,
)
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
    try:
        msisdn_hash = hash_msisdn(msisdn)
    except ValueError:
        return Response({"detail": "invalid phone number"},
                        status=status.HTTP_400_BAD_REQUEST)
    if RegisteredNumber.objects.filter(msisdn_hash=msisdn_hash).exists():
        return Response({"detail": "This phone number is already registered"},
                        status=status.HTTP_409_CONFLICT)
    rec, code = PhoneVerification.start(msisdn)
    if not get_sender().send_code(msisdn, code):
        # Delivery failed (e.g. Twilio rejected the number) — don't leave
        # the caller polling for a code that will never arrive, and don't
        # leave a live, never-deliverable PhoneVerification row behind.
        rec.delete()
        return Response({"detail": "Could not send the verification code"},
                        status=status.HTTP_502_BAD_GATEWAY)
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
    token = RegistrationToken.issue(msisdn_hash=rec.msisdn_hash)
    return Response({"registration_token": token.token})


@extend_schema(tags=["sms"],
    summary="Find a registered contact by phone number (PhoneDirectoryEntry)",
    request=inline_serializer("SmsLookup", {"msisdn": drf_serializers.CharField()}),
    responses=inline_serializer("SmsLookupResult", {
        "mailbox_id": drf_serializers.CharField(),
        "display_name": drf_serializers.CharField()}))
@api_view(["POST"])
@throttle_classes([SmsThrottle])
def lookup_by_phone(request):
    """Authenticated (default SignatureAuthentication — see this
    module's docstring: unlike request_code/verify_code above, this
    endpoint is deliberately NOT open to anonymous callers, since it's
    a search a signed-in user performs to add a contact, not part of
    the pre-identity signup flow) reverse lookup: does this phone
    number belong to a registered account? 404 if not found or the
    number never completed SMS-verified registration.
    """
    msisdn = str(request.data.get("msisdn", "")).strip()
    if not msisdn:
        return Response({"detail": "msisdn required"},
                        status=status.HTTP_400_BAD_REQUEST)
    try:
        msisdn_hash = hash_msisdn(msisdn)
    except ValueError:
        return Response({"detail": "invalid phone number"},
                        status=status.HTTP_400_BAD_REQUEST)
    entry = PhoneDirectoryEntry.objects.filter(
        msisdn_hash=msisdn_hash
    ).first()
    if entry is None:
        return Response({"detail": "no account found for this number"},
                        status=status.HTTP_404_NOT_FOUND)
    return Response({
        "mailbox_id": entry.mailbox_id,
        "display_name": entry.display_name,
    })
