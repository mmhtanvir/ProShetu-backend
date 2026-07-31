from django.db import transaction
from rest_framework import status
from rest_framework.decorators import (
    api_view, authentication_classes, permission_classes, throttle_classes,
)
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample, inline_serializer
from drf_spectacular.types import OpenApiTypes
from rest_framework import serializers as drf_serializers

from apps.common.models import Challenge
from apps.common.openapi import AUTH_HEADERS
from apps.common.validators import validate_hex
from .models import Identity, PreKeyBundle
from .serializers import (
    RegisterSerializer, IdentityPublicSerializer,
    PreKeyUploadSerializer, PreKeyBundleSerializer,
)


class ChallengeThrottle(ScopedRateThrottle):
    scope = "challenge"


class RegisterThrottle(ScopedRateThrottle):
    scope = "register"


@extend_schema(
    tags=["directory"], summary="Issue a single-use auth nonce",
    parameters=[OpenApiParameter("pub", OpenApiTypes.STR, OpenApiParameter.QUERY,
        required=True, description="Ed25519 public key, hex (32 bytes).")],
    responses=inline_serializer("Challenge", {"nonce": drf_serializers.CharField()}),
)
@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
@throttle_classes([ChallengeThrottle])
def challenge(request):
    """Issue a single-use auth nonce for a claimed Ed25519 identity.

    GET /v1/challenge?pub=<ed25519_hex>  ->  {"nonce": "..."}
    Anyone may request a challenge; it is useless without the private key.
    """
    pub = request.query_params.get("pub", "")
    try:
        validate_hex(pub, 32)
    except Exception:
        return Response({"detail": "pub must be 32-byte hex"},
                        status=status.HTTP_400_BAD_REQUEST)
    ch = Challenge.issue(pub)
    return Response({"nonce": ch.nonce})


@extend_schema(
    tags=["directory"], summary="Create/return a directory identity",
    request=RegisterSerializer, responses=IdentityPublicSerializer,
    examples=[OpenApiExample("register", value={
        "ed25519_pub": "<64-hex>", "x25519_pub": "<64-hex>"})],
)
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@throttle_classes([RegisterThrottle])
def register(request):
    """Create (or idempotently return) a directory identity.

    Anti-abuse is rate-limit + (optionally, upstream) proof-of-work or
    SMS-assisted verification; we do not gate on identity here because crisis
    users must be able to onboard with no phone number.
    """
    # Optional SMS-verification gate (architecture §14). When the deployment
    # sets REQUIRE_SMS_VERIFICATION, a single-use registration token from the
    # isolated smsverify service is required. The sync core never sees this
    # link (Identity/PreKeyBundle gain no phone-derived field below) — but
    # unlike registration tokens themselves, the phone hash <-> mailbox_id
    # pairing IS now kept in apps.smsverify.PhoneDirectoryEntry, by product
    # decision, so a contact search (/v1/sms/lookup) can find this account.
    from django.conf import settings as dj_settings
    msisdn_hash = ""
    if dj_settings.SMS["REQUIRE_SMS_VERIFICATION"]:
        from apps.smsverify.models import RegisteredNumber, RegistrationToken
        tok = request.data.get("registration_token", "")
        rt = RegistrationToken.objects.filter(token=tok).first()
        if rt is None or not rt.is_valid():
            return Response({"detail": "valid registration_token required"},
                            status=status.HTTP_403_FORBIDDEN)
        msisdn_hash = rt.msisdn_hash
        # Re-check here (not just at /v1/sms/request): closes the race
        # where two verified tokens for the same number both reach this
        # point before either has been marked registered below.
        if msisdn_hash and RegisteredNumber.objects.filter(
            msisdn_hash=msisdn_hash
        ).exists():
            rt.consumed = True
            rt.save(update_fields=["consumed"])
            return Response({"detail": "This phone number is already registered"},
                            status=status.HTTP_409_CONFLICT)
        rt.consumed = True
        rt.save(update_fields=["consumed"])

    ser = RegisterSerializer(data=request.data)
    ser.is_valid(raise_exception=True)
    identity = ser.save()

    if msisdn_hash:
        RegisteredNumber.objects.get_or_create(msisdn_hash=msisdn_hash)
        display_name = str(request.data.get("display_name", "")).strip()
        if display_name:
            from apps.smsverify.models import PhoneDirectoryEntry
            PhoneDirectoryEntry.objects.update_or_create(
                msisdn_hash=msisdn_hash,
                defaults={
                    "mailbox_id": str(identity.mailbox_id),
                    "display_name": display_name,
                },
            )

    return Response(IdentityPublicSerializer(identity).data,
                    status=status.HTTP_201_CREATED)


@extend_schema(
    tags=["directory"], summary="Upload/replace this identity's prekey bundle",
    parameters=AUTH_HEADERS, request=PreKeyUploadSerializer, responses={204: None},
)
@api_view(["POST"])
def upload_prekeys(request):
    """Authenticated: upload/replace this identity's prekey bundle."""
    ser = PreKeyUploadSerializer(data=request.data)
    ser.is_valid(raise_exception=True)
    identity = Identity.objects.filter(
        ed25519_pub=request.user.ed25519_pub
    ).first()
    if identity is None:
        return Response({"detail": "register first"},
                        status=status.HTTP_404_NOT_FOUND)
    PreKeyBundle.objects.update_or_create(
        identity=identity, defaults=ser.validated_data
    )
    return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema(
    tags=["directory"], summary="Fetch a peer's prekey bundle (pops one OTK)",
    parameters=AUTH_HEADERS, responses=PreKeyBundleSerializer,
)
@api_view(["GET"])
def fetch_prekeys(request, mailbox_id):
    """Authenticated: fetch a peer's bundle to bootstrap an E2E session.

    Pops one one-time prekey atomically so it is never reused across callers.
    """
    with transaction.atomic():
        bundle = (
            PreKeyBundle.objects
            .select_for_update()
            .filter(identity__mailbox_id=mailbox_id)
            .first()
        )
        if bundle is None:
            return Response({"detail": "no bundle"},
                            status=status.HTTP_404_NOT_FOUND)
        otk = bundle.take_one_time_prekey()
    data = PreKeyBundleSerializer(bundle, context={"one_time_prekey": otk}).data
    return Response(data)
