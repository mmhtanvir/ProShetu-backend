from django.db import transaction
from django.utils import timezone
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
from .models import Identity, IdentityBackup, PreKeyBundle
from .serializers import (
    RegisterSerializer, RecoverSerializer, IdentityPublicSerializer,
    FcmTokenSerializer, PreKeyUploadSerializer, PreKeyBundleSerializer,
    BackupUploadSerializer, BackupFetchSerializer, IdentityBackupSerializer,
)


class ChallengeThrottle(ScopedRateThrottle):
    scope = "challenge"


class RegisterThrottle(ScopedRateThrottle):
    scope = "register"


class RecoverThrottle(ScopedRateThrottle):
    scope = "recover"


class FcmThrottle(ScopedRateThrottle):
    scope = "fcm"


class BackupThrottle(ScopedRateThrottle):
    scope = "backup"


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
        if rt is None or not rt.is_valid() or rt.purpose != "signup":
            # The purpose check must come before any consuming branch
            # below: a recovery-purpose token would otherwise fall
            # through to the "already registered" 409 (its phone IS
            # already registered) and get burned there, silently
            # breaking /v1/recover for a client that hit the wrong
            # endpoint rather than getting a clear rejection here.
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
    tags=["directory"], summary="Recover an account with a new identity",
    request=RecoverSerializer, responses=IdentityPublicSerializer,
)
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@throttle_classes([RecoverThrottle])
def recover(request):
    """Mint a fresh directory identity for an already-registered phone
    number, replacing the one it was previously bound to.

    Requires a `registration_token` issued for purpose="recovery" (see
    apps.smsverify) — this is deliberately a separate token namespace
    from /v1/register's, so a signup token can never be redeemed here
    and vice versa. The old Identity/PreKeyBundle rows for this phone
    are left as-is (nothing references them by phone, and nothing else
    FKs to Identity.mailbox_id) — same "ages out, never explicitly
    forgotten" philosophy as local device-key destruction.
    """
    from django.conf import settings as dj_settings
    if not dj_settings.SMS["REQUIRE_SMS_VERIFICATION"]:
        return Response(
            {"detail": "account recovery is unavailable on this deployment"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    from apps.smsverify.models import PhoneDirectoryEntry, RegisteredNumber, RegistrationToken

    ser = RecoverSerializer(data=request.data)
    ser.is_valid(raise_exception=True)
    validated = ser.validated_data

    tok = validated["registration_token"]
    rt = RegistrationToken.objects.filter(token=tok).first()
    if rt is None or not rt.is_valid() or rt.purpose != "recovery":
        return Response({"detail": "valid recovery registration_token required"},
                        status=status.HTTP_403_FORBIDDEN)
    rt.consumed = True
    rt.save(update_fields=["consumed"])

    msisdn_hash = rt.msisdn_hash
    if not msisdn_hash or not RegisteredNumber.objects.filter(
        msisdn_hash=msisdn_hash
    ).exists():
        return Response({"detail": "no account registered with this number"},
                        status=status.HTTP_404_NOT_FOUND)

    identity, _ = Identity.objects.get_or_create(
        ed25519_pub=validated["ed25519_pub"],
        defaults={"x25519_pub": validated["x25519_pub"]},
    )

    old_entry = PhoneDirectoryEntry.objects.filter(msisdn_hash=msisdn_hash).first()
    display_name = validated.get("display_name", "").strip() or (
        old_entry.display_name if old_entry else ""
    )
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
    tags=["directory"], summary="Register/update this device's FCM token",
    parameters=AUTH_HEADERS, request=FcmTokenSerializer, responses={204: None},
)
@api_view(["POST"])
@throttle_classes([FcmThrottle])
def update_fcm_token(request):
    """Authenticated: register/update this identity's FCM registration
    token, used as apps.common.fcm's fallback wake-up path when
    push_to_mailbox() has no live WebSocket to deliver to.
    """
    ser = FcmTokenSerializer(data=request.data)
    ser.is_valid(raise_exception=True)
    identity = Identity.objects.filter(
        ed25519_pub=request.user.ed25519_pub
    ).first()
    if identity is None:
        return Response({"detail": "register first"},
                        status=status.HTTP_404_NOT_FOUND)
    Identity.objects.filter(mailbox_id=identity.mailbox_id).update(
        fcm_token=ser.validated_data["fcm_token"],
        fcm_token_updated_at=timezone.now(),
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


@extend_schema(
    tags=["directory"], summary="Upload/replace this identity's encrypted key backup",
    parameters=AUTH_HEADERS, request=BackupUploadSerializer, responses={204: None},
)
@api_view(["POST"])
@throttle_classes([BackupThrottle])
def upload_backup(request):
    """Authenticated: store/replace this identity's encrypted backup
    blob, keyed by its phone number (see IdentityBackup). Requires the
    identity to have gone through SMS-verified registration — no
    phone, no msisdn_hash to key the backup by, so recovery-by-
    Encryption-ID has nothing to look it up against later.
    """
    ser = BackupUploadSerializer(data=request.data)
    ser.is_valid(raise_exception=True)

    from apps.smsverify.models import PhoneDirectoryEntry

    identity = Identity.objects.filter(
        ed25519_pub=request.user.ed25519_pub
    ).first()
    if identity is None:
        return Response({"detail": "register first"},
                        status=status.HTTP_404_NOT_FOUND)
    entry = PhoneDirectoryEntry.objects.filter(
        mailbox_id=str(identity.mailbox_id)
    ).first()
    if entry is None:
        return Response(
            {"detail": "backup requires SMS-verified registration with a phone number"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    IdentityBackup.objects.update_or_create(
        msisdn_hash=entry.msisdn_hash,
        defaults={"encrypted_bundle": ser.validated_data["encrypted_bundle"]},
    )
    return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema(
    tags=["directory"], summary="Fetch this phone number's encrypted key backup",
    request=BackupFetchSerializer,
    responses=inline_serializer("BackupFetchResult", {
        "encrypted_bundle": drf_serializers.CharField(),
        "updated_at": drf_serializers.DateTimeField(),
        "mailbox_id": drf_serializers.CharField(),
    }),
)
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@throttle_classes([BackupThrottle])
def fetch_backup(request):
    """Unauthenticated by identity (a fresh device has none yet) but
    gated on proof of phone ownership via a recovery-purpose
    registration_token — the same SMS-verification /v1/recover uses.
    Unlike /v1/recover, this never mints or replaces an Identity; it
    only returns whatever encrypted blob (if any) this phone number
    previously uploaded via /v1/backup, for the client to decrypt
    locally with its Encryption ID.
    """
    from django.conf import settings as dj_settings
    if not dj_settings.SMS["REQUIRE_SMS_VERIFICATION"]:
        return Response(
            {"detail": "account recovery is unavailable on this deployment"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    from apps.smsverify.models import PhoneDirectoryEntry, RegistrationToken

    ser = BackupFetchSerializer(data=request.data)
    ser.is_valid(raise_exception=True)

    tok = ser.validated_data["registration_token"]
    rt = RegistrationToken.objects.filter(token=tok).first()
    if rt is None or not rt.is_valid() or rt.purpose != "recovery":
        return Response({"detail": "valid recovery registration_token required"},
                        status=status.HTTP_403_FORBIDDEN)
    rt.consumed = True
    rt.save(update_fields=["consumed"])

    backup = IdentityBackup.objects.filter(msisdn_hash=rt.msisdn_hash).first()
    if backup is None:
        return Response({"detail": "no backup found for this number"},
                        status=status.HTTP_404_NOT_FOUND)
    # The client needs its own mailbox_id back too (the encrypted
    # bundle only carries the Ed25519/X25519 seeds) — same
    # PhoneDirectoryEntry /v1/recover already relies on to resolve a
    # phone number to its current identity.
    entry = PhoneDirectoryEntry.objects.filter(msisdn_hash=rt.msisdn_hash).first()
    data = IdentityBackupSerializer(backup).data
    data["mailbox_id"] = entry.mailbox_id if entry else None
    return Response(data)
