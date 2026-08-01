from rest_framework import serializers

from apps.common.validators import validate_hex
from .models import Identity, PreKeyBundle


class RegisterSerializer(serializers.Serializer):
    ed25519_pub = serializers.CharField()
    x25519_pub = serializers.CharField()

    def validate_ed25519_pub(self, v):
        return validate_hex(v, 32)

    def validate_x25519_pub(self, v):
        return validate_hex(v, 32)

    def create(self, validated):
        identity, _ = Identity.objects.get_or_create(
            ed25519_pub=validated["ed25519_pub"],
            defaults={"x25519_pub": validated["x25519_pub"]},
        )
        return identity


class RecoverSerializer(serializers.Serializer):
    """Redeem a recovery-purpose registration token for a fresh
    identity bound to an already-registered phone number. See
    views.recover() — this never touches RegisteredNumber (same
    phone, already recorded); it only mints a new Identity and
    repoints PhoneDirectoryEntry at it.
    """
    registration_token = serializers.CharField()
    ed25519_pub = serializers.CharField()
    x25519_pub = serializers.CharField()
    display_name = serializers.CharField(required=False, allow_blank=True)

    def validate_ed25519_pub(self, v):
        return validate_hex(v, 32)

    def validate_x25519_pub(self, v):
        return validate_hex(v, 32)


class IdentityPublicSerializer(serializers.ModelSerializer):
    class Meta:
        model = Identity
        fields = ["mailbox_id", "ed25519_pub", "x25519_pub"]


class FcmTokenSerializer(serializers.Serializer):
    fcm_token = serializers.CharField(max_length=255)


class PreKeyUploadSerializer(serializers.Serializer):
    signed_prekey = serializers.CharField()
    signed_prekey_sig = serializers.CharField()
    one_time_prekeys = serializers.ListField(
        child=serializers.CharField(), allow_empty=True, max_length=200
    )

    def validate_signed_prekey(self, v):
        return validate_hex(v, 32)

    def validate_signed_prekey_sig(self, v):
        return validate_hex(v, 64)

    def validate_one_time_prekeys(self, v):
        for otk in v:
            validate_hex(otk, 32)
        return v


class PreKeyBundleSerializer(serializers.ModelSerializer):
    """What a caller fetching someone's bundle receives: the signed prekey and
    (at most) one popped one-time prekey."""
    one_time_prekey = serializers.SerializerMethodField()
    ed25519_pub = serializers.CharField(source="identity.ed25519_pub")
    x25519_pub = serializers.CharField(source="identity.x25519_pub")
    mailbox_id = serializers.UUIDField(source="identity.mailbox_id")

    class Meta:
        model = PreKeyBundle
        fields = [
            "mailbox_id", "ed25519_pub", "x25519_pub",
            "signed_prekey", "signed_prekey_sig", "one_time_prekey",
        ]

    def get_one_time_prekey(self, obj) -> str:
        # Popping happens in the view within a transaction; the view attaches
        # the taken OTK here to avoid double-pop.
        return self.context.get("one_time_prekey")
