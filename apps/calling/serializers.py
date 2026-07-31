import base64
from datetime import timedelta

from django.utils import timezone
from rest_framework import serializers

from .models import CallSignal

# Ring / signalling TTL ceiling. A stale call signal is worthless; keep it tiny.
SIGNAL_TTL_MAX = 90  # seconds


def _b64(v: str) -> bytes:
    try:
        return base64.b64decode(v, validate=True)
    except Exception:
        raise serializers.ValidationError("ciphertext must be base64")


class CallSignalIngestSerializer(serializers.Serializer):
    call_id = serializers.CharField(max_length=64)
    recipient_mailbox = serializers.UUIDField()
    kind = serializers.ChoiceField(choices=[k for k, _ in CallSignal.KIND_CHOICES])
    seq = serializers.IntegerField(min_value=0, default=0)
    ttl_seconds = serializers.IntegerField(min_value=1, max_value=SIGNAL_TTL_MAX,
                                            default=SIGNAL_TTL_MAX)
    ciphertext = serializers.CharField()  # base64, sealed to recipient

    def validate(self, attrs):
        attrs["_raw"] = _b64(attrs["ciphertext"])
        # Signalling blobs are small by nature; reject anything large so this
        # channel can't be abused to move bulk data around the store-and-forward
        # limits.
        if len(attrs["_raw"]) > 8192:
            raise serializers.ValidationError("signal payload too large")
        attrs["expires_at"] = timezone.now() + timedelta(seconds=attrs["ttl_seconds"])
        return attrs


class CallSignalOutSerializer(serializers.ModelSerializer):
    ciphertext = serializers.SerializerMethodField()

    class Meta:
        model = CallSignal
        fields = ["call_id", "kind", "seq", "ciphertext", "created_at", "expires_at"]

    def get_ciphertext(self, obj):
        return base64.b64encode(bytes(obj.ciphertext)).decode()
