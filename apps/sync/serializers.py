import base64
import hashlib

from rest_framework import serializers

from apps.common.validators import validate_ttl
from .models import Event, BlobFragment, Receipt


def _b64_to_bytes(v: str) -> bytes:
    try:
        return base64.b64decode(v, validate=True)
    except Exception:
        raise serializers.ValidationError("ciphertext must be base64")


def _content_id(ciphertext: bytes) -> str:
    """event_id = BLAKE2b-128 of the ciphertext (§3.4)."""
    return hashlib.blake2b(ciphertext, digest_size=16).hexdigest()


class EventIngestSerializer(serializers.Serializer):
    """One event a client is pushing into the fabric.

    The client MUST have already padded to a size bucket. The server verifies
    the declared event_id matches the ciphertext hash (content addressing),
    which makes ids unforgeable and dedup exact.
    """
    event_id = serializers.CharField()
    recipient_mailbox = serializers.UUIDField()
    priority = serializers.IntegerField(min_value=0, max_value=3)
    ttl_seconds = serializers.IntegerField(min_value=1)
    ciphertext = serializers.CharField()  # base64

    def validate(self, attrs):
        raw = _b64_to_bytes(attrs["ciphertext"])
        computed = _content_id(raw)
        if computed != attrs["event_id"]:
            raise serializers.ValidationError(
                "event_id does not match ciphertext hash"
            )
        attrs["_raw"] = raw
        attrs["ttl_seconds"] = validate_ttl(attrs["priority"], attrs["ttl_seconds"])
        return attrs


class BlobFragmentSerializer(serializers.Serializer):
    transfer_id = serializers.CharField()
    idx = serializers.IntegerField(min_value=0)
    count = serializers.IntegerField(min_value=1)
    recipient_mailbox = serializers.UUIDField()
    priority = serializers.IntegerField(min_value=0, max_value=3, default=3)
    ttl_seconds = serializers.IntegerField(min_value=1)
    ciphertext = serializers.CharField()  # base64

    def validate(self, attrs):
        attrs["_raw"] = _b64_to_bytes(attrs["ciphertext"])
        if attrs["idx"] >= attrs["count"]:
            raise serializers.ValidationError("idx out of range")
        attrs["ttl_seconds"] = validate_ttl(attrs["priority"], attrs["ttl_seconds"])
        return attrs


class ReceiptSerializer(serializers.Serializer):
    event_id = serializers.CharField()
    recipient_mailbox = serializers.UUIDField()  # original sender's mailbox
    ttl_seconds = serializers.IntegerField(min_value=1, default=48 * 3600)
    ciphertext = serializers.CharField()  # base64 E2E receipt payload

    def validate(self, attrs):
        attrs["_raw"] = _b64_to_bytes(attrs["ciphertext"])
        return attrs


class SyncRequestSerializer(serializers.Serializer):
    """The batch reconciliation payload (architecture §8, §11).

    carrying : events this client is offering to the fabric (it may be relaying
               others' traffic or sending its own).
    bloom    : {m, k, bits_hex} — filter of event_ids the client already holds.
    want     : explicit event_ids to repair Bloom false-positives.
    """
    carrying = EventIngestSerializer(many=True, required=False, default=list)
    receipts = ReceiptSerializer(many=True, required=False, default=list)
    bloom_m = serializers.IntegerField(min_value=8, required=False)
    bloom_k = serializers.IntegerField(min_value=1, max_value=32, required=False)
    bloom_bits = serializers.CharField(required=False, allow_blank=True, default="")
    want = serializers.ListField(
        child=serializers.CharField(), required=False, default=list
    )


class EventOutSerializer(serializers.ModelSerializer):
    ciphertext = serializers.SerializerMethodField()

    class Meta:
        model = Event
        fields = ["event_id", "priority", "size_bucket", "ciphertext",
                  "ttl_expires_at"]

    def get_ciphertext(self, obj) -> str:
        return base64.b64encode(bytes(obj.ciphertext)).decode()
