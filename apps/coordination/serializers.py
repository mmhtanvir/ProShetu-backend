import base64
import hashlib
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from rest_framework import serializers

from .models import CoordDelta


class CoordDeltaIngestSerializer(serializers.Serializer):
    geohash = serializers.CharField(max_length=12)
    ttl_seconds = serializers.IntegerField(min_value=1, max_value=7 * 24 * 3600)
    ciphertext = serializers.CharField()  # base64

    def validate_geohash(self, v):
        # Enforce coarse sharding: truncate to the platform precision so a
        # client cannot smuggle a precise location into the shard topic.
        return v[: settings.PLATFORM["COORD_GEOHASH_LEN"]].lower()

    def validate(self, attrs):
        try:
            raw = base64.b64decode(attrs["ciphertext"], validate=True)
        except Exception:
            raise serializers.ValidationError("ciphertext must be base64")
        attrs["_raw"] = raw
        attrs["delta_id"] = hashlib.blake2b(raw, digest_size=16).hexdigest()
        attrs["expires_at"] = timezone.now() + timedelta(seconds=attrs["ttl_seconds"])
        return attrs


class CoordDeltaOutSerializer(serializers.ModelSerializer):
    ciphertext = serializers.SerializerMethodField()

    class Meta:
        model = CoordDelta
        fields = ["delta_id", "geohash", "ciphertext", "created_at", "expires_at"]

    def get_ciphertext(self, obj):
        return base64.b64encode(bytes(obj.ciphertext)).decode()
