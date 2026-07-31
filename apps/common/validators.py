"""Shared validation helpers used across apps."""
from django.conf import settings
from rest_framework import serializers


def snap_to_bucket(size: int) -> int:
    """Snap a declared payload size up to the nearest uniform size bucket.

    Uniform buckets (architecture §7.1) prevent the server from learning
    payload length beyond a coarse class. The client is expected to have
    already padded to a bucket; the server records only the bucket.
    """
    for b in settings.PLATFORM["SIZE_BUCKETS"]:
        if size <= b:
            return b
    raise serializers.ValidationError("Payload exceeds maximum size bucket")


def validate_ttl(priority: int, ttl_seconds: int) -> int:
    """Clamp a requested TTL to the ceiling for its priority class (§1.4)."""
    ceil = settings.PLATFORM["TTL_MAX"].get(priority)
    if ceil is None:
        raise serializers.ValidationError("Invalid priority class")
    return min(ttl_seconds, ceil)


def validate_hex(value: str, expected_len_bytes: int | None = None) -> str:
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise serializers.ValidationError("Field must be hex-encoded")
    if expected_len_bytes is not None and len(raw) != expected_len_bytes:
        raise serializers.ValidationError(
            f"Expected {expected_len_bytes} bytes, got {len(raw)}"
        )
    return value
