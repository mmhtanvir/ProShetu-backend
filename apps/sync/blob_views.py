"""
Blob fragment transfer endpoints (architecture §5, §7.3).

Flow (prod, S3):
  1. POST /v1/blobs/{transfer}/{idx}/register  -> {object_key, upload_url?}
     Client PUTs ciphertext directly to `upload_url` (presigned S3), then:
  2. POST /v1/blobs/{transfer}/{idx}/complete   (marks uploaded=true)
  Recipient:
  3. GET  /v1/blobs/{transfer}                  -> manifest (which idx exist)
  4. GET  /v1/blobs/{transfer}/{idx}            -> {download_url} (presigned)

Flow (dev, local store): register returns no upload_url; client PUTs bytes to
  PUT /v1/blobs/{transfer}/{idx}  (proxied through the app); download returns
  the bytes inline. Same client code path, just no presign.

Everything here is opaque ciphertext. The server never decrypts a fragment.
"""
import base64
from datetime import timedelta

from django.conf import settings
from django.http import HttpResponse
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, throttle_classes
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from drf_spectacular.utils import extend_schema, OpenApiExample, inline_serializer, OpenApiTypes
from rest_framework import serializers as drf_serializers

from apps.common.openapi import AUTH_HEADERS
from apps.common.validators import snap_to_bucket, validate_ttl
from .models import BlobFragment
from .storage import get_store, object_key


class BlobThrottle(ScopedRateThrottle):
    scope = "sync"


@extend_schema(
    tags=["blobs"], summary="Register a fragment (returns presigned PUT on S3)",
    parameters=AUTH_HEADERS,
    request=inline_serializer("FragmentRegister", {
        "count": drf_serializers.IntegerField(),
        "recipient_mailbox": drf_serializers.UUIDField(),
        "size": drf_serializers.IntegerField(),
        "priority": drf_serializers.IntegerField(required=False),
        "ttl_seconds": drf_serializers.IntegerField(required=False),
    }),
    responses=inline_serializer("FragmentRegistered", {
        "object_key": drf_serializers.CharField(),
        "upload_url": drf_serializers.CharField(allow_null=True),
        "proxy_upload": drf_serializers.BooleanField()}),
)
@api_view(["POST"])
@throttle_classes([BlobThrottle])
def register_fragment(request, transfer_id, idx):
    """Register a fragment row and (on S3) return a presigned PUT URL."""
    idx = int(idx)
    try:
        count = int(request.data["count"])
        recipient = request.data["recipient_mailbox"]
        priority = int(request.data.get("priority", 3))
        declared_size = int(request.data["size"])
        ttl = validate_ttl(priority, int(request.data.get("ttl_seconds", 72 * 3600)))
    except (KeyError, ValueError):
        return Response({"detail": "count, recipient_mailbox, size required"},
                        status=status.HTTP_400_BAD_REQUEST)
    if idx >= count:
        return Response({"detail": "idx out of range"},
                        status=status.HTTP_400_BAD_REQUEST)

    key = object_key(transfer_id, idx)
    frag, _ = BlobFragment.objects.update_or_create(
        transfer_id=transfer_id, idx=idx,
        defaults={
            "count": count,
            "recipient_mailbox": recipient,
            "priority": priority,
            "size_bucket": snap_to_bucket(declared_size),
            "object_key": key,
            "ttl_expires_at": timezone.now() + timedelta(seconds=ttl),
        },
    )
    store = get_store()
    upload_url = store.presign_put(key) if store.supports_presign else None
    return Response({
        "object_key": key,
        "upload_url": upload_url,            # None in dev -> use PUT proxy below
        "proxy_upload": not store.supports_presign,
    }, status=status.HTTP_201_CREATED)


@extend_schema(
    tags=["blobs"], summary="Dev/local proxy upload of fragment bytes",
    parameters=AUTH_HEADERS,
    request={"application/octet-stream": {"type": "string", "format": "binary"}},
    responses={204: None},
)
@api_view(["PUT"])
@throttle_classes([BlobThrottle])
def upload_fragment(request, transfer_id, idx):
    """Dev/local proxy upload. In prod clients PUT straight to the presigned URL
    and skip this endpoint."""
    idx = int(idx)
    try:
        frag = BlobFragment.objects.get(transfer_id=transfer_id, idx=idx)
    except BlobFragment.DoesNotExist:
        return Response({"detail": "register the fragment first"},
                        status=status.HTTP_404_NOT_FOUND)
    body = request.body
    if len(body) > max(settings.PLATFORM["SIZE_BUCKETS"]):
        return Response({"detail": "fragment too large"},
                        status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
    get_store().put(frag.object_key, body)
    frag.uploaded = True
    frag.save(update_fields=["uploaded"])
    return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema(tags=["blobs"], summary="Mark a presigned upload complete (S3)",
    parameters=AUTH_HEADERS, request=None, responses={204: None})
@api_view(["POST"])
@throttle_classes([BlobThrottle])
def complete_fragment(request, transfer_id, idx):
    """Mark a presigned-uploaded fragment as present (prod path)."""
    updated = BlobFragment.objects.filter(
        transfer_id=transfer_id, idx=int(idx)
    ).update(uploaded=True)
    if not updated:
        return Response({"detail": "unknown fragment"},
                        status=status.HTTP_404_NOT_FOUND)
    return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema(tags=["blobs"], summary="Which fragments of a transfer exist",
    parameters=AUTH_HEADERS,
    responses=inline_serializer("Manifest", {
        "transfer_id": drf_serializers.CharField(),
        "count": drf_serializers.IntegerField(),
        "have": drf_serializers.ListField(child=drf_serializers.IntegerField()),
        "complete": drf_serializers.BooleanField()}))
@api_view(["GET"])
@throttle_classes([BlobThrottle])
def transfer_manifest(request, transfer_id):
    """Which fragments of a transfer are available, so a recipient knows what to
    pull and whether FEC can already reconstruct the payload."""
    frags = BlobFragment.objects.filter(
        transfer_id=transfer_id, uploaded=True, ttl_expires_at__gt=timezone.now()
    ).order_by("idx")
    if not frags:
        return Response({"detail": "no fragments"},
                        status=status.HTTP_404_NOT_FOUND)
    count = frags[0].count
    have = list(frags.values_list("idx", flat=True))
    return Response({
        "transfer_id": transfer_id,
        "count": count,
        "have": have,
        "complete": len(have) == count,
    })


@extend_schema(tags=["blobs"],
    summary="Download a fragment (presigned URL on S3, bytes on local)",
    parameters=AUTH_HEADERS, responses={200: OpenApiTypes.BINARY})
@api_view(["GET"])
@throttle_classes([BlobThrottle])
def download_fragment(request, transfer_id, idx):
    """Return a presigned GET URL (S3) or the raw ciphertext bytes (local)."""
    idx = int(idx)
    try:
        frag = BlobFragment.objects.get(
            transfer_id=transfer_id, idx=idx, uploaded=True
        )
    except BlobFragment.DoesNotExist:
        return Response({"detail": "not available"},
                        status=status.HTTP_404_NOT_FOUND)
    store = get_store()
    if store.supports_presign:
        return Response({"download_url": store.presign_get(frag.object_key)})
    data = store.get(frag.object_key)
    return HttpResponse(data, content_type="application/octet-stream")
