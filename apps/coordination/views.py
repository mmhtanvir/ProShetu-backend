from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, throttle_classes
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from drf_spectacular.utils import extend_schema, OpenApiParameter, inline_serializer
from drf_spectacular.types import OpenApiTypes
from rest_framework import serializers as drf_serializers

from apps.common.openapi import AUTH_HEADERS
from .models import CoordDelta
from .serializers import CoordDeltaIngestSerializer, CoordDeltaOutSerializer


class CoordThrottle(ScopedRateThrottle):
    scope = "coord"


@extend_schema(tags=["coordination"], summary="Publish an encrypted delta to a shard",
    parameters=AUTH_HEADERS,
    request=inline_serializer("CoordPublish", {
        "ttl_seconds": drf_serializers.IntegerField(),
        "ciphertext": drf_serializers.CharField(help_text="base64")}),
    responses=inline_serializer("CoordPublished", {"delta_id": drf_serializers.CharField()}))
@api_view(["POST"])
@throttle_classes([CoordThrottle])
def post_delta(request, geohash):
    """Authenticated: publish an encrypted coordination delta to a shard."""
    payload = dict(request.data)
    payload["geohash"] = geohash
    ser = CoordDeltaIngestSerializer(data=payload)
    ser.is_valid(raise_exception=True)
    v = ser.validated_data
    CoordDelta.objects.get_or_create(
        delta_id=v["delta_id"],
        defaults={
            "geohash": v["geohash"],
            "ciphertext": v["_raw"],
            "expires_at": v["expires_at"],
        },
    )
    return Response({"delta_id": v["delta_id"]}, status=status.HTTP_201_CREATED)


@extend_schema(tags=["coordination"], summary="Fetch unexpired deltas for a shard",
    parameters=AUTH_HEADERS + [OpenApiParameter("since", OpenApiTypes.DATETIME,
        OpenApiParameter.QUERY, required=False)],
    responses=inline_serializer("CoordList", {"deltas": CoordDeltaOutSerializer(many=True)}))
@api_view(["GET"])
@throttle_classes([CoordThrottle])
def get_deltas(request, geohash):
    """Authenticated: fetch unexpired deltas for a shard, optionally since a
    timestamp. Returns ciphertext only; the client decrypts + merges CRDTs."""
    shard = geohash[:5].lower()
    qs = CoordDelta.objects.filter(geohash=shard, expires_at__gt=timezone.now())
    since = request.query_params.get("since")
    if since:
        qs = qs.filter(created_at__gt=since)
    qs = qs.order_by("created_at")[:1000]
    return Response({"deltas": CoordDeltaOutSerializer(qs, many=True).data})
