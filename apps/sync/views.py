import base64
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, throttle_classes
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from drf_spectacular.utils import extend_schema, OpenApiExample, inline_serializer
from rest_framework import serializers as drf_serializers

from apps.common import fcm
from apps.common.openapi import AUTH_HEADERS
from apps.common.validators import snap_to_bucket
from apps.directory.models import Identity
from apps.common.push import push_to_mailbox
from .bloom import BloomFilter
from .models import Event, BlobFragment, Receipt
from .serializers import (
    SyncRequestSerializer, EventOutSerializer,
)


class SyncThrottle(ScopedRateThrottle):
    scope = "sync"


def _mailbox_for(identity_pub: str):
    return Identity.objects.filter(ed25519_pub=identity_pub).values_list(
        "mailbox_id", flat=True
    ).first()


@extend_schema(
    tags=["sync"], summary="Reconcile: push carried events, pull yours",
    parameters=AUTH_HEADERS, request=SyncRequestSerializer,
    responses=inline_serializer("SyncResponse", {
        "accepted": drf_serializers.ListField(child=drf_serializers.CharField()),
        "deliver": EventOutSerializer(many=True),
        "receipts": drf_serializers.ListField(child=drf_serializers.DictField()),
        "want": drf_serializers.ListField(child=drf_serializers.CharField()),
    }),
    examples=[OpenApiExample("push one event", value={
        "carrying": [{"event_id": "<blake2b-128 hex of ciphertext>",
                       "recipient_mailbox": "<uuid>", "priority": 2,
                       "ttl_seconds": 3600, "ciphertext": "<base64>"}],
        "bloom_m": 4096, "bloom_k": 7, "bloom_bits": "<hex>", "want": []})],
)
@api_view(["POST"])
@throttle_classes([SyncThrottle])
def sync(request):
    """
    The one reconciliation endpoint. Runs the SAME protocol the mesh runs
    peer-to-peer (architecture §8), so the backend is "just a very
    well-connected peer".

    Request  (SyncRequestSerializer):
        carrying[]  events the client offers to the fabric
        fragments[] bulk blob fragments the client offers
        receipts[]  delivery receipts the client is relaying
        bloom_*     the client's filter of event_ids it already holds
        want[]      explicit ids to repair Bloom false positives

    Response:
        accepted[]  ids the server ingested (or already had)
        deliver[]   events addressed to THIS client it doesn't yet hold
        want[]      ids the server is missing but saw referenced (future use)
    """
    ser = SyncRequestSerializer(data=request.data)
    ser.is_valid(raise_exception=True)
    data = ser.validated_data

    caller_mailbox = _mailbox_for(request.user.ed25519_pub)
    if caller_mailbox is None:
        return Response({"detail": "register first"},
                        status=status.HTTP_404_NOT_FOUND)

    now = timezone.now()
    accepted = []

    # ---- Ingest carried events (store-and-forward). Content-addressed, so
    #      re-submitting the same event is a harmless no-op (dedup). ----------
    if len(data["carrying"]) > settings.PLATFORM["SYNC_MAX_EVENTS"]:
        return Response({"detail": "too many events in one sync"},
                        status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)

    with transaction.atomic():
        for e in data["carrying"]:
            raw = e["_raw"]
            obj, _created = Event.objects.get_or_create(
                event_id=e["event_id"],
                defaults={
                    "recipient_mailbox": e["recipient_mailbox"],
                    "priority": e["priority"],
                    "size_bucket": snap_to_bucket(len(raw)),
                    "ciphertext": raw,
                    "ttl_expires_at": now + timedelta(seconds=e["ttl_seconds"]),
                },
            )
            accepted.append(obj.event_id)
            if _created:
                delivered_live = push_to_mailbox(str(e["recipient_mailbox"]), {"type": "event", "event_id": obj.event_id, "priority": obj.priority})
                if not delivered_live:
                    token = Identity.objects.filter(
                        mailbox_id=e["recipient_mailbox"]
                    ).values_list("fcm_token", flat=True).first()
                    if token:
                        fcm.notify_message(token, obj.event_id, obj.priority)

        # NOTE: bulk blob fragments are NOT ingested here anymore. Large
        # ciphertext does not belong in the batch JSON body; it goes to object
        # storage via the dedicated /v1/blobs/* endpoints (apps/sync/blob_views).
        # /sync carries only the small event that references a transfer_id.

        for r in data["receipts"]:
            Receipt.objects.get_or_create(
                event_id=r["event_id"],
                recipient_mailbox=r["recipient_mailbox"],
                defaults={
                    "ciphertext": r["_raw"],
                    "ttl_expires_at": now + timedelta(seconds=r["ttl_seconds"]),
                },
            )
            # A receipt lets the server GC the delivered event (frees storage).
            Event.objects.filter(event_id=r["event_id"]).update(delivered=True)

    # ---- Build the deliver-set: events for THIS caller it doesn't hold ------
    bloom = None
    if data.get("bloom_m") and data.get("bloom_k"):
        try:
            bloom = BloomFilter.from_hex(
                data["bloom_m"], data["bloom_k"], data.get("bloom_bits", "")
            )
        except ValueError:
            return Response({"detail": "invalid bloom parameters"},
                            status=status.HTTP_400_BAD_REQUEST)

    want_set = set(data.get("want", []))

    pending = (
        Event.objects
        .filter(recipient_mailbox=caller_mailbox, delivered=False,
                ttl_expires_at__gt=now)
        .order_by("priority", "created_at")[:settings.PLATFORM["SYNC_MAX_EVENTS"]]
    )

    deliver = []
    for ev in pending:
        # Skip events the client already holds (Bloom), unless explicitly wanted.
        if bloom is not None and ev.event_id in bloom and ev.event_id not in want_set:
            continue
        deliver.append(ev)

    # Also deliver any receipts addressed to this caller (delivery confirmations
    # for messages THEY originally sent).
    receipts = (
        Receipt.objects
        .filter(recipient_mailbox=caller_mailbox, delivered=False,
                ttl_expires_at__gt=now)[:settings.PLATFORM["SYNC_MAX_EVENTS"]]
    )

    # Coarse presence: bump last_seen bucket (hour granularity only).
    Identity.objects.filter(mailbox_id=caller_mailbox).update(
        last_seen_bucket=now.strftime("%Y-%m-%dT%H")
    )

    resp = {
        "accepted": accepted,
        "deliver": EventOutSerializer(deliver, many=True).data,
        "receipts": [
            {"event_id": r.event_id,
             "ciphertext": base64.b64encode(bytes(r.ciphertext)).decode()}
            for r in receipts
        ],
        "want": [],
    }
    return Response(resp)


@extend_schema(
    tags=["sync"], summary="Confirm storage so the server can GC",
    parameters=AUTH_HEADERS,
    request=inline_serializer("AckRequest", {
        "event_ids": drf_serializers.ListField(child=drf_serializers.CharField()),
        "receipt_event_ids": drf_serializers.ListField(child=drf_serializers.CharField()),
    }),
    responses={204: None},
)
@api_view(["POST"])
@throttle_classes([SyncThrottle])
def ack(request):
    """Client confirms it has durably stored specific events / receipts so the
    server may mark them delivered and reclaim storage."""
    caller_mailbox = _mailbox_for(request.user.ed25519_pub)
    if caller_mailbox is None:
        return Response({"detail": "register first"},
                        status=status.HTTP_404_NOT_FOUND)
    event_ids = request.data.get("event_ids", [])
    receipt_ids = request.data.get("receipt_event_ids", [])
    Event.objects.filter(
        event_id__in=event_ids, recipient_mailbox=caller_mailbox
    ).update(delivered=True)
    Receipt.objects.filter(
        event_id__in=receipt_ids, recipient_mailbox=caller_mailbox
    ).update(delivered=True)
    return Response(status=status.HTTP_204_NO_CONTENT)
