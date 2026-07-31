from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, throttle_classes
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from apps.directory.models import Identity
from drf_spectacular.utils import extend_schema, inline_serializer
from rest_framework import serializers as drf_serializers

from apps.common.openapi import AUTH_HEADERS
from apps.common.push import push_to_mailbox
from .models import CallSignal
from .serializers import CallSignalIngestSerializer, CallSignalOutSerializer


class CallThrottle(ScopedRateThrottle):
    scope = "call"


def _mailbox_for(pub: str):
    return Identity.objects.filter(ed25519_pub=pub).values_list(
        "mailbox_id", flat=True
    ).first()


@extend_schema(tags=["calling"], summary="Relay one sealed call signal",
    parameters=AUTH_HEADERS, request=CallSignalIngestSerializer,
    responses=inline_serializer("SignalStored", {"id": drf_serializers.IntegerField()}))
@api_view(["POST"])
@throttle_classes([CallThrottle])
def signal(request):
    """
    Relay one sealed call signal to a peer (both-online optimization, §4.1).

    The server stores it briefly and, if the recipient holds a live WebSocket,
    pushes it immediately for low ring latency. Media never touches this path.
    """
    ser = CallSignalIngestSerializer(data=request.data)
    ser.is_valid(raise_exception=True)
    v = ser.validated_data

    sig = CallSignal.objects.create(
        call_id=v["call_id"],
        recipient_mailbox=v["recipient_mailbox"],
        kind=v["kind"],
        seq=v["seq"],
        ciphertext=v["_raw"],
        expires_at=v["expires_at"],
    )
    # Best-effort instant delivery over WebSocket (feature: push). Falls back to
    # the callee's next /call/poll if no socket is connected.
    push_to_mailbox(str(v["recipient_mailbox"]), {
        "type": "call_signal",
        "call_id": sig.call_id,
        "kind": sig.kind,
        "seq": sig.seq,
    })
    return Response({"id": sig.id}, status=status.HTTP_201_CREATED)


@extend_schema(tags=["calling"], summary="Pull pending call signals for me",
    parameters=AUTH_HEADERS,
    responses=inline_serializer("SignalList", {
        "signals": CallSignalOutSerializer(many=True)}))
@api_view(["GET"])
@throttle_classes([CallThrottle])
def poll(request):
    """Pull undelivered call signals addressed to me, then mark them delivered.

    Used when the client has no live WebSocket. Signals are ephemeral, so the
    client should poll fast (or hold a socket) during an active/expected call.
    """
    mailbox = _mailbox_for(request.user.ed25519_pub)
    if mailbox is None:
        return Response({"detail": "register first"},
                        status=status.HTTP_404_NOT_FOUND)
    now = timezone.now()
    pending = list(
        CallSignal.objects.filter(
            recipient_mailbox=mailbox, delivered=False, expires_at__gt=now
        )[:200]
    )
    ids = [s.id for s in pending]
    CallSignal.objects.filter(id__in=ids).update(delivered=True)
    return Response({"signals": CallSignalOutSerializer(pending, many=True).data})
