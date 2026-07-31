from django.db import models


class CallSignal(models.Model):
    """
    An ephemeral, end-to-end-encrypted CALL SIGNAL relayed for the both-online
    case (architecture §4.1 signalling).

    IMPORTANT SCOPE — what the backend does and does NOT do for calls:
      • DOES relay small, sealed signalling blobs (ring/offer/answer/hangup/
        candidate) between two peers who both currently have internet but are
        not on the same local mesh. This is purely an optimization; the mesh
        control plane does the same thing peer-to-peer when devices are near.
      • Does NOT carry or see voice media. Media is peer-to-peer over the best
        available transport (Wi-Fi/BLE), encrypted with libsodium secretstream.
        There is no WebRTC and no SDP here.
      • Does NOT see call keys or the SAS. The signalling `ciphertext` is E2E
        encrypted to the recipient (sealed sender). The server only knows a
        call_id (random), a recipient mailbox, and a coarse `kind`.

    Signals are EPHEMERAL: unlike store-and-forward Events (hours/days TTL), a
    ring that is 30s stale is useless. Default TTL is seconds, and signals are
    deleted on delivery. Low-latency delivery comes from the WebSocket push
    channel; polling is the fallback.
    """
    KIND_CHOICES = [
        ("offer", "offer"),        # invite: codecs, ephemeral X25519 pub, SAS commit
        ("answer", "answer"),      # accept: peer ephemeral pub, chosen transport
        ("candidate", "candidate"),# reachable IP:port hints for direct UDP (online)
        ("ringing", "ringing"),    # callee device is alerting the user
        ("hangup", "hangup"),      # end / cancel / decline
        ("busy", "busy"),          # callee already in a call
    ]

    call_id = models.CharField(max_length=64, db_index=True)  # random hex, client-chosen
    recipient_mailbox = models.UUIDField(db_index=True)
    kind = models.CharField(max_length=12, choices=KIND_CHOICES)
    ciphertext = models.BinaryField()            # sealed signalling payload
    seq = models.PositiveIntegerField(default=0) # ordering within a call
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)
    delivered = models.BooleanField(default=False)

    class Meta:
        indexes = [
            models.Index(fields=["recipient_mailbox", "delivered"]),
            models.Index(fields=["call_id", "seq"]),
        ]
        ordering = ["seq", "created_at"]
