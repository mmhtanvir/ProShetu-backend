"""
WebSocket push consumer (architecture §5: "long-poll/WebSocket when
connectivity is stable").

Purpose: when a client has stable internet, hold one socket so the server can
push tiny "wake up and sync/poll" hints the instant something arrives for it —
new events, and especially low-latency call signals (ringing). This is an
optimization over batch /sync polling; everything still works without it.

Auth: the SAME signature challenge/response as REST. The client first obtains a
challenge over REST, then connects with:
    /ws/push?identity=<ed25519_hex>&nonce=<nonce>&signature=<hex>
The consumer verifies the signature (PyNaCl) before joining any group. An
unauthenticated socket is closed immediately.

What crosses the socket: only tiny hints (event_id, call_id, kind) — never
plaintext content. The client still fetches ciphertext over authenticated REST.
"""
from urllib.parse import parse_qs

from channels.generic.websocket import AsyncJsonWebsocketConsumer
from channels.db import database_sync_to_async
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

from apps.common.push import group_name


@database_sync_to_async
def _verify_and_resolve(identity_hex: str, nonce: str, signature_hex: str):
    """Verify the challenge signature and return the caller's mailbox_id."""
    from django.conf import settings
    from apps.common.models import Challenge
    from apps.directory.models import Identity

    try:
        vk = VerifyKey(bytes.fromhex(identity_hex))
        sig = bytes.fromhex(signature_hex)
    except (ValueError, Exception):
        return None
    try:
        ch = Challenge.objects.get(nonce=nonce, ed25519_pub=identity_hex)
    except Challenge.DoesNotExist:
        return None
    if not ch.is_valid(settings.PLATFORM["CHALLENGE_TTL"]):
        return None
    try:
        vk.verify(ch.nonce.encode(), sig)
    except BadSignatureError:
        return None
    ch.consumed = True
    ch.save(update_fields=["consumed"])
    return Identity.objects.filter(ed25519_pub=identity_hex).values_list(
        "mailbox_id", flat=True
    ).first()


class PushConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        qs = parse_qs(self.scope.get("query_string", b"").decode())
        identity = (qs.get("identity") or [""])[0]
        nonce = (qs.get("nonce") or [""])[0]
        signature = (qs.get("signature") or [""])[0]
        if not (identity and nonce and signature):
            await self.close(code=4401)
            return
        mailbox = await _verify_and_resolve(identity, nonce, signature)
        if mailbox is None:
            await self.close(code=4403)
            return
        self.group = group_name(str(mailbox))
        await self.channel_layer.group_add(self.group, self.channel_name)
        await self.accept()
        await self.send_json({"type": "ready"})

    async def disconnect(self, code):
        if hasattr(self, "group"):
            await self.channel_layer.group_discard(self.group, self.channel_name)

    async def receive_json(self, content, **kwargs):
        # Client may send a keepalive ping; we don't accept commands over the
        # socket (all actions go through authenticated REST).
        if content.get("type") == "ping":
            await self.send_json({"type": "pong"})

    async def notify(self, event):
        """Handler for group_send messages from apps.common.push."""
        await self.send_json(event["payload"])
