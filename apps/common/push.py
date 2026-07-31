"""
Push helper — deliver a small notification to a mailbox's live WebSocket(s).

This is intentionally decoupled so calling/sync code can call push_to_mailbox()
unconditionally. If no channel layer is configured (or no socket is connected),
it is a safe no-op and the client falls back to polling. When Channels is
enabled (feature: websocket push), notifications fan out over the layer to the
consumer group for that mailbox.

Payloads pushed here are tiny "wake up and sync/poll" hints (event kinds, call
ids) — never plaintext content. The actual ciphertext is still fetched over the
authenticated REST endpoints.
"""
from typing import Any

try:
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync
except Exception:  # channels not installed / not configured
    get_channel_layer = None
    async_to_sync = None


def group_name(mailbox_id: str) -> str:
    # Channel-layer group names must be <100 chars and use a limited charset.
    return f"mb_{str(mailbox_id).replace('-', '')}"


def push_to_mailbox(mailbox_id: str, payload: dict[str, Any]) -> bool:
    """Return True if a push was dispatched to the layer, False if unavailable."""
    if get_channel_layer is None:
        return False
    layer = get_channel_layer()
    if layer is None:
        return False
    async_to_sync(layer.group_send)(
        group_name(mailbox_id),
        {"type": "notify", "payload": payload},
    )
    return True
