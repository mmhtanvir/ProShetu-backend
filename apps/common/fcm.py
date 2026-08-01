"""
FCM push helper — deliver a wake-up hint to a device that has no live
WebSocket connected (see apps/common/push.py, whose push_to_mailbox()
covers the live-socket case; this module is the fallback for when it
returns False).

Lazily imports firebase-admin and only initializes it if
settings.FCM["CREDENTIALS_PATH"] is set, mirroring apps/smsverify's
"console sender by default, real gateway only when configured"
pattern — a deployment that never sets FCM_CREDENTIALS_PATH doesn't
need firebase-admin importable at all, and every function here is a
safe no-op (returns False) rather than raising.

Payloads are data-only (no FCM "notification" block) — never
plaintext content, same "tiny wake up and sync/poll hint" contract
push_to_mailbox() documents. The client (NotificationService) stays
the single place that decides what's shown.
"""
import logging
from typing import Any

from django.conf import settings

log = logging.getLogger("fcm")

try:
    import firebase_admin
    from firebase_admin import credentials, messaging
except Exception:  # firebase-admin not installed
    firebase_admin = None
    messaging = None


def _ensure_initialized() -> bool:
    """Returns True if the Firebase app is ready to send with."""
    if firebase_admin is None:
        return False
    path = settings.FCM.get("CREDENTIALS_PATH", "")
    if not path:
        return False
    try:
        firebase_admin.get_app()
    except ValueError:
        firebase_admin.initialize_app(credentials.Certificate(path))
    return True


def send_data_message(
    fcm_token: str, data: dict[str, Any], *, priority: str = "high"
) -> bool:
    """Send a data-only message. Returns True if FCM accepted it for
    delivery — False for "can't/didn't send" (no token, FCM disabled,
    or a send error), never raises. Callers should treat False the
    same as push_to_mailbox() returning False: the client will pick
    this up on its next poll instead.
    """
    if not fcm_token or not _ensure_initialized():
        return False
    apns_priority = "10" if priority == "high" else "5"
    message = messaging.Message(
        token=fcm_token,
        data={str(k): str(v) for k, v in data.items()},
        android=messaging.AndroidConfig(priority=priority),
        apns=messaging.APNSConfig(
            headers={"apns-priority": apns_priority},
            payload=messaging.APNSPayload(
                aps=messaging.Aps(content_available=True)
            ),
        ),
    )
    try:
        messaging.send(message)
        return True
    except Exception:
        log.exception("FCM send failed")
        return False


def notify_message(fcm_token: str, event_id: str, priority: int) -> bool:
    return send_data_message(
        fcm_token, {"type": "event", "event_id": event_id, "priority": priority}
    )


def notify_call(fcm_token: str, call_id: str, kind: str) -> bool:
    return send_data_message(
        fcm_token, {"type": "call_signal", "call_id": call_id, "kind": kind}
    )
