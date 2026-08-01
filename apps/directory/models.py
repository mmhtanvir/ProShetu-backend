import uuid
from django.db import models


class Identity(models.Model):
    """
    An opaque directory record (architecture §5, §10).

    The server knows a mailbox_id and public keys. It does NOT know a real
    name, phone number, or social graph. `mailbox_id` is the routing address
    other users address events to; it is deliberately decoupled from the
    Ed25519 identity so that "sealed sender" (§5) can hide senders.

    last_seen_bucket is a COARSE time bucket (hour granularity), never a
    precise timestamp or IP — enough to expire dead mailboxes, not enough to
    build a presence timeline.
    """
    mailbox_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ed25519_pub = models.CharField(max_length=64, unique=True, db_index=True)
    x25519_pub = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen_bucket = models.CharField(max_length=32, blank=True, default="")

    # Opaque FCM registration token for this mailbox's device, used by
    # apps.common.fcm as a fallback wake-up path when push_to_mailbox()
    # (apps.common.push, live WebSocket only) has no connected socket
    # to deliver to. Blank means this device hasn't registered one
    # (or FCM isn't configured) — callers must treat that as "can't
    # push, client will pick it up on next poll", never an error.
    fcm_token = models.CharField(max_length=255, blank=True, default="")
    fcm_token_updated_at = models.DateTimeField(null=True, blank=True)


class PreKeyBundle(models.Model):
    """
    X3DH-style prekey material (§5) so a user can start an end-to-end session
    with a party who is currently offline or never met. The server stores and
    hands these out but cannot use them — they are public keys plus a signed
    prekey and a pool of one-time prekeys, all opaque.
    """
    identity = models.OneToOneField(
        Identity, on_delete=models.CASCADE, related_name="prekeys",
        to_field="mailbox_id",
    )
    signed_prekey = models.CharField(max_length=64)       # X25519 pub, hex
    signed_prekey_sig = models.CharField(max_length=128)  # Ed25519 sig, hex
    one_time_prekeys = models.JSONField(default=list)     # list[hex X25519 pub]
    updated_at = models.DateTimeField(auto_now=True)

    def take_one_time_prekey(self):
        """Pop a one-time prekey (single use). Returns None if pool empty."""
        pool = list(self.one_time_prekeys or [])
        if not pool:
            return None
        otk = pool.pop(0)
        self.one_time_prekeys = pool
        self.save(update_fields=["one_time_prekeys", "updated_at"])
        return otk
