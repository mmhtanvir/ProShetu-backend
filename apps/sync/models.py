from django.db import models


class Event(models.Model):
    """
    One end-to-end encrypted event awaiting delivery (architecture §5, §10).

    The server is a well-connected store-and-forward node. It stores CIPHERTEXT
    ONLY and the minimum routing metadata:

      event_id      : BLAKE2b-128 content hash (hex). Content-addressed, so
                      dedup is exact and the id is unforgeable. Also the loop/
                      replay guard shared with the mesh.
      recipient_mailbox : WHERE to deliver. "Sealed sender" (§5) means the
                      SENDER identity is inside the ciphertext, not stored here.
      priority      : 0..3 class (§1.4) governing TTL and delivery order.
      size_bucket   : coarse size class only (§7.1) — never the exact length.
      ciphertext    : opaque bytes. The server cannot read this. Ever.
      ttl_expires_at: hard expiry; server GCs at/after this.
      delivered     : set once the recipient has pulled it; enables GC.
    """
    event_id = models.CharField(max_length=64, primary_key=True)  # hex BLAKE2b-128
    recipient_mailbox = models.UUIDField(db_index=True)
    priority = models.PositiveSmallIntegerField(default=2)
    size_bucket = models.PositiveIntegerField()
    ciphertext = models.BinaryField()
    ttl_expires_at = models.DateTimeField(db_index=True)
    delivered = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["recipient_mailbox", "delivered"]),
            models.Index(fields=["priority", "created_at"]),
        ]


class BlobFragment(models.Model):
    """
    A fragment of a large payload (media, panic-vault, voice note) — §3.5, §7.3.
    Bulk payloads are split into independently-relayable fragments so a transfer
    survives partial loss (client adds FEC).

    The fragment CIPHERTEXT lives in object storage (S3-compatible, see
    apps/sync/storage.py); this row keeps only routing metadata plus the
    `object_key`. `uploaded` flips true once the bytes are actually in the store
    (clients may register a fragment row, then PUT the bytes — directly to S3 via
    a presigned URL in prod, or through the app in dev).
    """
    transfer_id = models.CharField(max_length=64, db_index=True)  # hex
    idx = models.PositiveIntegerField()
    count = models.PositiveIntegerField()
    recipient_mailbox = models.UUIDField(db_index=True)
    priority = models.PositiveSmallIntegerField(default=3)
    size_bucket = models.PositiveIntegerField()
    object_key = models.CharField(max_length=160)   # key in the blob store
    uploaded = models.BooleanField(default=False)
    ttl_expires_at = models.DateTimeField(db_index=True)
    delivered = models.BooleanField(default=False)

    class Meta:
        unique_together = ("transfer_id", "idx")
        indexes = [models.Index(fields=["recipient_mailbox", "delivered"])]


class Receipt(models.Model):
    """
    A delivery receipt (§3.4). Receipts are themselves events, but we also keep
    a lightweight row so the server can garbage-collect delivered events and so
    a sender can learn delivery on its next sync.

    The receipt references an event_id (a pseudorandom content hash). It reveals
    THAT some opaque message was delivered — not who sent it or who received it,
    because ids are unlinkable to directory identities. This is the documented
    metadata trade-off that lets relays reclaim storage.
    """
    event_id = models.CharField(max_length=64, db_index=True)
    ciphertext = models.BinaryField()   # E2E receipt payload for the sender
    recipient_mailbox = models.UUIDField(db_index=True)  # who to route receipt to (the original sender's mailbox)
    observed_at = models.DateTimeField(auto_now_add=True)
    delivered = models.BooleanField(default=False)
    ttl_expires_at = models.DateTimeField(db_index=True)
