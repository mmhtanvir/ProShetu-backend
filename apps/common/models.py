import secrets
from django.db import models
from django.utils import timezone


class Challenge(models.Model):
    """
    A short-lived random nonce issued to a caller. The caller signs it with the
    Ed25519 private key matching the identity they claim; the signature proves
    control of that key without revealing it. Challenges are single-use and
    expire quickly (settings.PLATFORM['CHALLENGE_TTL']).

    This replaces passwords and cookie sessions entirely — there is no
    server-side secret tied to a user that could be stolen.
    """
    nonce = models.CharField(max_length=64, unique=True, db_index=True)
    # The identity the challenge was issued for, as a hex Ed25519 public key.
    ed25519_pub = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)
    consumed = models.BooleanField(default=False)

    @classmethod
    def issue(cls, ed25519_pub_hex: str) -> "Challenge":
        return cls.objects.create(
            nonce=secrets.token_hex(32), ed25519_pub=ed25519_pub_hex
        )

    def is_valid(self, ttl_seconds: int) -> bool:
        if self.consumed:
            return False
        age = (timezone.now() - self.created_at).total_seconds()
        return age <= ttl_seconds


class RateBucket(models.Model):
    """
    Coarse abuse-control counters. Keyed by an opaque bucket key (e.g. a
    truncated hash of an IP window, or a mailbox id) plus a time window. This
    is deliberately NOT a per-request audit log: it stores only aggregate
    counts, so it cannot be used to reconstruct who talked to whom or when.
    """
    bucket_key = models.CharField(max_length=128, db_index=True)
    window = models.CharField(max_length=32)  # e.g. "2026-07-29T14"
    count = models.PositiveIntegerField(default=0)

    class Meta:
        unique_together = ("bucket_key", "window")
