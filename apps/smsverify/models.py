"""
SMS verification for registration anti-abuse (architecture §5, §14).

Design constraints from the threat model:
  • This is the ONLY component that touches a phone number, and it is kept
    isolated so the zero-knowledge sync core never sees one.
  • The raw MSISDN is NEVER stored. We store a keyed hash (HMAC-BLAKE2b with a
    server pepper) so the DB cannot be trivially reversed into a phone list,
    and so the same number maps to a stable hash for rate-limiting/one-account
    logic without being recoverable.
  • The verification code is stored only as a hash; a leaked table does not
    reveal live codes.
  • Success yields a short-lived, single-use registration TOKEN that
    /v1/register can require. The token is NOT linked to the phone hash in a
    way the sync core can read — registration consumes the token and discards
    the association, so an identity is not bound to a phone number downstream.

SMS verification is OPTIONAL by deployment policy: crisis users often have no
phone service. Deployments choose whether /v1/register requires a token
(REQUIRE_SMS_VERIFICATION). When disabled, this app is dormant.
"""
import hashlib
import hmac
import secrets

from django.conf import settings
from django.db import models
from django.utils import timezone


def hash_msisdn(msisdn: str) -> str:
    """Keyed hash of a normalised phone number. Never store the raw number."""
    pepper = settings.SMS["PEPPER"].encode()
    norm = msisdn.strip().replace(" ", "")
    return hmac.new(pepper, norm.encode(), hashlib.blake2b).hexdigest()[:64]


def hash_code(code: str, salt: str) -> str:
    return hashlib.blake2b((salt + code).encode(), digest_size=32).hexdigest()


class PhoneVerification(models.Model):
    """A pending or completed verification, keyed by MSISDN hash only."""
    msisdn_hash = models.CharField(max_length=64, db_index=True)
    code_hash = models.CharField(max_length=64)
    code_salt = models.CharField(max_length=32)
    attempts = models.PositiveSmallIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    verified_at = models.DateTimeField(null=True, blank=True)

    MAX_ATTEMPTS = 5

    @classmethod
    def start(cls, msisdn: str):
        """Create a verification and return (record, plaintext_code)."""
        code = f"{secrets.randbelow(1_000_000):06d}"
        salt = secrets.token_hex(8)
        rec = cls.objects.create(
            msisdn_hash=hash_msisdn(msisdn),
            code_hash=hash_code(code, salt),
            code_salt=salt,
        )
        return rec, code

    def is_expired(self) -> bool:
        age = (timezone.now() - self.created_at).total_seconds()
        return age > settings.SMS["CODE_TTL"]

    def try_code(self, code: str) -> bool:
        if self.verified_at or self.is_expired() or self.attempts >= self.MAX_ATTEMPTS:
            return False
        self.attempts += 1
        ok = hmac.compare_digest(self.code_hash, hash_code(code, self.code_salt))
        if ok:
            self.verified_at = timezone.now()
        self.save(update_fields=["attempts", "verified_at"])
        return ok


class RegistrationToken(models.Model):
    """A short-lived, single-use token proving a verification succeeded.

    Deliberately NOT foreign-keyed to anything the sync core reads. It is a
    bearer token consumed once at /v1/register; after consumption no link
    remains between the phone hash and the created identity.
    """
    token = models.CharField(max_length=64, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    consumed = models.BooleanField(default=False)

    @classmethod
    def issue(cls):
        return cls.objects.create(token=secrets.token_urlsafe(32))

    def is_valid(self) -> bool:
        if self.consumed:
            return False
        age = (timezone.now() - self.created_at).total_seconds()
        return age <= settings.SMS["TOKEN_TTL"]
