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

PhoneDirectoryEntry (below) is a deliberate, later exception to the "discards
the association" line above: product wants WhatsApp/Telegram-style "search by
phone number" contact discovery. Every SMS-verified signup becomes
discoverable by whoever has that phone number — not just users who flip a
separate opt-in toggle. The raw number is still never stored (lookups hash
the query with the same pepper and compare), but the hash <-> mailbox_id link
this module used to discard is now kept, by product decision, specifically
for this feature. This does NOT touch the sync core or Identity/PreKeyBundle
— it's a standalone table queried only by /v1/sms/lookup.
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

    `msisdn_hash` is carried on the token (not the identity) purely so
    /v1/register can enforce one-account-per-number via [RegisteredNumber]
    at the moment the token is redeemed. It never touches Identity/PreKeyBundle
    and is not queryable from the sync core, so the phone-hash <-> identity
    link this app exists to avoid is still never made.
    """
    token = models.CharField(max_length=64, unique=True, db_index=True)
    msisdn_hash = models.CharField(max_length=64, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    consumed = models.BooleanField(default=False)

    @classmethod
    def issue(cls, msisdn_hash: str = ""):
        return cls.objects.create(
            token=secrets.token_urlsafe(32), msisdn_hash=msisdn_hash
        )

    def is_valid(self) -> bool:
        if self.consumed:
            return False
        age = (timezone.now() - self.created_at).total_seconds()
        return age <= settings.SMS["TOKEN_TTL"]


class RegisteredNumber(models.Model):
    """Marks an MSISDN hash as already bound to an account (one-account-
    per-number anti-abuse policy referenced in [PhoneVerification]).

    Holds nothing but the hash and a timestamp — no identity/mailbox
    reference — so this table can only answer "has this number registered
    before?"; it cannot be used to map a phone number to an account.
    """
    msisdn_hash = models.CharField(max_length=64, unique=True, db_index=True)
    registered_at = models.DateTimeField(auto_now_add=True)


class PhoneDirectoryEntry(models.Model):
    """Lets another user who already has this phone number find the
    account it belongs to — see this module's docstring for why this
    table exists despite the rest of the file avoiding exactly this
    link. Populated once, at successful SMS-verified registration
    (apps/directory/views.py::register); a number can only ever back
    one identity (RegisteredNumber enforces that upstream), so this is
    at most one row per msisdn_hash for the table's lifetime.
    """
    msisdn_hash = models.CharField(max_length=64, unique=True, db_index=True)
    mailbox_id = models.CharField(max_length=64)
    display_name = models.CharField(max_length=120)
    updated_at = models.DateTimeField(auto_now=True)
