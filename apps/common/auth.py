"""
Signature-based authentication.

Flow (architecture §11):
  1. Client GET /v1/challenge?pub=<ed25519_hex>  -> {nonce}
  2. Client signs the nonce bytes with its Ed25519 private key.
  3. Client sends on the authed request three headers:
        X-Identity  : ed25519 public key, hex
        X-Nonce     : the challenge nonce it was issued
        X-Signature : hex signature over the nonce's raw bytes
  4. Server verifies the signature with PyNaCl (libsodium). No password,
     no session. The authenticated "user" is simply the proven public key.

We use ONLY libsodium (PyNaCl) primitives here — no custom crypto. The server
never sees or stores any private key; it only verifies signatures.
"""
from dataclasses import dataclass

from django.conf import settings
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from rest_framework import authentication, exceptions

from .models import Challenge


@dataclass
class Identity:
    """Authenticated principal: a proven Ed25519 public key (hex)."""
    ed25519_pub: str

    @property
    def is_authenticated(self) -> bool:  # DRF checks this attribute
        return True


class SignatureAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        pub = request.headers.get("X-Identity")
        nonce = request.headers.get("X-Nonce")
        sig = request.headers.get("X-Signature")
        if not (pub and nonce and sig):
            return None  # anonymous; permission layer decides if that's ok

        try:
            verify_key = VerifyKey(bytes.fromhex(pub))
            signature = bytes.fromhex(sig)
        except (ValueError, Exception):
            raise exceptions.AuthenticationFailed("Malformed identity or signature")

        # The challenge must exist, match this identity, be unconsumed, fresh.
        try:
            challenge = Challenge.objects.get(nonce=nonce, ed25519_pub=pub)
        except Challenge.DoesNotExist:
            raise exceptions.AuthenticationFailed("Unknown or expired challenge")

        if not challenge.is_valid(settings.PLATFORM["CHALLENGE_TTL"]):
            raise exceptions.AuthenticationFailed("Challenge expired or already used")

        # Verify the signature over the raw nonce bytes.
        try:
            verify_key.verify(challenge.nonce.encode(), signature)
        except BadSignatureError:
            raise exceptions.AuthenticationFailed("Signature verification failed")

        # Single-use: burn the challenge so a captured request can't be replayed.
        challenge.consumed = True
        challenge.save(update_fields=["consumed"])

        return (Identity(ed25519_pub=pub), None)
