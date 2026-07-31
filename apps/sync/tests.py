"""
End-to-end tests exercising the real Ed25519 signature auth and the
store-and-forward sync flow. Uses PyNaCl (libsodium) client-side exactly as a
real device would, so these tests prove the auth + sync contract, not mocks.
"""
import base64
import hashlib

from django.test import TestCase
from nacl.signing import SigningKey
from nacl.public import PrivateKey
from rest_framework.test import APIClient


def content_id(raw: bytes) -> str:
    return hashlib.blake2b(raw, digest_size=16).hexdigest()


class Device:
    """A minimal client that mirrors what the Flutter app's crypto core does."""

    def __init__(self, api: APIClient):
        self.api = api
        self.sign = SigningKey.generate()
        self.dh = PrivateKey.generate()
        self.ed_pub = self.sign.verify_key.encode().hex()
        self.x_pub = bytes(self.dh.public_key).hex()
        self.mailbox_id = None

    def register(self):
        r = self.api.post("/v1/register",
                          {"ed25519_pub": self.ed_pub, "x25519_pub": self.x_pub},
                          format="json")
        assert r.status_code == 201, r.content
        self.mailbox_id = r.json()["mailbox_id"]
        return self

    def _auth_headers(self):
        # 1. get a challenge, 2. sign the nonce, 3. present the three headers.
        r = self.api.get(f"/v1/challenge?pub={self.ed_pub}")
        assert r.status_code == 200, r.content
        nonce = r.json()["nonce"]
        sig = self.sign.sign(nonce.encode()).signature.hex()
        return {
            "HTTP_X_IDENTITY": self.ed_pub,
            "HTTP_X_NONCE": nonce,
            "HTTP_X_SIGNATURE": sig,
        }

    def sync(self, carrying=None, bloom=None, want=None):
        body = {"carrying": carrying or []}
        if bloom:
            body.update(bloom)
        if want:
            body["want"] = want
        r = self.api.post("/v1/sync", body, format="json", **self._auth_headers())
        assert r.status_code == 200, r.content
        return r.json()


class SignatureAuthTests(TestCase):
    def setUp(self):
        self.api = APIClient()

    def test_bad_signature_rejected(self):
        dev = Device(self.api).register()
        r = self.api.get(f"/v1/challenge?pub={dev.ed_pub}")
        nonce = r.json()["nonce"]
        # Sign with a DIFFERENT key -> must fail.
        wrong = SigningKey.generate()
        bad_sig = wrong.sign(nonce.encode()).signature.hex()
        r2 = self.api.post("/v1/sync", {"carrying": []}, format="json",
                           HTTP_X_IDENTITY=dev.ed_pub, HTTP_X_NONCE=nonce,
                           HTTP_X_SIGNATURE=bad_sig)
        self.assertEqual(r2.status_code, 403)

    def test_challenge_is_single_use(self):
        dev = Device(self.api).register()
        r = self.api.get(f"/v1/challenge?pub={dev.ed_pub}")
        nonce = r.json()["nonce"]
        sig = dev.sign.sign(nonce.encode()).signature.hex()
        headers = dict(HTTP_X_IDENTITY=dev.ed_pub, HTTP_X_NONCE=nonce,
                       HTTP_X_SIGNATURE=sig)
        first = self.api.post("/v1/sync", {"carrying": []}, format="json", **headers)
        self.assertEqual(first.status_code, 200)
        # Replaying the exact same challenge+signature must now fail.
        replay = self.api.post("/v1/sync", {"carrying": []}, format="json", **headers)
        self.assertEqual(replay.status_code, 403)


class SyncFlowTests(TestCase):
    def setUp(self):
        self.api = APIClient()

    def test_store_and_forward_delivery(self):
        alice = Device(self.api).register()
        bob = Device(self.api).register()

        # Alice sends Bob an (opaque) event. In reality ciphertext is E2E; here
        # it's just bytes the server can't read anyway.
        raw = b"opaque-e2e-ciphertext-for-bob-" + b"\x00" * 64
        ev = {
            "event_id": content_id(raw),
            "recipient_mailbox": bob.mailbox_id,
            "priority": 2,
            "ttl_seconds": 3600,
            "ciphertext": base64.b64encode(raw).decode(),
        }
        out = alice.sync(carrying=[ev])
        self.assertIn(ev["event_id"], out["accepted"])
        self.assertEqual(out["deliver"], [])  # nothing addressed to Alice

        # Bob syncs and receives it.
        got = bob.sync()
        ids = [e["event_id"] for e in got["deliver"]]
        self.assertIn(ev["event_id"], ids)
        # Ciphertext round-trips byte-for-byte.
        delivered = next(e for e in got["deliver"] if e["event_id"] == ev["event_id"])
        self.assertEqual(base64.b64decode(delivered["ciphertext"]), raw)

    def test_content_id_mismatch_rejected(self):
        alice = Device(self.api).register()
        bob = Device(self.api).register()
        raw = b"payload"
        ev = {
            "event_id": "deadbeef" * 4,  # wrong hash
            "recipient_mailbox": bob.mailbox_id,
            "priority": 2, "ttl_seconds": 3600,
            "ciphertext": base64.b64encode(raw).decode(),
        }
        r = self.api.post("/v1/sync", {"carrying": [ev]}, format="json",
                          **alice._auth_headers())
        self.assertEqual(r.status_code, 400)

    def test_dedup_is_idempotent(self):
        alice = Device(self.api).register()
        bob = Device(self.api).register()
        raw = b"dup-test" + b"\x01" * 32
        ev = {
            "event_id": content_id(raw),
            "recipient_mailbox": bob.mailbox_id,
            "priority": 1, "ttl_seconds": 3600,
            "ciphertext": base64.b64encode(raw).decode(),
        }
        alice.sync(carrying=[ev])
        alice.sync(carrying=[ev])  # resubmit — must not duplicate
        from apps.sync.models import Event
        self.assertEqual(Event.objects.filter(event_id=ev["event_id"]).count(), 1)

    def test_bloom_suppresses_already_held_events(self):
        alice = Device(self.api).register()
        bob = Device(self.api).register()
        raw = b"bloom-held" + b"\x02" * 32
        eid = content_id(raw)
        ev = {
            "event_id": eid, "recipient_mailbox": bob.mailbox_id,
            "priority": 2, "ttl_seconds": 3600,
            "ciphertext": base64.b64encode(raw).decode(),
        }
        alice.sync(carrying=[ev])

        # Bob claims (via Bloom) he already holds it -> server should not redeliver.
        from apps.sync.bloom import BloomFilter
        bf = BloomFilter(m_bits=4096, k=7)
        bf.add(eid)
        bloom = {"bloom_m": 4096, "bloom_k": 7, "bloom_bits": bytes(bf.bits).hex()}
        got = bob.sync(bloom=bloom)
        self.assertNotIn(eid, [e["event_id"] for e in got["deliver"]])

        # But if Bob explicitly WANTS it (false-positive repair), he gets it.
        got2 = bob.sync(bloom=bloom, want=[eid])
        self.assertIn(eid, [e["event_id"] for e in got2["deliver"]])

    def test_ttl_clamped_to_priority_ceiling(self):
        alice = Device(self.api).register()
        bob = Device(self.api).register()
        raw = b"ttl-clamp" + b"\x03" * 32
        ev = {
            "event_id": content_id(raw), "recipient_mailbox": bob.mailbox_id,
            "priority": 0,               # P0 ceiling is 72h
            "ttl_seconds": 999999999,    # absurd
            "ciphertext": base64.b64encode(raw).decode(),
        }
        alice.sync(carrying=[ev])
        from apps.sync.models import Event
        from django.utils import timezone
        obj = Event.objects.get(event_id=ev["event_id"])
        # Expiry must be within the 72h ceiling, not ~31 years out.
        self.assertLess((obj.ttl_expires_at - timezone.now()).total_seconds(),
                        72 * 3600 + 60)
