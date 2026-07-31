import base64
import hashlib
from django.test import TestCase
from nacl.signing import SigningKey
from nacl.public import PrivateKey
from rest_framework.test import APIClient


class CoordinationTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.sign = SigningKey.generate()
        self.dh = PrivateKey.generate()
        self.ed_pub = self.sign.verify_key.encode().hex()
        r = self.api.post("/v1/register",
                          {"ed25519_pub": self.ed_pub,
                           "x25519_pub": bytes(self.dh.public_key).hex()},
                          format="json")
        assert r.status_code == 201

    def _auth(self):
        nonce = self.api.get(f"/v1/challenge?pub={self.ed_pub}").json()["nonce"]
        sig = self.sign.sign(nonce.encode()).signature.hex()
        return dict(HTTP_X_IDENTITY=self.ed_pub, HTTP_X_NONCE=nonce,
                    HTTP_X_SIGNATURE=sig)

    def test_publish_and_fetch_delta_by_shard(self):
        raw = b"encrypted-signed-crdt-delta-danger-zone"
        r = self.api.post("/v1/coord/tzcvd/publish",
                          {"ttl_seconds": 3600,
                           "ciphertext": base64.b64encode(raw).decode()},
                          format="json", **self._auth())
        self.assertEqual(r.status_code, 201, r.content)
        did = r.json()["delta_id"]
        self.assertEqual(did, hashlib.blake2b(raw, digest_size=16).hexdigest())

        got = self.api.get("/v1/coord/tzcvd", **self._auth())
        self.assertEqual(got.status_code, 200)
        deltas = got.json()["deltas"]
        self.assertEqual(len(deltas), 1)
        self.assertEqual(base64.b64decode(deltas[0]["ciphertext"]), raw)

    def test_geohash_truncated_to_coarse_precision(self):
        raw = b"delta-with-precise-geohash-attempt"
        # Client tries to attach a precise 9-char geohash; server truncates to 5.
        r = self.api.post("/v1/coord/tzcvd7xk2/publish",
                          {"ttl_seconds": 3600,
                           "ciphertext": base64.b64encode(raw).decode()},
                          format="json", **self._auth())
        self.assertEqual(r.status_code, 201)
        from apps.coordination.models import CoordDelta
        self.assertEqual(CoordDelta.objects.first().geohash, "tzcvd")
