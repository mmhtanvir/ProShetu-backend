import base64
from django.test import TestCase
from nacl.signing import SigningKey
from nacl.public import PrivateKey
from rest_framework.test import APIClient


class Device:
    def __init__(self, api):
        self.api = api
        self.sign = SigningKey.generate()
        self.dh = PrivateKey.generate()
        self.ed_pub = self.sign.verify_key.encode().hex()
        r = api.post("/v1/register",
                     {"ed25519_pub": self.ed_pub,
                      "x25519_pub": bytes(self.dh.public_key).hex()},
                     format="json")
        self.mailbox_id = r.json()["mailbox_id"]

    def auth(self):
        n = self.api.get(f"/v1/challenge?pub={self.ed_pub}").json()["nonce"]
        s = self.sign.sign(n.encode()).signature.hex()
        return dict(HTTP_X_IDENTITY=self.ed_pub, HTTP_X_NONCE=n, HTTP_X_SIGNATURE=s)


class CallSignallingTests(TestCase):
    def setUp(self):
        self.api = APIClient()

    def test_offer_answer_relay(self):
        alice = Device(self.api)
        bob = Device(self.api)

        # Alice rings Bob: sealed offer (codecs + ephemeral pub + SAS commit).
        offer = base64.b64encode(b"sealed-offer-opaque").decode()
        r = self.api.post("/v1/call/signal", {
            "call_id": "abc123", "recipient_mailbox": bob.mailbox_id,
            "kind": "offer", "seq": 0, "ciphertext": offer,
        }, format="json", **alice.auth())
        self.assertEqual(r.status_code, 201, r.content)

        # Bob polls and receives it.
        got = self.api.get("/v1/call/poll", **bob.auth()).json()["signals"]
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["kind"], "offer")
        self.assertEqual(base64.b64decode(got[0]["ciphertext"]), b"sealed-offer-opaque")

        # Polling again returns nothing (delivered signals are consumed).
        again = self.api.get("/v1/call/poll", **bob.auth()).json()["signals"]
        self.assertEqual(again, [])

        # Bob answers.
        ans = base64.b64encode(b"sealed-answer").decode()
        r2 = self.api.post("/v1/call/signal", {
            "call_id": "abc123", "recipient_mailbox": alice.mailbox_id,
            "kind": "answer", "seq": 1, "ciphertext": ans,
        }, format="json", **bob.auth())
        self.assertEqual(r2.status_code, 201)
        got_a = self.api.get("/v1/call/poll", **alice.auth()).json()["signals"]
        self.assertEqual(got_a[0]["kind"], "answer")

    def test_oversized_signal_rejected(self):
        alice = Device(self.api)
        bob = Device(self.api)
        big = base64.b64encode(b"x" * 9000).decode()  # > 8 KiB guard
        r = self.api.post("/v1/call/signal", {
            "call_id": "big", "recipient_mailbox": bob.mailbox_id,
            "kind": "offer", "ciphertext": big,
        }, format="json", **alice.auth())
        self.assertEqual(r.status_code, 400)

    def test_ttl_capped(self):
        alice = Device(self.api)
        bob = Device(self.api)
        r = self.api.post("/v1/call/signal", {
            "call_id": "ttl", "recipient_mailbox": bob.mailbox_id,
            "kind": "offer", "ttl_seconds": 99999,  # above 90s ceiling
            "ciphertext": base64.b64encode(b"o").decode(),
        }, format="json", **alice.auth())
        self.assertEqual(r.status_code, 400)  # serializer max_value rejects
