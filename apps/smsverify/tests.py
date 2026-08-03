from unittest.mock import patch

from django.test import TestCase, override_settings
from nacl.signing import SigningKey
from nacl.public import PrivateKey
from rest_framework.test import APIClient

from apps.smsverify.models import PhoneVerification, hash_msisdn
from apps.smsverify.sender import ConsoleSender, TwilioSender, get_sender


BASE_SMS = {
    "REQUIRE_SMS_VERIFICATION": True, "SENDER": "console",
    "PEPPER": "test-pepper", "CODE_TTL": 600, "TOKEN_TTL": 600,
    "TWILIO_SID": "", "TWILIO_TOKEN": "", "TWILIO_FROM": "",
}


class SmsVerifyTests(TestCase):
    def setUp(self):
        self.api = APIClient()

    def test_raw_number_never_stored(self):
        rec, code = PhoneVerification.start("+15551234567")
        self.assertNotIn("5551234567", rec.msisdn_hash)
        self.assertEqual(rec.msisdn_hash, hash_msisdn("+15551234567"))

    def test_request_verify_flow(self):
        r = self.api.post("/v1/sms/request", {"msisdn": "+15550001111"},
                          format="json")
        self.assertEqual(r.status_code, 201)
        vid = r.json()["verification_id"]
        # Pull the code from the DB (in real life it arrives by SMS).
        rec = PhoneVerification.objects.get(id=vid)
        # We can't read the plaintext code back (only its hash is stored), so
        # recompute a fresh verification with a known code path:
        # instead, test the wrong-code branch here and correct-code below.
        bad = self.api.post("/v1/sms/verify",
                            {"verification_id": vid, "code": "000000"},
                            format="json")
        # 000000 is almost certainly wrong -> 400 (or succeeds 1-in-a-million).
        self.assertIn(bad.status_code, (400,))

    def test_correct_code_issues_token(self):
        rec, code = PhoneVerification.start("+15559998888")
        r = self.api.post("/v1/sms/verify",
                          {"verification_id": rec.id, "code": code},
                          format="json")
        self.assertEqual(r.status_code, 200, r.content)
        self.assertIn("registration_token", r.json())

    def test_attempts_are_limited(self):
        rec, code = PhoneVerification.start("+15557776666")
        for _ in range(PhoneVerification.MAX_ATTEMPTS):
            rec.try_code("111111")  # wrong
        # Even the correct code now fails after too many attempts.
        self.assertFalse(rec.try_code(code))

    @override_settings(SMS=BASE_SMS)
    def test_registration_requires_token_when_enabled(self):
        sign = SigningKey.generate()
        dh = PrivateKey.generate()
        payload = {"ed25519_pub": sign.verify_key.encode().hex(),
                   "x25519_pub": bytes(dh.public_key).hex()}
        # No token -> forbidden.
        r = self.api.post("/v1/register", payload, format="json")
        self.assertEqual(r.status_code, 403)

        # Verify a phone -> get token -> register succeeds.
        rec, code = PhoneVerification.start("+15551112222")
        tok = self.api.post("/v1/sms/verify",
                            {"verification_id": rec.id, "code": code},
                            format="json").json()["registration_token"]
        payload["registration_token"] = tok
        r2 = self.api.post("/v1/register", payload, format="json")
        self.assertEqual(r2.status_code, 201, r2.content)

        # Token is single-use -> reusing it fails.
        sign2 = SigningKey.generate()
        payload2 = {"ed25519_pub": sign2.verify_key.encode().hex(),
                    "x25519_pub": bytes(dh.public_key).hex(),
                    "registration_token": tok}
        r3 = self.api.post("/v1/register", payload2, format="json")
        self.assertEqual(r3.status_code, 403)

    @override_settings(SMS=BASE_SMS)
    def test_cannot_request_code_for_already_registered_number(self):
        # First signup with this number succeeds end-to-end.
        rec, code = PhoneVerification.start("+15552223333")
        tok = self.api.post("/v1/sms/verify",
                            {"verification_id": rec.id, "code": code},
                            format="json").json()["registration_token"]
        sign = SigningKey.generate()
        dh = PrivateKey.generate()
        r = self.api.post("/v1/register", {
            "ed25519_pub": sign.verify_key.encode().hex(),
            "x25519_pub": bytes(dh.public_key).hex(),
            "registration_token": tok,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content)

        # A second attempt to even request a code for the same number is
        # rejected before any SMS is sent.
        r2 = self.api.post("/v1/sms/request", {"msisdn": "+15552223333"},
                           format="json")
        self.assertEqual(r2.status_code, 409, r2.content)

    @override_settings(SMS=BASE_SMS)
    def test_register_rejects_reused_number_even_with_a_fresh_token(self):
        # First signup with this number succeeds.
        rec, code = PhoneVerification.start("+15554445555")
        tok = self.api.post("/v1/sms/verify",
                            {"verification_id": rec.id, "code": code},
                            format="json").json()["registration_token"]
        sign = SigningKey.generate()
        dh = PrivateKey.generate()
        r = self.api.post("/v1/register", {
            "ed25519_pub": sign.verify_key.encode().hex(),
            "x25519_pub": bytes(dh.public_key).hex(),
            "registration_token": tok,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content)

        # Simulate a second, independently-verified token for the SAME
        # number (bypassing the /v1/sms/request gate directly at the model
        # level, the way a race between two in-flight signups could) —
        # /v1/register must still refuse it.
        rec2, code2 = PhoneVerification.start("+15554445555")
        tok2 = self.api.post("/v1/sms/verify",
                             {"verification_id": rec2.id, "code": code2},
                             format="json").json()["registration_token"]
        sign2 = SigningKey.generate()
        r2 = self.api.post("/v1/register", {
            "ed25519_pub": sign2.verify_key.encode().hex(),
            "x25519_pub": bytes(dh.public_key).hex(),
            "registration_token": tok2,
        }, format="json")
        self.assertEqual(r2.status_code, 409, r2.content)

    def _signed_in_device(self, phone="+15550009999"):
        """A second, independent registered+authenticated device — the
        one doing the phone-number search, mirroring apps/sync/tests.py's
        Device helper (real Ed25519 signing, not a mock). Goes through
        its own SMS verification too — REQUIRE_SMS_VERIFICATION is on
        for every test that calls this."""
        rec, code = PhoneVerification.start(phone)
        tok = self.api.post("/v1/sms/verify",
                            {"verification_id": rec.id, "code": code},
                            format="json").json()["registration_token"]
        sign = SigningKey.generate()
        dh = PrivateKey.generate()
        ed_pub = sign.verify_key.encode().hex()
        r = self.api.post("/v1/register", {
            "ed25519_pub": ed_pub, "x25519_pub": bytes(dh.public_key).hex(),
            "registration_token": tok,
        }, format="json")
        assert r.status_code == 201, r.content

        nonce = self.api.get(f"/v1/challenge?pub={ed_pub}").json()["nonce"]
        sig = sign.sign(nonce.encode()).signature.hex()
        return {
            "HTTP_X_IDENTITY": ed_pub,
            "HTTP_X_NONCE": nonce,
            "HTTP_X_SIGNATURE": sig,
        }

    @override_settings(SMS=BASE_SMS)
    def test_register_with_display_name_is_findable_by_phone_lookup(self):
        rec, code = PhoneVerification.start("+15556667777")
        tok = self.api.post("/v1/sms/verify",
                            {"verification_id": rec.id, "code": code},
                            format="json").json()["registration_token"]
        sign = SigningKey.generate()
        dh = PrivateKey.generate()
        ed_pub = sign.verify_key.encode().hex()
        x_pub = bytes(dh.public_key).hex()
        r = self.api.post("/v1/register", {
            "ed25519_pub": ed_pub,
            "x25519_pub": x_pub,
            "registration_token": tok,
            "display_name": "Ava Patel",
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content)
        mailbox_id = r.json()["mailbox_id"]

        headers = self._signed_in_device()
        found = self.api.post("/v1/sms/lookup", {"msisdn": "+15556667777"},
                              format="json", **headers)
        self.assertEqual(found.status_code, 200, found.content)
        self.assertEqual(found.json(), {
            "mailbox_id": mailbox_id, "display_name": "Ava Patel",
            "ed25519_pub": ed_pub, "x25519_pub": x_pub,
        })

    @override_settings(SMS=BASE_SMS)
    def test_lookup_requires_authentication(self):
        r = self.api.post("/v1/sms/lookup", {"msisdn": "+15556667777"},
                          format="json")
        self.assertIn(r.status_code, (401, 403))

    @override_settings(SMS=BASE_SMS)
    def test_lookup_404_for_number_never_registered(self):
        headers = self._signed_in_device()
        r = self.api.post("/v1/sms/lookup", {"msisdn": "+15559990000"},
                          format="json", **headers)
        self.assertEqual(r.status_code, 404)

    @override_settings(SMS=BASE_SMS)
    def test_register_without_display_name_is_not_findable(self):
        # Crisis users must still be able to skip sharing a display
        # name — see apps/directory/views.py::register's doc comment.
        rec, code = PhoneVerification.start("+15551237890")
        tok = self.api.post("/v1/sms/verify",
                            {"verification_id": rec.id, "code": code},
                            format="json").json()["registration_token"]
        sign = SigningKey.generate()
        dh = PrivateKey.generate()
        r = self.api.post("/v1/register", {
            "ed25519_pub": sign.verify_key.encode().hex(),
            "x25519_pub": bytes(dh.public_key).hex(),
            "registration_token": tok,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content)

        headers = self._signed_in_device()
        found = self.api.post("/v1/sms/lookup", {"msisdn": "+15551237890"},
                              format="json", **headers)
        self.assertEqual(found.status_code, 404)


class TwilioSenderTests(TestCase):
    @override_settings(SMS={**BASE_SMS, "SENDER": "twilio",
                            "TWILIO_SID": "sid", "TWILIO_TOKEN": "token",
                            "TWILIO_FROM": "+15550000000"})
    def test_sends_via_twilio_client(self):
        self.assertIsInstance(get_sender(), TwilioSender)
        with patch("twilio.rest.Client") as MockClient:
            instance = MockClient.return_value
            ok = TwilioSender().send_code("+15551234567", "123456")
        self.assertTrue(ok)
        instance.messages.create.assert_called_once()
        _, kwargs = instance.messages.create.call_args
        self.assertEqual(kwargs["to"], "+15551234567")
        self.assertEqual(kwargs["from_"], "+15550000000")
        self.assertIn("123456", kwargs["body"])

    @override_settings(SMS={**BASE_SMS, "SENDER": "twilio",
                            "TWILIO_SID": "", "TWILIO_TOKEN": "",
                            "TWILIO_FROM": ""})
    def test_missing_credentials_raises_at_construction(self):
        with self.assertRaises(RuntimeError):
            TwilioSender()

    @override_settings(SMS={**BASE_SMS, "SENDER": "console"})
    def test_console_backend_selected_by_default(self):
        self.assertIsInstance(get_sender(), ConsoleSender)

    @override_settings(SMS={**BASE_SMS, "SENDER": "twilio",
                            "TWILIO_SID": "sid", "TWILIO_TOKEN": "token",
                            "TWILIO_FROM": "+15550000000"})
    def test_request_code_returns_502_when_delivery_fails(self):
        from twilio.base.exceptions import TwilioRestException
        api = APIClient()
        with patch("twilio.rest.Client") as MockClient:
            MockClient.return_value.messages.create.side_effect = (
                TwilioRestException(400, "uri", "delivery failed")
            )
            r = api.post("/v1/sms/request", {"msisdn": "+15551234567"},
                         format="json")
        self.assertEqual(r.status_code, 502, r.content)
        self.assertFalse(
            PhoneVerification.objects.filter(
                msisdn_hash=hash_msisdn("+15551234567")
            ).exists()
        )
