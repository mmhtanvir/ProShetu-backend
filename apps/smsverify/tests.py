from django.test import TestCase, override_settings
from nacl.signing import SigningKey
from nacl.public import PrivateKey
from rest_framework.test import APIClient

from apps.smsverify.models import PhoneVerification, hash_msisdn


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
