"""
End-to-end tests for encrypted key backup (POST /v1/backup,
POST /v1/backup/fetch) — lets a user restore their EXISTING identity
on a new device via a self-chosen "Encryption ID" instead of minting a
fresh one through /v1/recover. See IdentityBackup's docstring
(apps/directory/models.py) for the zero-knowledge design: this server
only ever stores/returns an opaque, client-encrypted blob.
"""
from django.test import TestCase, override_settings
from nacl.signing import SigningKey
from nacl.public import PrivateKey
from rest_framework.test import APIClient

from apps.smsverify.models import PhoneVerification


BASE_SMS = {
    "REQUIRE_SMS_VERIFICATION": True, "SENDER": "console",
    "PEPPER": "test-pepper", "CODE_TTL": 600, "TOKEN_TTL": 600,
    "TWILIO_SID": "", "TWILIO_TOKEN": "", "TWILIO_FROM": "",
}


class Device:
    """Mirrors what the Flutter app's crypto core does — real Ed25519
    signature auth, no mocks."""

    def __init__(self, api: APIClient):
        self.api = api
        self.sign = SigningKey.generate()
        self.dh = PrivateKey.generate()
        self.ed_pub = self.sign.verify_key.encode().hex()
        self.x_pub = bytes(self.dh.public_key).hex()
        self.mailbox_id = None

    def _auth_headers(self):
        r = self.api.get(f"/v1/challenge?pub={self.ed_pub}")
        assert r.status_code == 200, r.content
        nonce = r.json()["nonce"]
        sig = self.sign.sign(nonce.encode()).signature.hex()
        return {
            "HTTP_X_IDENTITY": self.ed_pub,
            "HTTP_X_NONCE": nonce,
            "HTTP_X_SIGNATURE": sig,
        }

    @staticmethod
    def issue_token(phone, purpose="signup"):
        """Bypasses the SMS-sending step (as apps/smsverify/tests.py
        does) — verifies the real /v1/sms/verify endpoint still issues
        a usable token from a verification created directly."""
        rec, code = PhoneVerification.start(phone, purpose=purpose)
        api = APIClient()
        r = api.post("/v1/sms/verify",
                     {"verification_id": rec.id, "code": code}, format="json")
        assert r.status_code == 200, r.content
        return r.json()["registration_token"]

    def register(self, phone, display_name="Test User"):
        token = self.issue_token(phone, purpose="signup")
        r = self.api.post("/v1/register", {
            "ed25519_pub": self.ed_pub, "x25519_pub": self.x_pub,
            "registration_token": token, "display_name": display_name,
        }, format="json")
        assert r.status_code == 201, r.content
        self.mailbox_id = r.json()["mailbox_id"]
        return self

    def upload_backup(self, blob):
        return self.api.post("/v1/backup", {"encrypted_bundle": blob},
                             format="json", **self._auth_headers())


@override_settings(SMS=BASE_SMS)
class BackupTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.phone = "+15551230000"

    def test_upload_then_fetch_roundtrips_blob(self):
        dev = Device(self.api).register(self.phone)
        blob = "base64-ciphertext-not-decryptable-server-side"
        r = dev.upload_backup(blob)
        self.assertEqual(r.status_code, 204, r.content)

        # A brand new device, no identity yet — proves phone ownership
        # via a fresh recovery-purpose token, same as /v1/recover.
        recovery_token = Device.issue_token(self.phone, purpose="recovery")
        r = self.api.post("/v1/backup/fetch",
                          {"registration_token": recovery_token}, format="json")
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual(r.json()["encrypted_bundle"], blob)
        self.assertEqual(r.json()["mailbox_id"], dev.mailbox_id)

    def test_fetch_rejects_signup_purpose_token(self):
        dev = Device(self.api).register(self.phone)
        dev.upload_backup("some-blob")

        signup_token = Device.issue_token(self.phone, purpose="signup")
        r = self.api.post("/v1/backup/fetch",
                          {"registration_token": signup_token}, format="json")
        self.assertEqual(r.status_code, 403, r.content)

    def test_fetch_rejects_reused_token(self):
        dev = Device(self.api).register(self.phone)
        dev.upload_backup("some-blob")

        recovery_token = Device.issue_token(self.phone, purpose="recovery")
        r1 = self.api.post("/v1/backup/fetch",
                           {"registration_token": recovery_token}, format="json")
        self.assertEqual(r1.status_code, 200, r1.content)
        r2 = self.api.post("/v1/backup/fetch",
                           {"registration_token": recovery_token}, format="json")
        self.assertEqual(r2.status_code, 403, r2.content)

    def test_fetch_404_when_never_uploaded(self):
        Device(self.api).register(self.phone)
        recovery_token = Device.issue_token(self.phone, purpose="recovery")
        r = self.api.post("/v1/backup/fetch",
                          {"registration_token": recovery_token}, format="json")
        self.assertEqual(r.status_code, 404, r.content)

    def test_upload_requires_authentication(self):
        r = self.api.post("/v1/backup", {"encrypted_bundle": "x"}, format="json")
        self.assertIn(r.status_code, (401, 403), r.content)

    def test_second_upload_replaces_first(self):
        dev = Device(self.api).register(self.phone)
        dev.upload_backup("old-blob")
        r = dev.upload_backup("new-blob")
        self.assertEqual(r.status_code, 204, r.content)

        recovery_token = Device.issue_token(self.phone, purpose="recovery")
        r = self.api.post("/v1/backup/fetch",
                          {"registration_token": recovery_token}, format="json")
        self.assertEqual(r.json()["encrypted_bundle"], "new-blob")


@override_settings(SMS={**BASE_SMS, "REQUIRE_SMS_VERIFICATION": False})
class BackupWithoutSmsTests(TestCase):
    """Deployments with SMS verification off have no phone/msisdn_hash
    to key a backup by — upload must fail clearly, not silently no-op,
    and fetch must say recovery is unavailable, matching /v1/recover's
    existing behaviour for the same deployment mode."""

    def setUp(self):
        self.api = APIClient()

    def test_upload_without_phone_link_rejected(self):
        dev = Device(self.api)
        r = self.api.post("/v1/register", {
            "ed25519_pub": dev.ed_pub, "x25519_pub": dev.x_pub,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content)
        r = dev.upload_backup("x")
        self.assertEqual(r.status_code, 400, r.content)

    def test_fetch_unavailable(self):
        r = self.api.post("/v1/backup/fetch",
                          {"registration_token": "whatever"}, format="json")
        self.assertEqual(r.status_code, 400, r.content)
