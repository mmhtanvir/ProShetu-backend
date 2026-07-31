import os

from django.test import TestCase, override_settings
from nacl.signing import SigningKey
from nacl.public import PrivateKey
from nacl.secret import SecretBox
from rest_framework.test import APIClient

from apps.idverify.crypto import seal_fields, open_fields
from apps.idverify.models import IdentityDocument, DocumentVerification


IDV_WITH_KEY = {
    "PEPPER": "test-pepper",
    "ENC_KEY": os.urandom(SecretBox.KEY_SIZE).hex(),
    "OPERATOR_KEY": "",
}
IDV_HASH_ONLY = {"PEPPER": "test-pepper", "ENC_KEY": "", "OPERATOR_KEY": ""}


class Device:
    def __init__(self, api):
        self.api = api
        self.sign = SigningKey.generate()
        self.dh = PrivateKey.generate()
        self.ed_pub = self.sign.verify_key.encode().hex()
        r = api.post("/v1/register", {"ed25519_pub": self.ed_pub,
                     "x25519_pub": bytes(self.dh.public_key).hex()}, format="json")
        self.mailbox_id = r.json()["mailbox_id"]

    def auth(self):
        n = self.api.get(f"/v1/challenge?pub={self.ed_pub}").json()["nonce"]
        s = self.sign.sign(n.encode()).signature.hex()
        return dict(HTTP_X_IDENTITY=self.ed_pub, HTTP_X_NONCE=n, HTTP_X_SIGNATURE=s)


BC = {
    "doc_type": "birth_certificate",
    "fields": {
        "full_name": "Ayesha Rahman",
        "date_of_birth": "2001-04-17",
        "birth_registration_number": "1998-1234567890",
        "father_name": "Karim Rahman",
        "mother_name": "Nadia Rahman",
    },
}


@override_settings(IDV=IDV_WITH_KEY)
class IdVerifyMatchTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.user = Device(self.api)

    def _ingest(self):
        return self.api.post("/v1/idv/document", BC, format="json", **self.user.auth())

    def test_exact_match_passes_and_is_recorded(self):
        self.assertEqual(self._ingest().status_code, 201)
        # User enters the same info (different formatting on name/date on purpose).
        r = self.api.post("/v1/idv/verify", {
            "doc_type": "birth_certificate",
            "fields": {
                "full_name": "  AYESHA   rahman ",       # case/space differ
                "date_of_birth": "17/04/2001",           # format differs
                "birth_registration_number": "1998 1234567890",  # separator differs
            },
        }, format="json", **self.user.auth())
        self.assertEqual(r.status_code, 200, r.content)
        body = r.json()
        self.assertTrue(body["matched"], body)
        self.assertTrue(body["fields"]["full_name"])
        self.assertTrue(body["fields"]["date_of_birth"])
        # Verification recorded for this identity.
        st = self.api.get("/v1/idv/status", **self.user.auth()).json()
        self.assertTrue(st["verified"])

    def test_name_mismatch_fails(self):
        self._ingest()
        r = self.api.post("/v1/idv/verify", {
            "doc_type": "birth_certificate",
            "fields": {
                "full_name": "Different Person",
                "date_of_birth": "2001-04-17",
                "birth_registration_number": "1998-1234567890",
            },
        }, format="json", **self.user.auth())
        body = r.json()
        self.assertFalse(body["matched"])
        self.assertFalse(body["fields"]["full_name"])
        self.assertTrue(body["fields"]["date_of_birth"])
        # No verification recorded.
        st = self.api.get("/v1/idv/status", **self.user.auth()).json()
        self.assertFalse(st["verified"])

    def test_unknown_document_number(self):
        self._ingest()
        r = self.api.post("/v1/idv/verify", {
            "doc_type": "birth_certificate",
            "fields": {"full_name": "Ayesha Rahman", "date_of_birth": "2001-04-17",
                       "birth_registration_number": "0000-0000000000"},
        }, format="json", **self.user.auth())
        self.assertEqual(r.status_code, 404)
        self.assertFalse(r.json()["matched"])

    def test_raw_stored_encrypted_never_plaintext(self):
        self._ingest()
        doc = IdentityDocument.objects.get()
        # Encrypted blob exists and does NOT contain the plaintext name.
        self.assertIsNotNone(doc.enc_fields)
        self.assertNotIn(b"Ayesha", bytes(doc.enc_fields))
        # fields_hash holds hashes, not values.
        self.assertNotIn("Ayesha", str(doc.fields_hash))
        # But an operator with the key can recover the info ("store the info").
        recovered = open_fields(bytes(doc.enc_fields))
        self.assertEqual(recovered["full_name"], "Ayesha Rahman")


@override_settings(IDV=IDV_HASH_ONLY)
class IdVerifyHashOnlyTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.user = Device(self.api)

    def test_hash_only_mode_matches_without_retaining_raw(self):
        r = self.api.post("/v1/idv/document", BC, format="json", **self.user.auth())
        self.assertEqual(r.status_code, 201)
        self.assertFalse(r.json()["retained_encrypted"])  # no key -> not retained
        doc = IdentityDocument.objects.get()
        self.assertIsNone(doc.enc_fields)
        # Matching still works from hashes alone.
        r2 = self.api.post("/v1/idv/verify", {
            "doc_type": "birth_certificate",
            "fields": {"full_name": "Ayesha Rahman", "date_of_birth": "2001-04-17",
                       "birth_registration_number": "1998-1234567890"},
        }, format="json", **self.user.auth())
        self.assertTrue(r2.json()["matched"])


@override_settings(IDV={"PEPPER": "p", "ENC_KEY": "", "OPERATOR_KEY": "secret-op-key"})
class IdVerifyOperatorGateTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.user = Device(self.api)

    def test_ingest_requires_operator_key_when_set(self):
        r = self.api.post("/v1/idv/document", BC, format="json", **self.user.auth())
        self.assertEqual(r.status_code, 403)
        r2 = self.api.post("/v1/idv/document", BC, format="json",
                           HTTP_X_OPERATOR_KEY="secret-op-key", **self.user.auth())
        self.assertEqual(r2.status_code, 201)
