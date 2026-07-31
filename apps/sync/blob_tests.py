import base64, tempfile
from django.test import TestCase, override_settings
from nacl.signing import SigningKey
from nacl.public import PrivateKey
from rest_framework.test import APIClient

BLOB_LOCAL = {"BACKEND": "local", "LOCAL_ROOT": tempfile.mkdtemp(),
              "S3_BUCKET": "", "S3_ENDPOINT": "", "S3_REGION": "",
              "S3_KEY": "", "S3_SECRET": "", "S3_PRESIGN_TTL": 900}


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


@override_settings(BLOB=BLOB_LOCAL)
class BlobTransferTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        # reset the storage singleton so override_settings takes effect
        import apps.sync.storage as st
        st._store = None

    def test_fragment_roundtrip_local(self):
        alice, bob = Device(self.api), Device(self.api)
        tid = "transfer-xyz"
        frag0 = b"encrypted-fragment-0" + b"\x00" * 100
        frag1 = b"encrypted-fragment-1" + b"\x11" * 100

        for idx, data in [(0, frag0), (1, frag1)]:
            reg = self.api.post(f"/v1/blobs/{tid}/{idx}/register", {
                "count": 2, "recipient_mailbox": bob.mailbox_id,
                "size": len(data), "ttl_seconds": 3600,
            }, format="json", **alice.auth())
            self.assertEqual(reg.status_code, 201, reg.content)
            self.assertTrue(reg.json()["proxy_upload"])  # local store, no presign
            up = self.api.put(f"/v1/blobs/{tid}/{idx}/upload", data,
                              content_type="application/octet-stream", **alice.auth())
            self.assertEqual(up.status_code, 204, up.content)

        # Bob checks the manifest -> complete.
        man = self.api.get(f"/v1/blobs/{tid}", **bob.auth()).json()
        self.assertTrue(man["complete"])
        self.assertEqual(sorted(man["have"]), [0, 1])

        # Bob downloads and gets exact ciphertext back.
        d0 = self.api.get(f"/v1/blobs/{tid}/0", **bob.auth())
        self.assertEqual(d0.content, frag0)

    def test_download_before_upload_404(self):
        alice, bob = Device(self.api), Device(self.api)
        self.api.post("/v1/blobs/t2/0/register", {
            "count": 1, "recipient_mailbox": bob.mailbox_id, "size": 10,
        }, format="json", **alice.auth())
        r = self.api.get("/v1/blobs/t2/0", **bob.auth())
        self.assertEqual(r.status_code, 404)
