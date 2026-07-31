#!/usr/bin/env python3
"""
API test client for the Crisis Platform backend.

Handles the signature-auth dance for you (challenge -> sign nonce -> headers)
so you can exercise real endpoints against a running server.

USAGE
  # 1. start the server in one terminal (from the project root):
  #      IDV_ENC_KEY=$(python3 -c "import os;print(os.urandom(32).hex())") \
  #      daphne -b 127.0.0.1 -p 8000 config.asgi:application
  #
  # 2. in another terminal:
  #      pip install requests
  #      python scripts/api_client.py                 # runs the full smoke test
  #      python scripts/api_client.py --base http://127.0.0.1:8000

Use the Client class in your own scripts / a REPL to poke individual endpoints.
"""
import argparse
import base64
import hashlib
import sys

import requests
from nacl.signing import SigningKey
from nacl.public import PrivateKey


class Client:
    """One virtual device: holds keys, registers, and signs authed requests."""

    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.sign = SigningKey.generate()
        self.dh = PrivateKey.generate()
        self.ed_pub = self.sign.verify_key.encode().hex()
        self.x_pub = bytes(self.dh.public_key).hex()
        self.mailbox_id = None

    # --- auth helpers ------------------------------------------------------
    def register(self, registration_token: str | None = None):
        body = {"ed25519_pub": self.ed_pub, "x25519_pub": self.x_pub}
        if registration_token:
            body["registration_token"] = registration_token
        r = requests.post(f"{self.base}/v1/register", json=body)
        r.raise_for_status()
        self.mailbox_id = r.json()["mailbox_id"]
        return self.mailbox_id

    def _auth(self):
        """Fetch a fresh single-use challenge and sign it. Returns headers."""
        n = requests.get(f"{self.base}/v1/challenge",
                         params={"pub": self.ed_pub}).json()["nonce"]
        sig = self.sign.sign(n.encode()).signature.hex()
        return {"X-Identity": self.ed_pub, "X-Nonce": n, "X-Signature": sig}

    # --- thin endpoint wrappers (add more as you need them) ----------------
    def get(self, path, **kw):
        return requests.get(f"{self.base}{path}", headers=self._auth(), **kw)

    def post(self, path, json=None, **kw):
        return requests.post(f"{self.base}{path}", json=json,
                             headers=self._auth(), **kw)

    def put_bytes(self, path, data):
        h = self._auth(); h["Content-Type"] = "application/octet-stream"
        return requests.put(f"{self.base}{path}", data=data, headers=h)


def content_id(raw: bytes) -> str:
    return hashlib.blake2b(raw, digest_size=16).hexdigest()


def ok(cond, label):
    print(("  PASS " if cond else "  FAIL ") + label)
    return cond


def smoke(base: str) -> int:
    print(f"== Crisis backend API smoke test against {base} ==\n")
    failures = 0

    # -- open endpoints (no auth) -----------------------------------------
    print("[open endpoints]")
    h = requests.get(f"{base}/healthz")
    failures += not ok(h.status_code == 200 and h.json()["status"] == "ok",
                       "GET /healthz")

    alice, bob = Client(base), Client(base)
    alice.register(); bob.register()
    failures += not ok(alice.mailbox_id and bob.mailbox_id,
                       "POST /v1/register (alice, bob)")

    # -- sync: store-and-forward ------------------------------------------
    print("\n[sync]")
    raw = b"opaque-e2e-ciphertext" + b"\x00" * 40
    eid = content_id(raw)
    ev = {"event_id": eid, "recipient_mailbox": bob.mailbox_id,
          "priority": 2, "ttl_seconds": 3600,
          "ciphertext": base64.b64encode(raw).decode()}
    push = alice.post("/v1/sync", {"carrying": [ev]}).json()
    failures += not ok(eid in push["accepted"], "POST /v1/sync (alice pushes)")

    pull = bob.post("/v1/sync", {"carrying": []}).json()
    got = [e["event_id"] for e in pull["deliver"]]
    rt = any(base64.b64decode(e["ciphertext"]) == raw
             for e in pull["deliver"] if e["event_id"] == eid)
    failures += not ok(eid in got and rt, "POST /v1/sync (bob pulls, byte-exact)")

    # -- calling: signalling relay ----------------------------------------
    print("\n[calling]")
    sig_body = {"call_id": "ring1", "recipient_mailbox": bob.mailbox_id,
                "kind": "offer",
                "ciphertext": base64.b64encode(b"sealed-offer").decode()}
    s = alice.post("/v1/call/signal", sig_body)
    failures += not ok(s.status_code == 201, "POST /v1/call/signal")
    poll = bob.get("/v1/call/poll").json()["signals"]
    failures += not ok(any(x["kind"] == "offer" for x in poll),
                       "GET /v1/call/poll")

    # -- blobs: object-store fragment transfer ----------------------------
    print("\n[blobs]")
    tid, data = "transfer1", b"encrypted-fragment" * 8
    reg = alice.post(f"/v1/blobs/{tid}/0/register",
                     {"count": 1, "recipient_mailbox": bob.mailbox_id,
                      "size": len(data), "ttl_seconds": 3600})
    failures += not ok(reg.status_code == 201, "POST /v1/blobs/{t}/0/register")
    if reg.json().get("proxy_upload"):  # local store path
        up = alice.put_bytes(f"/v1/blobs/{tid}/0/upload", data)
        failures += not ok(up.status_code == 204, "PUT /v1/blobs/{t}/0/upload")
    man = bob.get(f"/v1/blobs/{tid}").json()
    failures += not ok(man.get("complete") is True, "GET /v1/blobs/{t} (manifest)")
    dl = bob.get(f"/v1/blobs/{tid}/0")
    body = dl.content if dl.headers.get("content-type", "").startswith(
        "application/octet-stream") else None
    failures += not ok(body == data, "GET /v1/blobs/{t}/0 (download, byte-exact)")

    # -- coordination: encrypted deltas by geohash ------------------------
    print("\n[coordination]")
    cd = alice.post("/v1/coord/tzcvd/publish",
                    {"ttl_seconds": 3600,
                     "ciphertext": base64.b64encode(b"signed-crdt-delta").decode()})
    failures += not ok(cd.status_code == 201, "POST /v1/coord/{geohash}/publish")
    deltas = bob.get("/v1/coord/tzcvd").json()["deltas"]
    failures += not ok(len(deltas) >= 1, "GET /v1/coord/{geohash}")

    # -- SMS verification (open endpoints) --------------------------------
    print("\n[sms verification]")
    req = requests.post(f"{base}/v1/sms/request", json={"msisdn": "+15551230000"})
    failures += not ok(req.status_code == 201, "POST /v1/sms/request")
    # (the code arrives by SMS; in dev it's printed to the server log)
    bad = requests.post(f"{base}/v1/sms/verify",
                        json={"verification_id": req.json()["verification_id"],
                              "code": "000000"})
    failures += not ok(bad.status_code in (200, 400), "POST /v1/sms/verify")

    # -- NID / birth-certificate verification -----------------------------
    print("\n[id verification]")
    bc = {"doc_type": "birth_certificate",
          "fields": {"full_name": "Ayesha Rahman", "date_of_birth": "2001-04-17",
                     "birth_registration_number": "1998-1234567890"}}
    ing = alice.post("/v1/idv/document", bc)
    failures += not ok(ing.status_code == 201, "POST /v1/idv/document (ingest)")
    ver = alice.post("/v1/idv/verify", {"doc_type": "birth_certificate",
          "fields": {"full_name": "ayesha  RAHMAN", "date_of_birth": "17/04/2001",
                     "birth_registration_number": "1998 1234567890"}}).json()
    failures += not ok(ver.get("matched") is True,
                       "POST /v1/idv/verify (messy input still matches)")
    st = alice.get("/v1/idv/status").json()
    failures += not ok(st.get("verified") is True, "GET /v1/idv/status")

    print(f"\n== {'ALL PASSED' if failures == 0 else str(failures)+' FAILED'} ==")
    return failures


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    args = ap.parse_args()
    try:
        sys.exit(1 if smoke(args.base) else 0)
    except requests.exceptions.ConnectionError:
        print(f"Could not reach {args.base} — is the server running?")
        sys.exit(2)
