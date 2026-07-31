# Crisis Platform — Backend (Django / DRF / PostgreSQL)

The **optional** super-node for the offline-first crisis platform. The system
works with zero backend; this service only improves reach and sync when IP
connectivity exists. It is an **honest-but-curious, zero-knowledge**
store-and-forward node: it holds **ciphertext only**, never keys, and cannot
read any payload.

Maps to the architecture doc: §5 (backend), §6 (security), §10 (schema),
§11 (API), §13 (coordination).

## What this backend is (and is not)

- **Is:** a very well-connected mesh peer. It runs the *same* reconciliation
  protocol the devices run over Bluetooth/Wi-Fi (`/v1/sync`), so there is one
  sync engine, three transports.
- **Is:** a directory (identities + X3DH prekeys) and a coordination fan-out
  keyed by coarse geohash.
- **Is not:** an account system. There are no passwords and no sessions.
  Identity is an Ed25519 public key, proven per-request by signing a
  short-lived server challenge.
- **Is not:** able to read messages, media, vault data, voice, or coordination
  content. All of that is end-to-end encrypted on the client.

## Quick start (dev)

```bash
pip install -r requirements.txt
python manage.py migrate            # SQLite fallback, no config needed
python manage.py test               # 9 tests: auth, sync, dedup, bloom, coord
python manage.py runserver
```

For production set the PostgreSQL env vars in `.env` (see `.env.example`);
supplying any `POSTGRES_*` switches off the SQLite dev fallback. Serve with
`gunicorn config.wsgi` behind TLS 1.3 with certificate pinning at the client.

## Interactive API docs (Swagger / OpenAPI)

With the server running, open:

- **Swagger UI:** http://localhost:8000/api/docs  (browse every endpoint, see
  request/response schemas and example payloads)
- **ReDoc:** http://localhost:8000/api/redoc
- **Raw schema:** http://localhost:8000/api/schema  (OpenAPI 3, YAML)

Endpoints are grouped by tag (directory, sync, calling, blobs, coordination,
sms, idverify). Authed endpoints show the required `X-Identity` / `X-Nonce` /
`X-Signature` headers. Note: Swagger's "Try it out" cannot sign requests for
you (signing needs your Ed25519 private key) — use `scripts/api_client.py` to
actually call authed routes. Generate a static schema file with:

```bash
python manage.py spectacular --file schema.yaml
```

## Auth model (signature challenge/response)

```
GET  /v1/challenge?pub=<ed25519_hex>      -> { "nonce": "..." }        # single use
# client signs nonce bytes with its Ed25519 private key (libsodium)
<any authed request> with headers:
  X-Identity : <ed25519 public key, hex>
  X-Nonce    : <the issued nonce>
  X-Signature: <hex signature over the nonce bytes>
```

Verification uses PyNaCl (libsodium) only — no custom crypto. Challenges are
single-use and expire in 120s, so a captured request cannot be replayed.

## API surface (§11)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET  | `/healthz` | no | liveness |
| GET  | `/v1/challenge?pub=` | no | issue auth nonce |
| POST | `/v1/register` | no | create/return directory identity |
| POST | `/v1/prekeys` | yes | upload this identity's X3DH bundle |
| GET  | `/v1/prekeys/{mailbox_id}` | yes | fetch a peer's bundle (pops one OTK) |
| POST | `/v1/sync` | yes | **core**: push carried events, pull yours |
| POST | `/v1/ack` | yes | confirm storage so server can GC |
| POST | `/v1/coord/{geohash}/publish` | yes | publish encrypted coordination delta |
| GET  | `/v1/coord/{geohash}` | yes | fetch shard deltas (`?since=`) |
| POST | `/v1/call/signal` | yes | relay one sealed call signal (both-online) |
| GET  | `/v1/call/poll` | yes | pull pending call signals (WS fallback) |
| POST | `/v1/blobs/{transfer}/{idx}/register` | yes | register fragment; get presigned PUT (S3) |
| PUT  | `/v1/blobs/{transfer}/{idx}/upload` | yes | dev proxy upload (local store) |
| POST | `/v1/blobs/{transfer}/{idx}/complete` | yes | mark presigned upload done (S3) |
| GET  | `/v1/blobs/{transfer}` | yes | transfer manifest (which idx present) |
| GET  | `/v1/blobs/{transfer}/{idx}` | yes | presigned GET (S3) or bytes (local) |
| POST | `/v1/sms/request` | no | send SMS verification code (hash stored) |
| POST | `/v1/sms/verify` | no | verify code → single-use registration token |
| POST | `/v1/idv/document` | yes* | store authoritative BC/NID record (operator-gated) |
| POST | `/v1/idv/verify` | yes | match user-entered data against a stored document |
| GET  | `/v1/idv/status` | yes | is the caller document-verified? |
| WS   | `/ws/push?identity=&nonce=&signature=` | yes | live push (event/call hints) |

### `/v1/sync` request/response shape

```jsonc
// request
{
  "carrying":  [ { "event_id","recipient_mailbox","priority","ttl_seconds","ciphertext(b64)" } ],
  "fragments": [ { "transfer_id","idx","count","recipient_mailbox","priority","ttl_seconds","ciphertext(b64)" } ],
  "receipts":  [ { "event_id","recipient_mailbox","ttl_seconds","ciphertext(b64)" } ],
  "bloom_m": 4096, "bloom_k": 7, "bloom_bits": "<hex>",   // filter of ids client holds
  "want": [ "<event_id>", ... ]                            // false-positive repair
}
// response
{
  "accepted": [ "<event_id>", ... ],
  "deliver":  [ { "event_id","priority","size_bucket","ciphertext(b64)","ttl_expires_at" } ],
  "receipts": [ { "event_id","ciphertext(b64)" } ],
  "want": []
}
```

## Zero-knowledge / metadata-minimization choices

- **Sealed sender:** stored events carry only the *recipient* mailbox; the
  sender identity lives inside the ciphertext (§5).
- **Content addressing:** `event_id = BLAKE2b-128(ciphertext)`. The server
  verifies this on ingest, making ids unforgeable and dedup exact. Same ids the
  mesh uses, so backend and mesh dedupe against each other for free.
- **Size buckets:** the server records only a coarse size class, never exact
  length (§7.1). TTLs are clamped to per-priority ceilings (§1.4).
- **Coarse geohash:** coordination shards truncate to ~5 km precision
  server-side; a client cannot smuggle a precise location into the topic.
- **No per-request logs:** abuse control is aggregate rate-limit counters
  (`apps.common.RateBucket`), not an audit trail of who synced when.
- **Short retention:** `python manage.py gc` (run on a schedule) drops expired
  or delivered ciphertext and consumed challenges, mirroring mesh relay GC.

## Layout

```
config/            settings, urls, wsgi/asgi
apps/common/       signature auth, challenges, validators, health, rate buckets
apps/directory/    Identity + PreKeyBundle (X3DH), register, challenge, prekeys
apps/sync/         Event / BlobFragment / Receipt, /sync reconciliation, bloom, gc
apps/coordination/ encrypted CRDT deltas sharded by coarse geohash
```

## Calling (signalling relay) — `apps/calling`

The backend has **no voice-media path and no WebRTC** — media stays
peer-to-peer over the mesh, encrypted with libsodium (§4.1). The only call role
here is relaying small **sealed signalling** blobs (ring/offer/answer/hangup/
candidate) for the case where two peers both have internet but aren't on the
same local mesh. Signals are ephemeral (≤90s TTL), deleted on delivery, and the
server never sees keys, the SAS, or media. When the callee holds a live
WebSocket, a ring is pushed instantly; otherwise it's picked up on `/call/poll`.

## Blob object storage — `apps/sync/storage.py`

Large payload fragments (media, vault, voice notes) live in an **S3-compatible
object store**, not the DB. The `BlobFragment` row keeps only routing metadata +
an `object_key`. Two backends, chosen by env (like the SQLite/Postgres
fallback): `S3Store` (boto3, presigned PUT/GET so ciphertext bypasses the app)
and `LocalStore` (filesystem, dev/CI, no creds). Set `BLOB_BACKEND=s3` + `S3_*`
for prod. Fragments are opaque ciphertext; the store never decrypts.

## WebSocket push — `apps/common/consumers.py` (Django Channels)

`/ws/push` holds one authenticated socket per client so the server can push
tiny "wake up and sync/poll" hints the instant something arrives — new events
and, importantly, low-latency call rings. Auth reuses the **same signature
challenge**: the client passes `identity/nonce/signature` as query params and
the consumer verifies with PyNaCl before joining the mailbox group. Only hints
cross the socket (event_id, call_id, kind) — never plaintext; ciphertext is
still fetched over REST. Dev uses the in-memory channel layer; set `REDIS_URL`
for the Redis layer across workers in prod. Serve with `daphne config.asgi`.

## SMS verification — `apps/smsverify` (isolated)

Optional registration anti-abuse (§14), **off by default** because crisis users
often have no phone service. `POST /v1/sms/request` sends a 6-digit code (dev:
console/log sender; prod: Twilio/SMPP hook) and stores only a **keyed hash of
the number** (HMAC-BLAKE2b with a server pepper) — the raw MSISDN is never
persisted. `POST /v1/sms/verify` checks the code (also stored hashed, attempt-
limited) and issues a **single-use registration token**. Enable
`REQUIRE_SMS_VERIFICATION=1` to make `/v1/register` require that token; the
token is consumed and its phone association discarded, so an identity is never
bound to a phone number in anything the sync core can read.

## NID / birth-certificate verification — `apps/idverify` (isolated, optional)

Stores an authoritative BC/NID record and checks that the data a user entered
matches it. Two-step: (1) `POST /v1/idv/document` ingests the document's fields
(from OCR, a registry lookup, or an authorised operator) — gated by
`X-Operator-Key` when `IDV_OPERATOR_KEY` is set; (2) `POST /v1/idv/verify` takes
the user-entered fields, locates the document by its (hashed) number, and
returns a per-field match map plus an overall result, recording a verification
for the caller's identity on success.

**How the info is stored (deliberately not plaintext).** Applying the system's
threat model to a PII-heavy feature, each field is kept two ways: a peppered
**HMAC-BLAKE2b match-hash** (so comparison never needs plaintext) and, if
`IDV_ENC_KEY` (32-byte hex) is set, the raw fields **encrypted with libsodium
SecretBox** (XSalsa20-Poly1305). So "the info from the birth certificate" is
retained and recoverable *only* with the key — the DB itself never holds a
plaintext registry of names/DOBs/ID numbers. Without a key it runs hash-only
(matches, retains nothing recoverable). `DocumentVerification` records store no
document contents, only which hashed document matched and when.

**Matching is exact on normalised values** — case/whitespace-insensitive,
diacritics stripped, dates parsed to ISO, ID numbers de-separated. Cross-script
/ transliteration fuzzy matching is intentionally **not** attempted; getting
identity matching wrong in a crisis harms real people, so that is left as an
explicit deployment policy decision.

**Non-negotiable scope:** this is **optional** and must **never** gate
distress/SOS or basic messaging. Many crisis, protest, and displaced users have
no papers or must not surface them. Collecting government-ID data is legally
regulated (data-protection law) — a deployment/compliance responsibility.

## Still not built (honest scope — next steps)

- **`/v1/stream` semantics beyond hints** — the socket currently pushes
  notifications; the client still pulls ciphertext over REST (by design). Full
  payload push could be added but widens the socket's data exposure.
- **USSD** — carrier-partnership dependent (§14); out of scope here.
- **Proof-of-work registration** — an alternative to SMS gating; hook exists at
  `/v1/register`, not implemented.
- **Contact-discovery oblivious lookup** — deferred; best-effort per the design.

Run `python manage.py test` — **17 tests** cover auth, sync, dedup, bloom,
coordination, calling, blob transfer, WebSocket push, and SMS verification.

See `../crisis-platform-architecture.md` for the full system design.
