# API Testing Guide

Two ways to exercise the running API: **curl** (fine for open endpoints, awkward
for authed ones) and the **signing client** at `scripts/api_client.py` (handles
auth for you — recommended).

## 1. Start the server

From the project root:

```bash
# ASGI server (needed for WebSocket push + calling). Set an IDV key so the
# id-verification endpoints retain encrypted data; omit it for hash-only mode.
export IDV_ENC_KEY=$(python3 -c "import os;print(os.urandom(32).hex())")
daphne -b 127.0.0.1 -p 8000 config.asgi:application
```

(`python manage.py runserver` also works for the REST endpoints, but use daphne
if you want to test the WebSocket at `/ws/push`.)

## 2. Fastest check — the signing client

```bash
pip install requests
python scripts/api_client.py --base http://127.0.0.1:8000
```

It registers two virtual devices and walks every endpoint (sync, calling,
blobs, coordination, SMS, ID verification), printing PASS/FAIL per call and
`ALL PASSED` at the end. Use the `Client` class inside it to poke individual
endpoints from a REPL:

```python
from scripts.api_client import Client
a = Client("http://127.0.0.1:8000"); a.register()
print(a.get("/v1/idv/status").json())
```

## 3. curl — the auth model

Authenticated requests need three headers, and the challenge is **single-use**
(you fetch a fresh one per request):

```
X-Identity : <ed25519 public key, hex>
X-Nonce    : <nonce from GET /v1/challenge>
X-Signature: <hex Ed25519 signature over the nonce bytes>
```

### Open endpoints (no signing) — pure curl

```bash
# health
curl -s http://127.0.0.1:8000/healthz

# register an identity (returns a mailbox_id)
curl -s -X POST http://127.0.0.1:8000/v1/register \
  -H 'Content-Type: application/json' \
  -d '{"ed25519_pub":"<64-hex>","x25519_pub":"<64-hex>"}'

# request an auth challenge for a pubkey
curl -s "http://127.0.0.1:8000/v1/challenge?pub=<64-hex>"

# SMS verification (open)
curl -s -X POST http://127.0.0.1:8000/v1/sms/request \
  -H 'Content-Type: application/json' -d '{"msisdn":"+15551230000"}'
```

### An authed call in one shell snippet (bash + python for the signing)

Signing needs the private key, so pure curl can't do it alone. This helper
prints ready-to-paste headers for a key you generate:

```bash
python3 - <<'PY'
import requests
from nacl.signing import SigningKey
from nacl.public import PrivateKey
BASE="http://127.0.0.1:8000"
s=SigningKey.generate(); d=PrivateKey.generate()
ed=s.verify_key.encode().hex(); x=bytes(d.public_key).hex()
requests.post(f"{BASE}/v1/register",json={"ed25519_pub":ed,"x25519_pub":x})
n=requests.get(f"{BASE}/v1/challenge",params={"pub":ed}).json()["nonce"]
sig=s.sign(n.encode()).signature.hex()
print(f"-H 'X-Identity: {ed}' -H 'X-Nonce: {n}' -H 'X-Signature: {sig}'")
PY
# copy the printed headers into e.g.:
# curl -s -X POST http://127.0.0.1:8000/v1/sync \
#   -H 'Content-Type: application/json' <PASTE HEADERS> -d '{"carrying":[]}'
```

## 4. Postman / Insomnia

Import the endpoints from the API table in `README.md`. For authed requests,
add a pre-request script that (a) GETs `/v1/challenge`, (b) signs the nonce with
tweetnacl, and (c) sets the three headers. If that's more work than it's worth,
just use `scripts/api_client.py` — it already does exactly this.

## 5. WebSocket (`/ws/push`)

```bash
pip install websocket-client
python3 - <<'PY'
import requests, websocket, json
from nacl.signing import SigningKey; from nacl.public import PrivateKey
BASE="http://127.0.0.1:8000"; WS="ws://127.0.0.1:8000/ws/push"
s=SigningKey.generate(); d=PrivateKey.generate()
ed=s.verify_key.encode().hex()
requests.post(f"{BASE}/v1/register",json={"ed25519_pub":ed,"x25519_pub":bytes(d.public_key).hex()})
n=requests.get(f"{BASE}/v1/challenge",params={"pub":ed}).json()["nonce"]
sig=s.sign(n.encode()).signature.hex()
ws=websocket.create_connection(f"{WS}?identity={ed}&nonce={n}&signature={sig}")
print("connected:", json.loads(ws.recv()))   # {"type":"ready"}
PY
```

To see a push arrive, have a second client send you a `/v1/call/signal` while
this socket is open.
```
