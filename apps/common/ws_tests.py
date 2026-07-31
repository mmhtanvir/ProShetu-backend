"""WebSocket push tests using Channels' in-memory communicator."""
from channels.testing import WebsocketCommunicator
from channels.db import database_sync_to_async
from django.test import TransactionTestCase
from nacl.signing import SigningKey
from nacl.public import PrivateKey

from config.asgi import application
from apps.common.push import push_to_mailbox


@database_sync_to_async
def _register():
    from apps.directory.models import Identity
    from apps.common.models import Challenge
    sign = SigningKey.generate()
    dh = PrivateKey.generate()
    ed = sign.verify_key.encode().hex()
    ident = Identity.objects.create(ed25519_pub=ed, x25519_pub=bytes(dh.public_key).hex())
    return sign, ed, str(ident.mailbox_id)


@database_sync_to_async
def _challenge(ed):
    from apps.common.models import Challenge
    return Challenge.issue(ed).nonce


class PushConsumerTests(TransactionTestCase):
    async def _connect(self, sign, ed):
        nonce = await _challenge(ed)
        sig = sign.sign(nonce.encode()).signature.hex()
        url = f"/ws/push?identity={ed}&nonce={nonce}&signature={sig}"
        comm = WebsocketCommunicator(application, url)
        connected, _ = await comm.connect()
        return comm, connected

    async def test_authed_socket_receives_push(self):
        sign, ed, mailbox = await _register()
        comm, connected = await self._connect(sign, ed)
        self.assertTrue(connected)
        ready = await comm.receive_json_from()
        self.assertEqual(ready["type"], "ready")

        # Server pushes a hint to this mailbox -> socket receives it.
        await database_sync_to_async(push_to_mailbox)(
            mailbox, {"type": "call_signal", "call_id": "ring1", "kind": "offer"}
        )
        msg = await comm.receive_json_from()
        self.assertEqual(msg["type"], "call_signal")
        self.assertEqual(msg["call_id"], "ring1")
        await comm.disconnect()

    async def test_bad_signature_rejected(self):
        sign, ed, mailbox = await _register()
        nonce = await _challenge(ed)
        wrong = SigningKey.generate()
        sig = wrong.sign(nonce.encode()).signature.hex()  # wrong key
        comm = WebsocketCommunicator(
            application, f"/ws/push?identity={ed}&nonce={nonce}&signature={sig}"
        )
        connected, _ = await comm.connect()
        self.assertFalse(connected)

    async def test_missing_credentials_rejected(self):
        comm = WebsocketCommunicator(application, "/ws/push")
        connected, _ = await comm.connect()
        self.assertFalse(connected)
