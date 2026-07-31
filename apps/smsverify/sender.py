"""
Pluggable SMS sender. Dev/CI uses a console backend (prints the code to logs);
production wires a real gateway (Twilio, an SMPP aggregator, or in-country
modem banks per §14). The sender only ever receives a phone number + short
code and returns success/failure — it holds no other state.
"""
import logging

from django.conf import settings

log = logging.getLogger("smsverify")


class ConsoleSender:
    """Dev backend: does not send anything; logs the code. NEVER use in prod."""
    def send_code(self, msisdn: str, code: str) -> bool:
        log.warning("[DEV SMS] code for %s...: %s", msisdn[:4], code)
        return True


class TwilioSender:  # skeleton — fill in credentials/client in deployment
    def __init__(self):
        cfg = settings.SMS
        self.sid = cfg.get("TWILIO_SID")
        self.token = cfg.get("TWILIO_TOKEN")
        self.from_ = cfg.get("TWILIO_FROM")

    def send_code(self, msisdn: str, code: str) -> bool:
        # from twilio.rest import Client
        # Client(self.sid, self.token).messages.create(
        #     to=msisdn, from_=self.from_, body=f"Your code: {code}")
        raise NotImplementedError("wire Twilio credentials in production")


def get_sender():
    backend = settings.SMS["SENDER"]
    return TwilioSender() if backend == "twilio" else ConsoleSender()
