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


class TwilioSender:
    """Sends the code via Twilio's Programmable Messaging API. Needs
    TWILIO_SID/TWILIO_TOKEN/TWILIO_FROM set (config/settings.py reads
    them from env) and SMS_SENDER=twilio to be selected by get_sender().
    """
    def __init__(self):
        cfg = settings.SMS
        self.sid = cfg.get("TWILIO_SID")
        self.token = cfg.get("TWILIO_TOKEN")
        self.from_ = cfg.get("TWILIO_FROM")
        if not (self.sid and self.token and self.from_):
            raise RuntimeError(
                "SMS_SENDER=twilio but TWILIO_SID/TWILIO_TOKEN/TWILIO_FROM "
                "are not all set"
            )

    def send_code(self, msisdn: str, code: str) -> bool:
        # Imported here, not at module load, so deployments that never
        # select the twilio backend don't need the package installed.
        from twilio.base.exceptions import TwilioRestException
        from twilio.rest import Client

        try:
            Client(self.sid, self.token).messages.create(
                to=msisdn,
                from_=self.from_,
                body=f"Your ProShetu verification code is: {code}",
            )
            return True
        except TwilioRestException:
            log.exception("Twilio send failed for %s...", msisdn[:4])
            return False


def get_sender():
    backend = settings.SMS["SENDER"]
    return TwilioSender() if backend == "twilio" else ConsoleSender()
