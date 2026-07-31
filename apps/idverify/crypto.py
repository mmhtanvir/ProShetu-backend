"""
Normalisation, field hashing, and encryption helpers for ID/BC verification.

Two protections (architecture §6 posture applied to a PII-heavy feature):

  1. MATCH-HASHES: each document field is normalised then keyed-hashed
     (HMAC-BLAKE2b with a server pepper). Matching compares hashes, so the
     comparison never needs plaintext and a leaked hash table does not reveal
     names/DOBs/ID numbers by inspection.

  2. ENCRYPTED-AT-REST RAW: the actual field values ("store the info from the
     birth certificate") are kept, but sealed with libsodium SecretBox
     (XSalsa20-Poly1305) under a server key. The DB never holds plaintext ID
     documents; only a holder of IDV_ENC_KEY can recover them.

Normalisation note (honest limitation): matching is EXACT on normalised values.
Cross-script/transliteration name matching ("Md. Rahman" vs "Mohammad Rahman")
is deliberately NOT attempted — fuzzy identity matching is error-prone and
getting it wrong in a crisis context harms real people. Names are lower-cased,
whitespace-collapsed, diacritics stripped, and punctuation removed; dates are
parsed to ISO; numbers have separators stripped. Anything beyond that is a
policy decision for the deployment.
"""
import hashlib
import hmac
import json
import re
import unicodedata
from datetime import datetime

from django.conf import settings
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random


# ---- normalisation --------------------------------------------------------

_PUNCT = re.compile(r"[^\w\s]", flags=re.UNICODE)
_WS = re.compile(r"\s+")


def normalize_text(value: str) -> str:
    v = unicodedata.normalize("NFKD", str(value))
    v = "".join(c for c in v if not unicodedata.combining(c))  # drop diacritics
    v = v.casefold()
    v = _PUNCT.sub(" ", v)
    v = _WS.sub(" ", v).strip()
    return v


def normalize_number(value: str) -> str:
    return re.sub(r"[\s\-]", "", str(value)).casefold()


_DATE_FORMATS = ["%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y", "%m/%d/%Y",
                 "%d %b %Y", "%d %B %Y", "%Y/%m/%d"]


def normalize_date(value: str) -> str:
    s = str(value).strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(s, fmt).date().isoformat()
        except ValueError:
            continue
    # last resort: keep digits in order (won't match unless caller is consistent)
    return re.sub(r"[^\d]", "", s)


# Which normaliser applies to which field.
_NUMBER_FIELDS = {"nid_number", "birth_registration_number", "doc_number"}
_DATE_FIELDS = {"date_of_birth", "dob"}


def normalize_field(field: str, value: str) -> str:
    if field in _NUMBER_FIELDS:
        return normalize_number(value)
    if field in _DATE_FIELDS:
        return normalize_date(value)
    return normalize_text(value)


# ---- match hashing --------------------------------------------------------

def hash_field(field: str, value: str) -> str:
    pepper = settings.IDV["PEPPER"].encode()
    norm = normalize_field(field, value)
    msg = f"{field}:{norm}".encode()
    return hmac.new(pepper, msg, hashlib.blake2b).hexdigest()[:64]


def hash_doc_number(doc_type: str, number: str) -> str:
    pepper = settings.IDV["PEPPER"].encode()
    msg = f"{doc_type}:{normalize_number(number)}".encode()
    return hmac.new(pepper, msg, hashlib.blake2b).hexdigest()[:64]


# ---- encryption at rest ---------------------------------------------------

def _enc_key():
    key_hex = settings.IDV.get("ENC_KEY", "")
    if not key_hex:
        return None
    raw = bytes.fromhex(key_hex)
    if len(raw) != SecretBox.KEY_SIZE:
        raise ValueError("IDV_ENC_KEY must be 32 bytes hex")
    return raw


def seal_fields(fields: dict) -> bytes | None:
    """Encrypt the raw field dict. Returns None if no key configured
    (hash-only mode — the info is matched but not retained in recoverable form).
    """
    key = _enc_key()
    if key is None:
        return None
    box = SecretBox(key)
    plaintext = json.dumps(fields, ensure_ascii=False, sort_keys=True).encode()
    nonce = nacl_random(SecretBox.NONCE_SIZE)
    return box.encrypt(plaintext, nonce)  # nonce is prepended by PyNaCl


def open_fields(blob: bytes) -> dict:
    key = _enc_key()
    if key is None:
        raise ValueError("no IDV_ENC_KEY configured")
    box = SecretBox(key)
    return json.loads(box.decrypt(bytes(blob)).decode())
