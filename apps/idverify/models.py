"""
NID / birth-certificate verification (isolated, optional).

Flow:
  1. An authoritative document record is stored (the "info from the birth
     certificate" / NID) — from OCR of an uploaded document, a registry lookup,
     or an authorised operator keying it in. See views.ingest_document.
       -> stored as: match-hashes per field + encrypted-at-rest raw fields,
          keyed by a hashed document number.
  2. A user submits the data THEY entered during onboarding, plus the document
     number. The server matches their entered fields against the stored
     document's hashes and records a verification if they match.

ISOLATION / PRIVACY (read this):
  • This module is the ONLY place identity-document data lives, kept separate
    from the zero-knowledge sync core, exactly like the SMS module.
  • The DB never stores plaintext ID data — only peppered hashes (for matching)
    and SecretBox-encrypted raw (recoverable only with IDV_ENC_KEY).
  • Verification is OPTIONAL and must NEVER gate distress/SOS or basic
    messaging. Many crisis, protest, and displaced users have no papers or must
    not surface them. It exists to let deployments mark "document-verified
    responder/volunteer" where that is genuinely required.
  • Collecting national-ID data is legally regulated (data-protection law);
    that is a deployment/compliance responsibility, flagged here.
"""
from django.db import models


class IdentityDocument(models.Model):
    DOC_TYPES = [("birth_certificate", "birth_certificate"), ("nid", "nid")]

    doc_type = models.CharField(max_length=20, choices=DOC_TYPES)
    # HMAC of the normalised document number — the lookup key. Never the raw No.
    doc_number_hash = models.CharField(max_length=64, db_index=True)
    # {field_name: hmac_hash} for every stored field (incl. the number).
    fields_hash = models.JSONField(default=dict)
    # SecretBox-encrypted JSON of the raw fields; NULL in hash-only mode.
    enc_fields = models.BinaryField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("doc_type", "doc_number_hash")


class DocumentVerification(models.Model):
    """Records that a proven identity matched a stored document.

    Tied to the Ed25519 identity that authenticated the verify call. Stores no
    document contents — just which (hashed) document was matched and when — so
    this table does not re-expose PII.
    """
    ed25519_pub = models.CharField(max_length=64, db_index=True)
    doc_type = models.CharField(max_length=20)
    doc_number_hash = models.CharField(max_length=64)
    verified_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("ed25519_pub", "doc_type", "doc_number_hash")
