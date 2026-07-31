"""
Endpoints:
  POST /v1/idv/document   ingest an authoritative BC/NID record (operator-gated)
  POST /v1/idv/verify     match user-entered data against a stored document
  GET  /v1/idv/status     is the caller document-verified?
"""
from django.conf import settings
from rest_framework import status
from rest_framework.decorators import api_view, throttle_classes
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from .crypto import hash_field, hash_doc_number, seal_fields
from .models import IdentityDocument, DocumentVerification
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample, inline_serializer
from drf_spectacular.types import OpenApiTypes
from rest_framework import serializers as drf_serializers

from apps.common.openapi import AUTH_HEADERS
from .serializers import DocumentIngestSerializer, VerifyRequestSerializer, DOC_SCHEMA


class IdvThrottle(ScopedRateThrottle):
    scope = "idv"


def _operator_ok(request) -> bool:
    """Ingest of authoritative records should be restricted to authorised
    verifiers. If IDV_OPERATOR_KEY is set, require it in X-Operator-Key.
    If unset (dev), allow but the deployment is expected to set it in prod."""
    required = settings.IDV.get("OPERATOR_KEY", "")
    if not required:
        return True  # dev / open ingest
    return request.headers.get("X-Operator-Key", "") == required


@extend_schema(tags=["idverify"],
    summary="Store an authoritative BC/NID record (operator-gated)",
    parameters=AUTH_HEADERS + [OpenApiParameter("X-Operator-Key", OpenApiTypes.STR,
        OpenApiParameter.HEADER, required=False,
        description="Required when IDV_OPERATOR_KEY is configured.")],
    request=DocumentIngestSerializer,
    examples=[OpenApiExample("birth certificate", value={
        "doc_type": "birth_certificate", "fields": {
            "full_name": "Ayesha Rahman", "date_of_birth": "2001-04-17",
            "birth_registration_number": "1998-1234567890"}})],
    responses=inline_serializer("IdvStored", {
        "stored": drf_serializers.BooleanField(),
        "doc_type": drf_serializers.CharField(),
        "retained_encrypted": drf_serializers.BooleanField(),
        "fields_stored": drf_serializers.ListField(child=drf_serializers.CharField())}))
@api_view(["POST"])
@throttle_classes([IdvThrottle])
def ingest_document(request):
    """Store an authoritative BC/NID record as match-hashes + encrypted raw.

    Idempotent per (doc_type, document number): re-ingesting updates the record.
    """
    if not _operator_ok(request):
        return Response({"detail": "operator authorisation required"},
                        status=status.HTTP_403_FORBIDDEN)
    ser = DocumentIngestSerializer(data=request.data)
    ser.is_valid(raise_exception=True)
    doc_type = ser.validated_data["doc_type"]
    fields = ser.validated_data["fields"]
    num_field = DOC_SCHEMA[doc_type]["number_field"]

    fields_hash = {k: hash_field(k, v) for k, v in fields.items()}
    doc = IdentityDocument.objects.update_or_create(
        doc_type=doc_type,
        doc_number_hash=hash_doc_number(doc_type, fields[num_field]),
        defaults={
            "fields_hash": fields_hash,
            "enc_fields": seal_fields(fields),  # None in hash-only mode
        },
    )[0]
    return Response(
        {"stored": True, "doc_type": doc_type,
         "retained_encrypted": doc.enc_fields is not None,
         "fields_stored": sorted(fields.keys())},
        status=status.HTTP_201_CREATED,
    )


@extend_schema(tags=["idverify"],
    summary="Match user-entered data against a stored document",
    parameters=AUTH_HEADERS, request=VerifyRequestSerializer,
    responses=inline_serializer("IdvResult", {
        "matched": drf_serializers.BooleanField(),
        "fields": drf_serializers.DictField(child=drf_serializers.BooleanField(allow_null=True)),
        "required": drf_serializers.ListField(child=drf_serializers.CharField())}),
    examples=[OpenApiExample("verify", value={
        "doc_type": "birth_certificate", "fields": {
            "full_name": "ayesha rahman", "date_of_birth": "17/04/2001",
            "birth_registration_number": "1998 1234567890"}})])
@api_view(["POST"])
@throttle_classes([IdvThrottle])
def verify(request):
    """Match the caller's entered data against a stored document.

    Returns a per-field match map (booleans only — never the stored values) and
    an overall result. On a full match of the required fields, records a
    DocumentVerification for the authenticated identity.
    """
    ser = VerifyRequestSerializer(data=request.data)
    ser.is_valid(raise_exception=True)
    doc_type = ser.validated_data["doc_type"]
    entered = ser.validated_data["fields"]
    schema = DOC_SCHEMA[doc_type]
    num_field = schema["number_field"]

    dn_hash = hash_doc_number(doc_type, entered[num_field])
    doc = IdentityDocument.objects.filter(
        doc_type=doc_type, doc_number_hash=dn_hash
    ).first()
    if doc is None:
        # Do not distinguish "no such document" from "number mismatch" in a way
        # that enables enumeration beyond what the number itself implies.
        return Response({"matched": False, "reason": "no_document"},
                        status=status.HTTP_404_NOT_FOUND)

    per_field = {}
    for field, value in entered.items():
        stored = doc.fields_hash.get(field)
        if stored is None:
            per_field[field] = None  # field not on the stored document
        else:
            per_field[field] = (hash_field(field, value) == stored)

    required = schema["required_match"]
    all_required_match = all(per_field.get(f) is True for f in required)
    # Any explicitly-provided field that is present on the doc must also match.
    no_contradiction = all(v is not False for v in per_field.values())
    matched = all_required_match and no_contradiction

    if matched:
        DocumentVerification.objects.get_or_create(
            ed25519_pub=request.user.ed25519_pub,
            doc_type=doc_type, doc_number_hash=dn_hash,
        )

    return Response({
        "matched": matched,
        "fields": per_field,          # true / false / null(not on document)
        "required": required,
    })


@extend_schema(tags=["idverify"], summary="Is the caller document-verified?",
    parameters=AUTH_HEADERS,
    responses=inline_serializer("IdvStatus", {
        "verified": drf_serializers.BooleanField(),
        "verifications": drf_serializers.ListField(child=drf_serializers.DictField())}))
@api_view(["GET"])
@throttle_classes([IdvThrottle])
def verification_status(request):
    """Whether the authenticated identity has any recorded document match."""
    qs = DocumentVerification.objects.filter(
        ed25519_pub=request.user.ed25519_pub
    ).values("doc_type", "verified_at")
    return Response({"verified": bool(qs), "verifications": list(qs)})
