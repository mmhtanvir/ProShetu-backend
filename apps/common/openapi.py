"""Shared drf-spectacular helpers.

AUTH_HEADERS documents the three signature-auth headers so they appear as
inputs in Swagger UI on authenticated endpoints. (Signing still has to happen
client-side — see scripts/api_client.py — but this makes the contract visible.)
"""
from drf_spectacular.utils import OpenApiParameter
from drf_spectacular.types import OpenApiTypes

AUTH_HEADERS = [
    OpenApiParameter(
        "X-Identity", OpenApiTypes.STR, OpenApiParameter.HEADER,
        required=True, description="Ed25519 public key, hex (32 bytes)."),
    OpenApiParameter(
        "X-Nonce", OpenApiTypes.STR, OpenApiParameter.HEADER,
        required=True, description="Nonce from GET /v1/challenge (single-use)."),
    OpenApiParameter(
        "X-Signature", OpenApiTypes.STR, OpenApiParameter.HEADER,
        required=True, description="Hex Ed25519 signature over the nonce bytes."),
]
