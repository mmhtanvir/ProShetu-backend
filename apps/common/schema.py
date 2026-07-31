"""
Register the custom signature auth with drf-spectacular so schema generation
resolves it instead of warning. The three signing headers are documented via
apps.common.openapi.AUTH_HEADERS on each authed view; here we simply declare an
apiKey-style scheme keyed on X-Signature so the OpenAPI 'security' requirement
is satisfied.

Importing this module registers the extension (drf-spectacular discovers
subclasses of OpenApiAuthenticationExtension at import time).
"""
from drf_spectacular.extensions import OpenApiAuthenticationExtension


class SignatureAuthScheme(OpenApiAuthenticationExtension):
    target_class = "apps.common.auth.SignatureAuthentication"
    name = "SignatureAuth"

    def get_security_definition(self, auto_schema):
        return {
            "type": "apiKey",
            "in": "header",
            "name": "X-Signature",
            "description": (
                "Ed25519 signature over a challenge nonce. Also send X-Identity "
                "and X-Nonce (see the header parameters on each endpoint). Get a "
                "nonce from GET /v1/challenge; challenges are single-use."
            ),
        }
