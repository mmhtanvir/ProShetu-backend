from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, inline_serializer
from rest_framework import serializers as drf_serializers


@extend_schema(tags=["health"], summary="Liveness probe", auth=[],
    responses=inline_serializer("Health", {"status": drf_serializers.CharField()}))
@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def healthz(request):
    """Liveness probe. Reveals nothing about state or identities."""
    return Response({"status": "ok"})
