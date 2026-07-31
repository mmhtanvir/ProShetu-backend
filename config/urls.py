from django.urls import path, include
from drf_spectacular.views import (
    SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView,
)

urlpatterns = [
    path("v1/", include("apps.directory.urls")),
    path("v1/", include("apps.sync.urls")),
    path("v1/", include("apps.coordination.urls")),
    path("v1/", include("apps.calling.urls")),
    path("v1/", include("apps.smsverify.urls")),
    path("v1/", include("apps.idverify.urls")),
    path("healthz", include("apps.common.urls")),

    # OpenAPI schema + interactive docs
    path("api/schema", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    path("api/redoc", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
]
