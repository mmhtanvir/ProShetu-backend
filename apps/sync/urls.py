from django.urls import path
from . import views

urlpatterns = [
    path("sync", views.sync, name="sync"),
    path("ack", views.ack, name="ack"),
]

from . import blob_views  # noqa: E402

urlpatterns += [
    path("blobs/<str:transfer_id>", blob_views.transfer_manifest, name="blob-manifest"),
    path("blobs/<str:transfer_id>/<int:idx>/register", blob_views.register_fragment, name="blob-register"),
    path("blobs/<str:transfer_id>/<int:idx>/complete", blob_views.complete_fragment, name="blob-complete"),
    path("blobs/<str:transfer_id>/<int:idx>/upload", blob_views.upload_fragment, name="blob-upload"),
    path("blobs/<str:transfer_id>/<int:idx>", blob_views.download_fragment, name="blob-download"),
]
