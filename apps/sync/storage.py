"""
Blob object storage (architecture §5: "S3-compatible object store for blob
fragments").

Large payloads (media, panic-vault, voice notes) are fragmented (§3.5, §7.3).
Storing that ciphertext as DB rows does not scale, so fragments live in object
storage; the DB keeps only routing metadata + the object key.

Two backends, selected by env (mirrors the SQLite/Postgres fallback):
  • S3Store    — any S3-compatible endpoint (AWS, MinIO, Wasabi...) via boto3.
                 Supports presigned PUT/GET so clients transfer bytes directly,
                 keeping ciphertext out of the Django process entirely.
  • LocalStore — filesystem under BLOB_ROOT for dev/CI; bytes are proxied
                 through the app. No AWS creds needed to run.

The store only ever handles OPAQUE CIPHERTEXT. It never decrypts anything.
"""
import os
from pathlib import Path

from django.conf import settings


class LocalStore:
    """Dev/CI filesystem store. Proxies bytes through the app (no presign)."""
    supports_presign = False

    def __init__(self):
        self.root = Path(settings.BLOB["LOCAL_ROOT"])
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        # Keys look like "transfer_id/idx"; keep them within root.
        p = (self.root / key).resolve()
        if not str(p).startswith(str(self.root.resolve())):
            raise ValueError("invalid blob key")
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def put(self, key: str, data: bytes) -> None:
        self._path(key).write_bytes(data)

    def get(self, key: str) -> bytes:
        return self._path(key).read_bytes()

    def delete(self, key: str) -> None:
        try:
            self._path(key).unlink()
        except FileNotFoundError:
            pass

    def presign_put(self, key: str):  # not supported locally
        return None

    def presign_get(self, key: str):
        return None


class S3Store:
    """Production object store. Prefers presigned URLs for direct transfer."""
    supports_presign = True

    def __init__(self):
        import boto3
        cfg = settings.BLOB
        self.bucket = cfg["S3_BUCKET"]
        self.expiry = cfg["S3_PRESIGN_TTL"]
        self.client = boto3.client(
            "s3",
            endpoint_url=cfg.get("S3_ENDPOINT") or None,
            region_name=cfg.get("S3_REGION") or None,
            aws_access_key_id=cfg.get("S3_KEY") or None,
            aws_secret_access_key=cfg.get("S3_SECRET") or None,
        )

    def put(self, key: str, data: bytes) -> None:
        self.client.put_object(Bucket=self.bucket, Key=key, Body=data)

    def get(self, key: str) -> bytes:
        return self.client.get_object(Bucket=self.bucket, Key=key)["Body"].read()

    def delete(self, key: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=key)

    def presign_put(self, key: str):
        return self.client.generate_presigned_url(
            "put_object", Params={"Bucket": self.bucket, "Key": key},
            ExpiresIn=self.expiry,
        )

    def presign_get(self, key: str):
        return self.client.generate_presigned_url(
            "get_object", Params={"Bucket": self.bucket, "Key": key},
            ExpiresIn=self.expiry,
        )


_store = None


def get_store():
    """Singleton store selected by settings.BLOB['BACKEND']."""
    global _store
    if _store is None:
        backend = settings.BLOB["BACKEND"]
        _store = S3Store() if backend == "s3" else LocalStore()
    return _store


def object_key(transfer_id: str, idx: int) -> str:
    return f"{transfer_id}/{idx}"
