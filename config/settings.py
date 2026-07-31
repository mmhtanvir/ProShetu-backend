"""
Django settings for the Crisis Communication Platform backend.

Design posture (see architecture doc §5, §6):
  - The backend is an HONEST-BUT-CURIOUS store-and-forward super-node.
  - It stores CIPHERTEXT ONLY. It never holds keys and cannot read payloads.
  - Auth is signature-based (Ed25519 challenge/response). No passwords,
    no server-side sessions to steal.
  - Data minimization: no per-request user logging; retention is short and
    driven by delivery/TTL, mirroring how mesh relays behave.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "dev-insecure-change-me")
DEBUG = os.getenv("DJANGO_DEBUG", "1") == "1"
ALLOWED_HOSTS = os.getenv("DJANGO_ALLOWED_HOSTS", "*").split(",")

INSTALLED_APPS = [
    "daphne",
    "channels",
    "django.contrib.contenttypes",
    "django.contrib.staticfiles",
    # NOTE: no auth/sessions/admin — we deliberately avoid cookie sessions and
    # server-side user accounts. Identity is a public key, proven per-request.
    "rest_framework",
    "apps.common",
    "apps.directory",
    "apps.sync",
    "apps.coordination",
    "apps.calling",
    "apps.smsverify",
    "apps.idverify",
    "drf_spectacular",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    # Intentionally NO SessionMiddleware / CsrfMiddleware / AuthenticationMiddleware:
    # this API is stateless and signature-authenticated.
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [],
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": []},
}]

# --- Database -------------------------------------------------------------
# Prod: PostgreSQL. Dev/CI: SQLite fallback so the project runs anywhere.
if os.getenv("DATABASE_URL") or os.getenv("POSTGRES_DB"):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("POSTGRES_DB", "crisis"),
            "USER": os.getenv("POSTGRES_USER", "crisis"),
            "PASSWORD": os.getenv("POSTGRES_PASSWORD", ""),
            "HOST": os.getenv("POSTGRES_HOST", "localhost"),
            "PORT": os.getenv("POSTGRES_PORT", "5432"),
            "CONN_MAX_AGE": 60,
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "dev.sqlite3",
        }
    }

# --- DRF ------------------------------------------------------------------
REST_FRAMEWORK = {
    # Every endpoint authenticates by verifying an Ed25519 signature over a
    # server-issued challenge (see apps/common/auth.py).
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "apps.common.auth.SignatureAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.ScopedRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "register": "20/hour",
        "sync": "600/hour",
        "challenge": "600/hour",
        "coord": "600/hour",
        "call": "1200/hour",
        "sms": "10/hour",
        "idv": "60/hour",
    },
    "UNAUTHENTICATED_USER": None,
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

# --- Blob object storage (architecture §5) --------------------------------
# Dev/CI: local filesystem (no creds). Prod: set BLOB_BACKEND=s3 + S3_* vars.
BLOB = {
    "BACKEND": os.getenv("BLOB_BACKEND", "local"),   # "local" | "s3"
    "LOCAL_ROOT": os.getenv("BLOB_LOCAL_ROOT", str(BASE_DIR / "blobstore")),
    "S3_BUCKET": os.getenv("S3_BUCKET", ""),
    "S3_ENDPOINT": os.getenv("S3_ENDPOINT", ""),     # e.g. MinIO URL; blank=AWS
    "S3_REGION": os.getenv("S3_REGION", ""),
    "S3_KEY": os.getenv("S3_KEY", ""),
    "S3_SECRET": os.getenv("S3_SECRET", ""),
    "S3_PRESIGN_TTL": int(os.getenv("S3_PRESIGN_TTL", "900")),
}

# --- OpenAPI / Swagger (drf-spectacular) ----------------------------------
SPECTACULAR_SETTINGS = {
    "TITLE": "Crisis Communication Platform API",
    "DESCRIPTION": (
        "Zero-knowledge store-and-forward backend for the offline-first crisis "
        "platform. The server holds CIPHERTEXT ONLY and never sees keys.\n\n"
        "AUTH: most endpoints require a signature challenge. Call "
        "`GET /v1/challenge?pub=<ed25519_hex>`, sign the returned nonce with "
        "your Ed25519 key, then send three headers: `X-Identity`, `X-Nonce`, "
        "`X-Signature`. Challenges are single-use. Browser 'Try it out' cannot "
        "sign for you \u2014 use scripts/api_client.py to exercise authed routes."
    ),
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "COMPONENT_SPLIT_REQUEST": True,
    "TAGS": [
        {"name": "directory", "description": "Identities, prekeys, auth challenge"},
        {"name": "sync", "description": "Store-and-forward event reconciliation"},
        {"name": "calling", "description": "Sealed call-signalling relay (no media)"},
        {"name": "blobs", "description": "Object-store fragment transfer"},
        {"name": "coordination", "description": "Encrypted CRDT deltas by geohash"},
        {"name": "sms", "description": "Optional SMS registration verification"},
        {"name": "idverify", "description": "Optional NID / birth-certificate match"},
        {"name": "health", "description": "Liveness"},
    ],
}

# --- Platform tunables (architecture §1.4, §3, §5) ------------------------
PLATFORM = {
    # TTL ceilings (seconds) by priority class. Server refuses longer TTLs.
    "TTL_MAX": {0: 72 * 3600, 1: 48 * 3600, 2: 7 * 24 * 3600, 3: 72 * 3600},
    # Challenge validity window for signature auth.
    "CHALLENGE_TTL": 120,
    # Max events accepted per /sync push.
    "SYNC_MAX_EVENTS": 500,
    # Coordination geohash precision the server shards on (coarse = ~5km).
    "COORD_GEOHASH_LEN": 5,
    # Size buckets (bytes) the server enforces for padding uniformity (§7.1).
    "SIZE_BUCKETS": [512, 2048, 8192, 32768, 131072, 1048576],
}

# --- NID / birth-certificate verification (isolated, optional; §6) ---------
# OPTIONAL and never a gate for distress/SOS or basic messaging. Stores only
# peppered match-hashes + SecretBox-encrypted raw fields (needs IDV_ENC_KEY, a
# 32-byte hex key, to retain recoverable raw data; without it, hash-only mode).
# Collecting government-ID data is legally regulated — a deployment concern.
IDV = {
    "PEPPER": os.getenv("IDV_PEPPER", "dev-insecure-idv-pepper"),
    "ENC_KEY": os.getenv("IDV_ENC_KEY", ""),        # 32-byte hex; blank=hash-only
    "OPERATOR_KEY": os.getenv("IDV_OPERATOR_KEY", ""),  # gate document ingest
}

# --- SMS verification (isolated; architecture §14) ------------------------
# OPTIONAL. Crisis users may have no phone service, so gating registration on
# SMS is a deployment choice, off by default. The raw MSISDN is never stored;
# only a keyed hash (needs SMS_PEPPER set in prod).
SMS = {
    "REQUIRE_SMS_VERIFICATION": os.getenv("REQUIRE_SMS_VERIFICATION", "0") == "1",
    "SENDER": os.getenv("SMS_SENDER", "console"),   # "console" | "twilio"
    "PEPPER": os.getenv("SMS_PEPPER", "dev-insecure-sms-pepper"),
    "CODE_TTL": int(os.getenv("SMS_CODE_TTL", "600")),    # 10 min
    "TOKEN_TTL": int(os.getenv("SMS_TOKEN_TTL", "600")),  # 10 min
    "TWILIO_SID": os.getenv("TWILIO_SID", ""),
    "TWILIO_TOKEN": os.getenv("TWILIO_TOKEN", ""),
    "TWILIO_FROM": os.getenv("TWILIO_FROM", ""),
}

# --- Channels / WebSocket push --------------------------------------------
# Dev/CI: in-memory layer (single process). Prod: Redis across workers.
if os.getenv("REDIS_URL"):
    CHANNEL_LAYERS = {
        "default": {
            "BACKEND": "channels_redis.core.RedisChannelLayer",
            "CONFIG": {"hosts": [os.getenv("REDIS_URL")]},
        }
    }
else:
    CHANNEL_LAYERS = {
        "default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}
    }

# --- Logging: deliberately minimal, no request/identity logging -----------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": "WARNING"},
    # No access logs tying identities to requests are configured here; abuse
    # control is rate-limit counters only (apps.common), not per-user logs.
}

STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
USE_TZ = True
TIME_ZONE = "UTC"
LANGUAGE_CODE = "en-us"
