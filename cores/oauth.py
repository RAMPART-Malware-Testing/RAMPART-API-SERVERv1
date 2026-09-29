"""OAuth client registration for external identity providers.

RAMPART authenticates users exclusively through Google and GitHub. This
module wires up Authlib's Starlette/FastAPI integration once at import time;
`routers/oauth.py` and `services/oauth/oauth_service.py` consume the
registered clients from here.
"""

import os
from urllib.parse import urlparse

from authlib.integrations.starlette_client import OAuth
from dotenv import load_dotenv

load_dotenv()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")

OAUTH_REDIRECT_BASE_URL = os.getenv("OAUTH_REDIRECT_BASE_URL", "http://localhost:8006").rstrip("/")

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000").rstrip("/")

ALLOWED_ORIGINS = tuple(
    dict.fromkeys(
        [FRONTEND_URL]
        + [
            origin.strip().rstrip("/")
            for origin in os.getenv("ALLOWED_ORIGINS", "").split(",")
            if origin.strip()
        ]
    )
)

oauth = OAuth()

oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    client_kwargs={"scope": "openid email profile"},
)

oauth.register(
    name="github",
    client_id=GITHUB_CLIENT_ID,
    client_secret=GITHUB_CLIENT_SECRET,
    access_token_url="https://github.com/login/oauth/access_token",
    authorize_url="https://github.com/login/oauth/authorize",
    api_base_url="https://api.github.com/",
    client_kwargs={"scope": "read:user user:email"},
)

def oauth_configured(provider: str) -> bool:
    if provider == "google":
        return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)
    if provider == "github":
        return bool(GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET)
    return False

def origin_netloc(value: str) -> str:
    candidate = value.strip().rstrip("/")
    if candidate and "://" not in candidate:
        candidate = f"//{candidate}"
    return urlparse(candidate).netloc.lower()

def resolve_redirect_origin(candidate: str | None) -> str | None:
    if not candidate:
        return None

    netloc = origin_netloc(candidate)
    if not netloc:
        return None

    for origin in ALLOWED_ORIGINS:
        if origin_netloc(origin) == netloc:
            return origin
    return None

def redirect_uri_for(provider: str, origin: str | None = None) -> str:
    base = (origin or OAUTH_REDIRECT_BASE_URL).rstrip("/")
    return f"{base}/api/auth/{provider}/callback"
