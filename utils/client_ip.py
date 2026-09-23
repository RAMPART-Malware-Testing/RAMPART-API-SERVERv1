"""Resolves the caller's IP address for rate limiting and audit rows.

Why this exists: every request to this API in production arrives through the
Next.js server (the frontend proxies /api/auth/* to us and forwards the
original client address), so `request.client.host` is the *proxy's* address
for every caller. Keying a per-IP rate limit on that value puts all users in
one bucket - 20 login attempts across the whole user base would lock out
everyone. So the proxy-recorded address is used when this deployment is
configured to trust the proxy, and the socket peer otherwise.

TRUST_PROXY_HEADERS must only be TRUE when the API is reachable exclusively
through that trusted proxy (the app's normal topology). If the port is also
exposed directly, a caller could send its own x-client-ip and get a fresh
rate-limit bucket per request - the per-email protections (wrong-password
lockout, OTP send limit, OTP attempt lockout) are keyed on the account and
are unaffected by that, but the per-IP layer would be bypassable.
"""

import os

from fastapi import Request

_TRUSTED_HEADERS = ("x-client-ip", "x-forwarded-for", "x-real-ip")


def trust_proxy_headers() -> bool:
    return os.getenv("TRUST_PROXY_HEADERS", "FALSE").upper() == "TRUE"


def get_client_ip(request: Request) -> str | None:
    if trust_proxy_headers():
        for header in _TRUSTED_HEADERS:
            raw = request.headers.get(header)
            if not raw:
                continue
            # x-forwarded-for is a comma-separated chain (client, proxy1, ...);
            # the left-most entry is the original caller.
            first = raw.split(",")[0].strip()
            if first:
                return first

    return request.client.host if request.client else None
