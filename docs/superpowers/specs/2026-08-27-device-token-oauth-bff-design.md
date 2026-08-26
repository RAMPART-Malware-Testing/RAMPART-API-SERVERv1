# Device-Token Trust, OAuth Auto-Link, and BFF Hardening — Design Spec

Date: 2026-08-27
Status: Approved, implementing (per explicit "design and build it, don't ask" instruction)

## Problems found (via research before this spec)

1. **Device-token bypass is unbound to any account.** `AuthService.login()` only
   checks that the submitted `deviceToken` is a structurally valid, non-expired
   `type=device` JWT — it never compares the token's `sub` (uid) against the
   user being logged into. Any valid device token (for ANY account, issued at
   ANY point in its 7-day life) currently skips OTP for ANY email+password
   login attempt. This directly contradicts the required behavior ("device
   token ของ a@a.com ต้องข้าม OTP ได้เฉพาะตอน login เป็น a@a.com เท่านั้น").
2. **The `deviceToken` cookie is never written anywhere in the frontend.**
   `login/route.ts` reads a `deviceToken` cookie but nothing in the entire
   repo ever calls `.cookies.set('deviceToken', ...)` — the whole mechanism
   is currently dead on arrival; the bypass path is unreachable in practice
   today (masking bug #1's real-world impact, but a fix-half-only situation).
3. **OAuth login never issues a device token** — only a session cookie. If a
   user later tries password-login with the same (now-verified) email, they
   get no bypass benefit from having previously proven that email via OAuth.
4. **OAuth auto-link by email ignores `OAuthProfile.email_verified`.** Any
   OAuth profile whose email matches an existing account is silently linked,
   regardless of whether the provider actually verified that email address —
   a spoofing/account-takeover risk for providers that allow unverified
   emails through.
5. **No forced-OTP rule for password-login on an OAuth-linked account.** Per
   the explicit requirement's last sentence, an account that has ANY
   `oauth_accounts` row must always require OTP on password login,
   regardless of device-token state — this tier of account is treated as
   higher-value/higher-risk.
6. **`login_history` is only ever written for OAuth logins.** Password logins
   (with or without OTP, with or without device-token bypass) are never
   recorded, even though the table's `provider` column already documents
   `'password' | 'google' | 'github'` as expected values.
7. **BFF violation**: the Google/GitHub buttons on `/login` are raw
   `<a href="{NEXT_PUBLIC_SERVER_URL}/...">` tags — the browser navigates
   directly to the FastAPI backend, and the backend's URL (currently a public
   ngrok tunnel) is exposed to client-side code via `NEXT_PUBLIC_SERVER_URL`.
   Every other auth flow (password login/register/reset/OTP) already
   correctly proxies through local `/api/auth/*` Next.js routes with zero
   backend-URL exposure to the browser — only the OAuth buttons violate this.

## Design

### Backend

#### 1. Device token binds to email, not just structural validity

`login_confirm()` (issues the device token after successful OTP) embeds the
account's email into the token:

```python
device_token = create_token(
    subject=str(user.uid),
    token_type="device",
    expires_minutes=60 * 24 * 7,
    extra_payload={"email": user.email},
)
```

`login()`'s device-token-bypass block becomes:

```python
if deviceToken:
    payload, err = TokenService.verify_token(deviceToken, "device")
    if not err and payload.get("sub") == str(user.uid) and payload.get("email") == user.email:
        ...bypass...
```

Both `sub` (uid) AND `email` must match the account being logged into. `sub`
alone would already be sufficient (uid is unique), but checking `email` too
gives defense-in-depth against any future code path that might issue a
device token with a mismatched subject, and gives the exact "changed email ⇒
must re-verify" semantics the requirement describes explicityl in terms of
email, not uid.

On successful bypass, a **fresh** device token is minted (same uid+email,
new 7-day expiry) and returned to the frontend so the cookie gets refreshed
on every successful login — satisfying "ถ้า device token ไม่หมดอายุ ... update
device token มีอายุ 7 วัน".

#### 2. OAuth-linked accounts always require OTP on password login

Immediately after password verification succeeds in `login()`, before the
device-token check, query whether the account has any `oauth_accounts` row:

```python
has_oauth = await session.execute(select(OAuthAccount.id).where(OAuthAccount.uid == user.uid).limit(1))
if has_oauth.scalar_one_or_none() is not None:
    # Skip the device-token bypass entirely - always fall through to OTP,
    # regardless of whether a valid, matching device token was presented.
```

This is a hard override: even a perfectly matching, non-expired device token
for the correct account does not bypass OTP if that account has any linked
OAuth identity. Implements the explicit last requirement.

#### 3. OAuth login also issues a device token bound to email

`oauth_callback_controller`, after `issue_access_token`, also mints a device
token the same way `login_confirm` does (`extra_payload={"email": user.email}`,
7-day expiry) and appends it to the redirect query string as `device_token`
(snake_case, to avoid colliding with the camelCase `deviceToken` header
convention used elsewhere — the frontend callback route reads it and sets
the same `deviceToken` cookie name for consistency on the frontend side).

This means: sign in via Google once ⇒ later a password-login attempt with
the same email (if the account also has a password set, e.g. via password
reset) can skip OTP too — UNLESS rule #2 above applies (which it always will
for an OAuth-originated account, since it necessarily has an `oauth_accounts`
row). In practice, rule #2 makes this device token only useful for a
*second* OAuth login's own re-entry convenience, never for bypassing
password-login OTP on that same account — which is the intended stricter
posture per the explicit requirement. Still implemented for consistency and
because a future account-management feature (e.g. "unlink OAuth, keep
password") would need it.

#### 4. `email_verified` gate on OAuth auto-link into an existing account

In `find_or_create_user`, the "link to existing password/OAuth account by
email" branch additionally requires `profile.email_verified is True`. If an
OAuth profile's email matches an existing account but the provider didn't
verify it, the login is rejected with `OAuthError` (surfaced as
`OAUTH_EMAIL_MISSING`-style redirect) rather than silently merging into
someone else's account. New-account creation (no existing email match) is
unaffected — that path doesn't merge into anyone else's data.

#### 5. `login_history` written for every password-auth login path

New helper in `auth_service.py`, called from `login()` (device-bypass path
and the OTP-required path get differently-labeled `status` values) and from
`login_confirm()` (`provider="password"`, `status="success"`). Uses
`cores.sync_pg_db` — wait, `auth_service.py` is fully async (`SessionLocal`
from `cores.async_pg_db`), so this uses the same async session already open
in each method, just one more `session.add(LoginHistory(...))` before
commit.

### Frontend (BFF hardening)

#### 1. OAuth buttons go through local Next.js routes, never expose backend URL

New `src/app/(routes)/api/auth/[provider]/login/route.ts` — validates
`provider` is `google`/`github`, then issues a 302 redirect to
`${SERVER_URL}/api/auth/{provider}/login` (server-side `SERVER_URL`, never
`NEXT_PUBLIC_*`). `/login/page.tsx`'s buttons change from
`href="${NEXT_PUBLIC_SERVER_URL}/api/auth/google/login"` to
`href="/api/auth/google/login"` — same for GitHub. The browser's address bar
and every DOM attribute now only ever references `localhost:3000`.

#### 2. `deviceToken` cookie is actually written (fixes the dead mechanism)

- `login/route.ts`: on `bypass_otp: true` (device-token bypass succeeded),
  the backend now also returns a **refreshed** device token in
  `res.data.device_token` — write it to the `deviceToken` httpOnly cookie
  (7-day maxAge, matching the JWT's own expiry) alongside the existing
  `access_token` cookie.
- `verify-otp/route.ts` (`content === 'login_confirm'` branch): backend's
  `login_confirm` response already includes `deiveToken` (existing typo,
  kept for backend-compat) — write it to the `deviceToken` cookie here too.
  This is the **primary** path that actually establishes device trust for
  the first time (a brand-new device always goes through OTP once).
- `src/app/(routes)/auth/callback/route.ts` (OAuth): read the new
  `device_token` query param from the backend redirect, write it to the same
  `deviceToken` cookie.

All three use the same cookie shape: httpOnly, `secure` in production,
`sameSite: 'lax'`, `path: '/'`, `maxAge: 60*60*24*7`. The cookie's payload
(signed with the frontend's own `jwtService`, matching the existing pattern
for `access_token`) simply wraps the raw backend device JWT string — the
frontend never needs to inspect its contents, it's opaque passthrough,
exactly like how `access_token`'s cookie wraps the raw backend access JWT.

#### 3. Types

`src/types/auth.type.ts`: `LoginParams` unchanged (already has
`deviceToken: string | null` for the outbound leg). No new frontend-only
types strictly required — the device token is opaque passthrough on the
frontend, matching how `access_token` is already handled.

## Testing

Backend: extend `tests/test_password_auth.py` with:
- device token bypass succeeds only when `sub` AND `email` both match
- device token bypass rejected (falls through to OTP) when email differs
  (simulating the "login as b@b.com with a@a.com's device token" case)
- device token bypass rejected when account has a linked OAuth identity
  (rule #2), even with a perfectly matching device token
- `login_confirm` mints a device token containing the account's email
- OAuth auto-link into an existing account requires `email_verified=True`
  (`find_or_create_user` in `test_uuid_flows.py`, extending the existing
  OAuth test coverage there)
- `login_history` gets a row written on `login_confirm` success

Full suite must stay green net of the 4 pre-existing unrelated failures
already documented (CAPE test assertions, test-mode console content drift).

Live E2E via the running stack + real Postgres/Redis: full register → OTP →
first login (OTP required, device token minted) → cookie captured → second
login with that same device token+email (OTP skipped, fresh device token
returned) → login attempt with a DIFFERENT email but the first device token
(OTP required again) → confirm `login_history` rows exist for both password
logins.

Frontend: `tsc --noEmit` clean (0 errors, matching current baseline). Live
E2E via a real Playwright browser session: click the Google button and
confirm the browser's address bar shows `localhost:3000/api/auth/google/login`
momentarily before the 302 hands off to Google (never showing the raw
backend/ngrok URL in the omnibox); complete a password login twice in the
same browser context and confirm no OTP page is shown the second time
(device token cookie effect visible in Application/cookie inspector).
