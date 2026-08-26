# OTP Attempt Limiting + Gmail Delivery Fix — Design Spec

Date: 2026-08-27
Status: Approved, implementing

## Problems

1. **Wrong-OTP UX is broken.** `OTPService.verify_otp` returns the exact
   same message ("รหัส OTP ไม่ถูกต้องหรือหมดอายุ") for both "you typed the
   wrong 6 digits" and "the code actually expired". The frontend
   (`verify-otp/page.tsx` + `verify-otp/route.ts`) then string-matches for
   the word "หมดอายุ" in that message to decide whether to redirect back to
   `/login` - since that substring is present in BOTH cases, every wrong
   OTP entry (even the very first typo) immediately bounces the user back
   to `/login` instead of letting them retry on the same page. There is
   also **no attempt-counting or lockout mechanism at all** today - nothing
   tracks how many times a given OTP session has been guessed wrong, so
   the product requirement ("แจ้งเตือนว่าผิดกี่ครั้ง เหลืออีกกี่ครั้ง, เกิน limit
   ต้องรอ Redis หมดอายุ") cannot be satisfied without adding one from
   scratch.
2. **OTP e-mails are never actually sent.** `OTPService._send_email` only
   ever attempts real delivery when `SMTP_HOST` is set - it is not set
   anywhere in `.env` (only `GMAIL_USERNAME`/`GMAIL_PASSWORD` are, unused by
   this function), so every OTP silently falls through to the
   `print(f"[OTP] ... code for {email}: {otp}")` dev fallback. In a real
   deployment, users never receive their code by e-mail for register,
   login, or password-reset.

## Design

### 1. Redis-backed attempt counter with a hard lockout

New key per OTP session, alongside the existing `otp:{action}:{token}`
value key: `otp_attempts:{action}:{token}`, an integer counter with the
SAME TTL as the OTP itself (so it naturally expires together - no separate
cleanup needed). Constants:

```python
MAX_OTP_ATTEMPTS = 5
```

`OTPService.verify_otp(action, token, otp)` becomes stateful:

- If the OTP key doesn't exist in Redis at all → `("expired", None)` - the
  session token expired or was never issued (5-minute create-time TTL, or
  it was already consumed/cleared by a prior successful confirm).
- If the attempts counter is already `>= MAX_OTP_ATTEMPTS` → `("locked",
  remaining_seconds)` - reject immediately WITHOUT comparing the submitted
  code at all (prevents wasting the lockout window on further guesses),
  `remaining_seconds` read from Redis `TTL` so the frontend can show a
  countdown/"ลองใหม่ในอีก N วินาที" message.
- If the submitted code is correct → returns `("ok", None)`, and the
  caller (login_confirm/register_confirm/reset_confirm) is responsible for
  clearing BOTH the OTP key and the attempts key via
  `clear_otp_session` (extended to delete both).
- If the submitted code is wrong → increments the attempts counter
  (`INCR`, re-applying the same TTL defensively on the first increment in
  case the key was somehow created without one), returns `("wrong",
  attempts_remaining)` where `attempts_remaining = MAX_OTP_ATTEMPTS -
  new_count` (can be 0, meaning this was the attempt that triggered the
  lockout).

Return shape changes from `tuple[bool, str|None]` to
`tuple[Literal["ok","wrong","locked","expired"], int|None]` - every call
site (`AuthService.login_confirm/register_confirm/reset_confirm`) is
updated to branch on the new outcome and produce a response with BOTH a
stable, frontend-parseable `status` code (via `utils.status_code.AuthStatus`,
new constants `OTP_WRONG`, `OTP_LOCKED`, `OTP_EXPIRED`) and a human Thai
message that includes the exact remaining-attempts or remaining-seconds
count - so the frontend never has to string-sniff the message again.

### 2. Frontend: branch on `status`, not substring-matching the message

`controller.py`/service responses already flow through
`utils/response.py`'s `{success, status, message, data}` shape - the
`verify-otp` Route Handler forwards `status` as-is instead of deriving its
own numeric `1400` pseudo-code from a substring match. `verify-otp/page.tsx`
switches on the returned `status`:

- `OTP_WRONG` → stay on the page, show the exact "รหัสไม่ถูกต้อง เหลือโอกาส
  อีก N ครั้ง" message from the backend, clear the OTP boxes, refocus the
  first box. No redirect.
- `OTP_LOCKED` → show "ลองผิดครบ N ครั้งแล้ว กรุณารอ M วินาทีแล้วลองใหม่",
  disable the form (submit button + OTP boxes) for the remaining TTL
  (client-side countdown timer re-enables the form when it hits 0 - it
  doesn't need to re-check with the server, Redis is the actual source of
  truth and will simply keep rejecting via the `locked` path until it
  naturally expires).
- `OTP_EXPIRED` / `TOKEN_EXPIRED` / `TOKEN_INVALID` (the token itself is
  gone or was never valid) → THIS is the only case that still redirects to
  `/login`, matching current behavior but now correctly scoped to actual
  expiry instead of every wrong guess.

### 3. Real Gmail SMTP delivery

`OTPService._send_email` gains a Gmail-specific fallback path: if
`SMTP_HOST` isn't set but `GMAIL_USERNAME`+`GMAIL_PASSWORD` are, use
`smtp.gmail.com:587` with STARTTLS and those credentials (Gmail App
Password format, matches the `.env` value's spaced 16-char shape). Only
falls through to the raw print-to-console dev mode if NEITHER `SMTP_HOST`
nor `GMAIL_USERNAME`/`GMAIL_PASSWORD` are configured. Existing generic
`SMTP_*` path is unchanged/still takes priority if someone does configure
a non-Gmail SMTP relay later.

## Testing

Backend: extend `tests/test_password_auth.py` with attempt-limiting
coverage - wrong OTP decrements remaining count correctly across repeated
calls, 5th wrong attempt returns `locked`, a locked session rejects even
a CORRECT code without re-checking it, expired/missing session returns
`expired` distinctly from `wrong`. New focused unit tests for
`OTPService.verify_otp` directly (fake Redis) covering the state machine.
Live E2E: real register→OTP flow, intentionally submit 5 wrong codes in a
row, confirm the exact `attempts_remaining` sequence (4,3,2,1,0) and the
lockout response on the 5th, confirm a 6th attempt (even with the correct
code) still returns locked, confirm real Gmail delivery actually occurs
(inspect Redis TTL / send success, cannot literally read the test Gmail
inbox in this environment but confirm smtplib call succeeds without
falling to the print fallback).

Frontend: `tsc --noEmit` clean. Live E2E via browser: submit wrong OTP
digits repeatedly and confirm the page stays put with the correct Thai
attempts-remaining message each time, confirm the lockout message and
disabled state appear on the 5th wrong attempt, confirm only a genuinely
expired/invalid token redirects to `/login`.
