# fastapi-magic-link-auth

A reference implementation of HMAC-signed magic-link authentication for FastAPI.

No password storage. No database for sessions. No JWT library, no Auth0, no Passport. Just `hmac`, `hashlib`, `base64`, and a single secret env var. Production-grade.

## Why this exists

Most magic-link tutorials online get one of these wrong:

- Use predictable timestamps (vulnerable to enumeration)
- Use `==` instead of `hmac.compare_digest` (timing attack)
- Store tokens server-side and require a database lookup (slow + adds infra)
- Sign tokens with the wrong scope (a "session" token gets accepted in a "password reset" flow)
- Have no expiry (or expiry is implemented but not actually checked)
- Have no kind-tagging (so a session token forged from a magic-link token works)

This implementation fixes all of those. The whole thing is ~120 lines of Python and one secret in your environment.

## How it works

```
Token format:  base64url(body).base64url(hmac_sha256(secret, body))
Body format:   "v1|<kind>|<payload>|<expiry_unix>"
```

The token is self-contained. Server-side state is unnecessary because verification re-computes the HMAC from the body and compares constant-time. If the HMAC matches, the body is trusted. The body carries:

- `kind` — `"magic"` or `"session"` (so a magic-link token cannot be replayed as a session token)
- `payload` — opaque to the auth layer. Usually a user ID or email.
- `expiry_unix` — Unix timestamp. Magic links expire in 15 minutes, sessions in 30 days. Verification rejects expired tokens.

The HMAC means an attacker cannot forge a body without the secret. The expiry means a stolen token is short-lived. The `kind` field means the same secret can sign multiple token types without cross-contamination.

## Usage

```python
from auth import issue_magic_link_token, consume_magic_link_token
from auth import issue_session_token, resolve_session

# Step 1: User enters email at /login
# Server generates a magic-link token bound to that email
token = issue_magic_link_token(email="user@example.com")
link = f"https://example.com/auth?token={token}"
# Email the link to user via your email provider

# Step 2: User clicks link, lands at /auth?token=...
# Server verifies the magic-link token
email = consume_magic_link_token(token)
if not email:
    return "Invalid or expired link"

# Step 3: Server issues a session token bound to user ID
# Set as an HttpOnly cookie on the response
session_token = issue_session_token(user_id="123")
response.set_cookie("session", session_token, httponly=True, secure=True, samesite="lax")

# Step 4: On every subsequent request, resolve_session reads the cookie
def get_current_user(request):
    user_id = resolve_session(request.cookies.get("session"))
    if not user_id:
        raise HTTPException(401)
    return load_user(user_id)
```

## Verify it works

No credentials, no services, no network. Clone it and run the suite:

```bash
python -m pytest test_auth.py -q
```

Expected output:

```
15 passed
```

That covers token signing and verification, expiry, single-use enforcement,
tampering, and a check that `_verify_token` uses `hmac.compare_digest` rather
than `==`. If any of those fail, the auth is not safe to copy.

## What this is not

- **An identity provider.** This signs and verifies tokens. It does not store users, send emails, or manage sessions in a database. You wire those parts up.
- **A complete OAuth flow.** OAuth is a different problem. If you want OAuth, use Authlib.
- **A replacement for a real auth provider at scale.** If you have 10M users or compliance requirements that require central revocation, you want a database-backed session store. This pattern is right for indie SaaS at 0-10k user scale.

## What this gives you over the "obvious" approach

The obvious approach is:
- Generate a random token, store it in a database with expiry
- On verification, look it up, check expiry, mark as used
- Repeat for sessions

That works. It also adds:
- A database read on every authenticated request (slow on a cold cache)
- A database write on every login + every session creation
- A revocation problem (you have to clean up expired tokens or the table grows forever)
- A "user can be logged in on multiple devices" complication

The HMAC pattern in this repo trades:
- One environment variable (your secret) for one fewer database
- A token-length overhead (signed tokens are ~150 chars vs ~20 for a database lookup ID) for zero database load on auth
- Inability to centrally revoke a session before its expiry, for not having to maintain a revocation list

For solo SaaS and most small-to-medium teams, those are good trades.

## Files

- `auth.py` — the actual implementation (~120 lines, no third-party deps)
- `example_fastapi_app.py` — full working FastAPI demo with magic-link login + session cookies
- `test_auth.py` — pytest test suite covering the security properties (HMAC tampering, expiry, kind confusion, signature length variation)

## Running the demo

```bash
pip install fastapi uvicorn
export AUTH_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
python example_fastapi_app.py
# Visit http://localhost:8000/login
```

In the demo, the "email" step is mocked — the magic link is printed to the console instead of emailed. Wire it to your email provider (Resend, SES, Postmark) for production.

## Security properties this implementation has

- **Constant-time HMAC comparison** via `hmac.compare_digest` (prevents timing attacks on token verification)
- **Kind-tagged tokens** so a `magic` token cannot be replayed as a `session` token
- **Expiry enforced on every verification** — no "we forgot to check" bug class
- **Secret rotation supported** — append new secret to env, keep old as `AUTH_SECRET_PREVIOUS` for 24h, then drop. Verification tries both during the rotation window.
- **HMAC-SHA256** — well-studied, no weird crypto choices
- **No user input in the secret-key path** — secret is read once at startup, never derived from request data

## License

MIT. Use it, copy it, adapt it. If you find a security issue please email sal@consentleads.uk before disclosing publicly.
