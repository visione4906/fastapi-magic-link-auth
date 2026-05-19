"""HMAC-signed magic-link auth + session cookies for FastAPI.

No external dependencies beyond the standard library and FastAPI itself.
Tokens are self-contained (body + HMAC). Server-side state is unnecessary
because verification re-computes the HMAC from the body and compares
constant-time.

Security properties:
  - Constant-time HMAC compare (hmac.compare_digest)
  - Kind-tagged tokens (magic vs session) - tokens cannot be cross-used
  - Expiry enforced on every verify
  - Secret rotation supported via AUTH_SECRET_PREVIOUS env var
  - HMAC-SHA256, no exotic crypto

Set the AUTH_SECRET environment variable to a high-entropy random string
(at least 32 bytes urlsafe-base64). Recommended:

    python -c "import secrets; print(secrets.token_urlsafe(32))"

To rotate the secret without invalidating live sessions:
  1. Generate new secret, set as AUTH_SECRET
  2. Copy the old secret to AUTH_SECRET_PREVIOUS
  3. Wait until the longest token TTL has elapsed (30 days for sessions here)
  4. Remove AUTH_SECRET_PREVIOUS

During the overlap window, verification tries both secrets.
"""
import base64
import hashlib
import hmac
import os
import time

# Token TTLs - tune for your use case
MAGIC_LINK_TTL_SECONDS = 15 * 60          # 15 minutes
SESSION_TTL_SECONDS = 30 * 24 * 3600      # 30 days


def _secret() -> bytes:
    s = (os.environ.get("AUTH_SECRET") or "").strip()
    if not s:
        raise RuntimeError("AUTH_SECRET environment variable not set")
    return s.encode("utf-8")


def _secret_previous() -> bytes | None:
    s = (os.environ.get("AUTH_SECRET_PREVIOUS") or "").strip()
    return s.encode("utf-8") if s else None


def _b64u(b: bytes) -> str:
    """Base64-url-encode without padding."""
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64u_decode(s: str) -> bytes:
    """Base64-url-decode, re-adding padding as needed."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _sign(secret: bytes, body: bytes) -> bytes:
    return hmac.new(secret, body, hashlib.sha256).digest()


def _make_token(kind: str, payload: str, ttl_seconds: int) -> str:
    """Build a kind-tagged, expiring, HMAC-signed token.

    Body format: v1|<kind>|<payload>|<expiry_unix>
    Token format: <b64u(body)>.<b64u(hmac(secret, body))>
    """
    exp = int(time.time()) + ttl_seconds
    body = f"v1|{kind}|{payload}|{exp}".encode("utf-8")
    sig = _sign(_secret(), body)
    return _b64u(body) + "." + _b64u(sig)


def _verify_token(token: str, expected_kind: str) -> str | None:
    """Verify and unpack a token. Returns the payload string if valid, else None.

    Validates: format, HMAC (against current + previous secret), kind, expiry.
    Constant-time HMAC comparison.
    """
    if not token or "." not in token:
        return None
    try:
        body_b64, sig_b64 = token.split(".", 1)
        body = _b64u_decode(body_b64)
        provided_sig = _b64u_decode(sig_b64)
    except Exception:
        return None

    # Try current secret, then previous (for rotation overlap)
    current = _sign(_secret(), body)
    valid = hmac.compare_digest(current, provided_sig)

    if not valid:
        prev = _secret_previous()
        if prev is not None:
            previous = _sign(prev, body)
            valid = hmac.compare_digest(previous, provided_sig)

    if not valid:
        return None

    try:
        parts = body.decode("utf-8").split("|")
        if len(parts) != 4 or parts[0] != "v1":
            return None
        kind, payload, exp_str = parts[1], parts[2], parts[3]
        if kind != expected_kind:
            return None  # Reject tokens of wrong kind (defense in depth)
        if int(exp_str) < int(time.time()):
            return None  # Expired
        return payload
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def issue_magic_link_token(email: str) -> str:
    """Issue a short-lived magic-link token bound to an email address."""
    return _make_token("magic", email.lower().strip(), MAGIC_LINK_TTL_SECONDS)


def consume_magic_link_token(token: str) -> str | None:
    """Verify a magic-link token. Returns the email if valid, else None.

    Note: this implementation does NOT mark the token as used. A magic link
    can be re-clicked within its TTL window. For most flows that is fine
    (idempotent login). If you need single-use semantics, you'll need
    server-side state (database column "used_at"). The trade-off is one
    database write per login.
    """
    return _verify_token(token, "magic")


def issue_session_token(user_id: str) -> str:
    """Issue a long-lived session token bound to a user ID."""
    return _make_token("session", str(user_id), SESSION_TTL_SECONDS)


def resolve_session(token: str | None) -> str | None:
    """Verify a session token from a cookie. Returns the user ID if valid."""
    if not token:
        return None
    return _verify_token(token, "session")
