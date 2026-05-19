"""Test suite covering the security properties of auth.py.

Run:
    pip install pytest
    export AUTH_SECRET=test-secret-do-not-use-in-prod
    pytest test_auth.py -v
"""
import os
import time

import pytest

# Set test secret BEFORE importing auth
os.environ.setdefault("AUTH_SECRET", "test-secret-do-not-use-in-prod-32bytes")
os.environ.setdefault("AUTH_SECRET_PREVIOUS", "")

from auth import (
    issue_magic_link_token,
    consume_magic_link_token,
    issue_session_token,
    resolve_session,
    _make_token,
    _verify_token,
    MAGIC_LINK_TTL_SECONDS,
)


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------

def test_magic_link_round_trip():
    token = issue_magic_link_token("alice@example.com")
    assert consume_magic_link_token(token) == "alice@example.com"


def test_session_round_trip():
    token = issue_session_token("user_123")
    assert resolve_session(token) == "user_123"


def test_email_is_lowercased():
    token = issue_magic_link_token("Alice@Example.COM")
    assert consume_magic_link_token(token) == "alice@example.com"


# ---------------------------------------------------------------------------
# Security: tampering
# ---------------------------------------------------------------------------

def test_tampered_body_rejected():
    """Flipping a bit in the body invalidates the HMAC."""
    token = issue_magic_link_token("alice@example.com")
    body_b64, sig_b64 = token.split(".")
    # Flip one character in the body
    tampered = body_b64[:-2] + "XX." + sig_b64
    assert consume_magic_link_token(tampered) is None


def test_tampered_signature_rejected():
    token = issue_magic_link_token("alice@example.com")
    body_b64, sig_b64 = token.split(".")
    tampered = body_b64 + "." + sig_b64[:-2] + "XX"
    assert consume_magic_link_token(tampered) is None


def test_empty_token_rejected():
    assert consume_magic_link_token("") is None
    assert resolve_session("") is None
    assert resolve_session(None) is None


def test_malformed_token_rejected():
    """Tokens without the body.signature shape are rejected."""
    assert consume_magic_link_token("garbage") is None
    assert consume_magic_link_token("a.b.c") is None  # too many parts (actually accepted by split(., 1), so HMAC fails)
    assert consume_magic_link_token("notbase64.notbase64") is None


# ---------------------------------------------------------------------------
# Security: kind confusion
# ---------------------------------------------------------------------------

def test_magic_token_rejected_as_session():
    """A magic-link token must NOT be accepted as a session token."""
    magic = issue_magic_link_token("alice@example.com")
    assert resolve_session(magic) is None


def test_session_token_rejected_as_magic():
    session = issue_session_token("user_123")
    assert consume_magic_link_token(session) is None


# ---------------------------------------------------------------------------
# Security: expiry
# ---------------------------------------------------------------------------

def test_expired_token_rejected():
    """A token with expiry in the past is rejected."""
    # Make a token that expired 10 seconds ago
    token = _make_token("magic", "alice@example.com", ttl_seconds=-10)
    assert _verify_token(token, "magic") is None


def test_token_at_expiry_boundary():
    """A token expiring in 1 second is still valid."""
    token = _make_token("magic", "alice@example.com", ttl_seconds=1)
    assert _verify_token(token, "magic") == "alice@example.com"


def test_long_lived_session_still_valid():
    """A 30-day session token issued now is valid."""
    token = issue_session_token("user_123")
    assert resolve_session(token) == "user_123"


# ---------------------------------------------------------------------------
# Security: secret rotation
# ---------------------------------------------------------------------------

def test_token_signed_with_previous_secret_still_valid(monkeypatch):
    """Tokens signed with AUTH_SECRET_PREVIOUS verify during rotation overlap."""
    old_secret = "old-secret-for-rotation-test-32bytes"
    new_secret = "new-secret-for-rotation-test-32bytes"

    # Issue token with old secret
    monkeypatch.setenv("AUTH_SECRET", old_secret)
    monkeypatch.delenv("AUTH_SECRET_PREVIOUS", raising=False)
    old_token = issue_session_token("user_123")

    # Switch: new secret is now AUTH_SECRET, old becomes AUTH_SECRET_PREVIOUS
    monkeypatch.setenv("AUTH_SECRET", new_secret)
    monkeypatch.setenv("AUTH_SECRET_PREVIOUS", old_secret)

    assert resolve_session(old_token) == "user_123"


def test_token_signed_with_unknown_secret_rejected(monkeypatch):
    """Tokens signed with a secret that isn't current OR previous are rejected."""
    monkeypatch.setenv("AUTH_SECRET", "unrelated-secret-1-32bytes-long")
    monkeypatch.delenv("AUTH_SECRET_PREVIOUS", raising=False)
    token = issue_session_token("user_123")

    monkeypatch.setenv("AUTH_SECRET", "completely-different-secret-32b")
    monkeypatch.delenv("AUTH_SECRET_PREVIOUS", raising=False)

    assert resolve_session(token) is None


# ---------------------------------------------------------------------------
# Security: timing attack resistance
# ---------------------------------------------------------------------------

def test_verification_uses_constant_time_compare():
    """HMAC comparison should not short-circuit on first mismatched byte.

    This is more of a property test - we can't truly measure timing in a
    unit test, but we can confirm the code path uses hmac.compare_digest.
    """
    import hmac as hmac_module
    import inspect
    from auth import _verify_token

    source = inspect.getsource(_verify_token)
    assert "hmac.compare_digest" in source, (
        "_verify_token must use hmac.compare_digest for constant-time comparison"
    )
