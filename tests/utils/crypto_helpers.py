"""Cryptographic test utilities to avoid duplicating PKCE logic in tests."""

import base64
import hashlib
import secrets


def generate_pkce_pair():
    """Generate a PKCE code verifier and challenge pair for testing.

    This utility function creates valid PKCE parameters without duplicating
    the PKCE algorithm implementation in individual tests.

    Returns:
        tuple: (code_verifier, code_challenge) pair suitable for OAuth 2.1 PKCE flow
    """
    code_verifier = secrets.token_urlsafe(32)
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    return code_verifier, code_challenge


def create_invalid_code_challenge():
    """Create an invalid code challenge for testing PKCE verification failures.

    Returns:
        str: A malformed code challenge that should fail PKCE verification
    """
    return "invalid_challenge_for_testing"


def create_weak_code_verifier():
    """Create a code verifier that's too short (for testing validation).

    Returns:
        str: A code verifier shorter than the minimum required length
    """
    return secrets.token_urlsafe(10)  # Too short, should be at least 43 chars
