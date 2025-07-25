"""Tests for token manager functionality."""

import pytest

from src.auth.models import UserInfo
from src.auth.token_manager import TokenManager

# Mark all async functions in this module as asyncio tests
pytestmark = pytest.mark.asyncio


class TestTokenManager:
    """Test cases for TokenManager."""

    async def test_token_manager_initialization(self, token_manager):
        """Test token manager initializes correctly."""
        assert token_manager.secret_key == "test-secret-key-for-testing-only"
        assert token_manager.issuer == "http://localhost:8080"
        assert token_manager.algorithm == "HS256"
        assert token_manager.token_storage is not None

    async def test_create_access_token_basic(self, token_manager):
        """Test basic access token creation."""
        token = await token_manager.create_access_token(
            client_id="test_client",
            user_id="test_user_123",
            scope="read write",
            expires_in=3600,
        )

        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0

    async def test_create_access_token_with_resource(self, token_manager):
        """Test access token creation with resource parameter."""

        resource = "http://localhost:8080/calculator/mcp"
        token = await token_manager.create_access_token(
            client_id="test_client",
            user_id="test_user_123",
            scope="read calculate",
            resource=resource,
            expires_in=3600,
        )

        assert token is not None

        # Validate the token can be decoded
        payload = await token_manager.validate_access_token(token, resource)
        assert payload is not None
        assert payload["aud"] == resource
        assert payload["sub"] == "test_user_123"
        assert payload["client_id"] == "test_client"
        assert payload["scope"] == "read calculate"

    async def test_validate_token_success(self, token_manager):
        """Test successful token validation."""

        resource = "http://localhost:8080/calculator/mcp"
        token = await token_manager.create_access_token(
            client_id="test_client",
            user_id="test_user_123",
            scope="read",
            resource=resource,
            expires_in=3600,
        )

        payload = await token_manager.validate_access_token(token, resource)

        assert payload is not None
        assert payload["sub"] == "test_user_123"
        assert payload["client_id"] == "test_client"
        assert payload["scope"] == "read"
        assert payload["aud"] == resource
        assert payload["iss"] == token_manager.issuer

    async def test_validate_token_wrong_audience(self, token_manager):
        """Test token validation with wrong audience."""

        token = await token_manager.create_access_token(
            client_id="test_client",
            user_id="test_user_123",
            scope="read",
            resource="http://localhost:8080/calculator/mcp",
            expires_in=3600,
        )

        # Try to validate with wrong resource
        payload = await token_manager.validate_access_token(
            token, "http://localhost:8080/weather/mcp"
        )

        assert payload is None

    async def test_validate_token_expired(self, token_manager):
        """Test token validation with expired token."""

        # Create token that expires immediately
        token = await token_manager.create_access_token(
            client_id="test_client",
            user_id="test_user_123",
            scope="read",
            expires_in=-1,  # Expired token
        )

        payload = await token_manager.validate_access_token(token, token_manager.issuer)

        assert payload is None

    async def test_validate_token_invalid_signature(
        self, token_manager, memory_storage
    ):
        """Test token validation with invalid signature."""
        # Create a token with a different secret
        different_manager = TokenManager(
            "different_secret", token_manager.issuer, token_storage=memory_storage
        )

        token = await different_manager.create_access_token(
            client_id="test_client",
            user_id="test_user_123",
            scope="read",
            expires_in=3600,
        )

        # Try to validate with original manager (different secret)
        payload = await token_manager.validate_access_token(token, token_manager.issuer)

        assert payload is None

    async def test_validate_token_malformed(self, token_manager):
        """Test token validation with malformed token."""
        payload = await token_manager.validate_access_token(
            "invalid.token.here", token_manager.issuer
        )

        assert payload is None

    async def test_create_refresh_token(self, token_manager):
        """Test refresh token creation."""

        refresh_token = await token_manager.create_refresh_token(
            client_id="test_client", user_id="test_user_123", scope="read write"
        )

        assert refresh_token is not None
        assert isinstance(refresh_token, str)
        assert len(refresh_token) > 0
        # Check token is stored in storage backend
        token_data = await token_manager.validate_refresh_token(refresh_token)
        assert token_data is not None

    async def test_validate_refresh_token_success(self, token_manager):
        """Test successful refresh token validation."""

        refresh_token = await token_manager.create_refresh_token(
            client_id="test_client", user_id="test_user_123", scope="read write"
        )

        token_data = await token_manager.validate_refresh_token(refresh_token)

        assert token_data is not None
        assert token_data.user_id == "test_user_123"
        assert token_data.client_id == "test_client"
        assert token_data.scope == "read write"

    async def test_validate_refresh_token_invalid(self, token_manager):
        """Test refresh token validation with invalid token."""
        token_data = await token_manager.validate_refresh_token("invalid_token")

        assert token_data is None

    async def test_revoke_refresh_token(self, token_manager):
        """Test refresh token revocation."""

        refresh_token = await token_manager.create_refresh_token(
            client_id="test_client",
            user_id="test_user_123",
            scope="read",
        )

        # Verify token exists
        token_data = await token_manager.validate_refresh_token(refresh_token)
        assert token_data is not None

        # Revoke token
        revoked = await token_manager.revoke_refresh_token(refresh_token)

        assert revoked is True

        # Try to validate revoked token
        token_data = await token_manager.validate_refresh_token(refresh_token)
        assert token_data is None

    async def test_revoke_nonexistent_refresh_token(self, token_manager):
        """Test revoking non-existent refresh token."""
        revoked = await token_manager.revoke_refresh_token("nonexistent_token")

        assert revoked is False

    async def test_audience_normalization(self, token_manager):
        """Test that audience values are normalized correctly."""

        # Test with trailing slash
        resource_with_slash = "http://localhost:8080/calculator/mcp/"
        token = await token_manager.create_access_token(
            client_id="test_client",
            user_id="test_user_123",
            scope="read",
            resource=resource_with_slash,
        )

        # Should validate with normalized resource (without trailing slash)
        normalized_resource = "http://localhost:8080/calculator/mcp"
        payload = await token_manager.validate_access_token(token, normalized_resource)

        assert payload is not None
        assert payload["aud"] == normalized_resource

    async def test_token_payload_structure(self, token_manager):
        """Test that token payload contains all required fields."""
        user_info = UserInfo(
            id="test_user_123",
            email="test@example.com",
            name="Test User",
            provider="github",
            avatar_url="https://example.com/avatar.jpg",
        )

        resource = "http://localhost:8080/calculator/mcp"
        token = await token_manager.create_access_token(
            client_id="test_client",
            user_id="test_user_123",
            scope="read calculate",
            resource=resource,
            expires_in=3600,
            user_info=user_info,
        )

        payload = await token_manager.validate_access_token(token, resource)

        # Check all required fields
        assert "iss" in payload  # issuer
        assert "sub" in payload  # subject (user_id)
        assert "aud" in payload  # audience
        assert "client_id" in payload
        assert "scope" in payload
        assert "iat" in payload  # issued at
        assert "exp" in payload  # expires at
        assert "jti" in payload  # JWT ID
        assert "resource" in payload

        # Check user info fields
        assert "email" in payload
        assert "name" in payload
        assert "provider" in payload
        assert "avatar_url" in payload

        # Verify values
        assert payload["email"] == "test@example.com"
        assert payload["name"] == "Test User"
        assert payload["provider"] == "github"
        assert payload["avatar_url"] == "https://example.com/avatar.jpg"
