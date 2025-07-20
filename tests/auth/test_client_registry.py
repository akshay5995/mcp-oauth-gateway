"""Tests for client registry functionality."""

import time

import pytest

from src.auth.models import ClientRegistrationRequest

# Mark all async functions in this module as asyncio tests
pytestmark = pytest.mark.asyncio


class TestClientRegistry:
    """Test cases for ClientRegistry."""

    async def test_client_registry_initialization(self, client_registry):
        """Test client registry initializes correctly."""
        assert client_registry.client_storage is not None

    async def test_register_client_success(self, client_registry):
        """Test successful client registration."""
        request = ClientRegistrationRequest(
            client_name="Test MCP Client",
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
            token_endpoint_auth_method="client_secret_basic",
            scope="read write",
        )

        client = await client_registry.register_client(request)

        assert client.client_name == "Test MCP Client"
        assert client.redirect_uris == ["http://localhost:8080/callback"]
        assert client.grant_types == ["authorization_code"]
        assert client.response_types == ["code"]
        assert client.token_endpoint_auth_method == "client_secret_basic"
        assert client.scope == "read write"
        assert client.client_id.startswith("mcp_client_")
        assert len(client.client_secret) > 20
        # Verify client is stored
        retrieved_client = await client_registry.get_client(client.client_id)
        assert retrieved_client is not None

    async def test_register_client_deduplication(self, client_registry):
        """Test client registration deduplication."""
        request = ClientRegistrationRequest(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
        )

        # Register client twice
        client1 = await client_registry.register_client(request)
        client2 = await client_registry.register_client(request)

        # Should return the same client
        assert client1.client_id == client2.client_id
        assert client1.client_secret == client2.client_secret

    async def test_register_client_missing_name(self, client_registry):
        """Test client registration fails without name."""
        request = ClientRegistrationRequest(
            client_name="",  # Empty name
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
        )

        with pytest.raises(ValueError, match="client_name is required"):
            await client_registry.register_client(request)

    async def test_register_client_missing_redirect_uris(self, client_registry):
        """Test client registration fails without redirect URIs."""
        request = ClientRegistrationRequest(
            client_name="Test Client",
            redirect_uris=[],  # Empty redirect URIs
            grant_types=["authorization_code"],
            response_types=["code"],
        )

        with pytest.raises(ValueError, match="redirect_uris is required"):
            await client_registry.register_client(request)

    async def test_register_client_invalid_redirect_uri(self, client_registry):
        """Test client registration fails with invalid redirect URI."""
        request = ClientRegistrationRequest(
            client_name="Test Client",
            redirect_uris=["invalid-uri"],  # Invalid URI
            grant_types=["authorization_code"],
            response_types=["code"],
        )

        with pytest.raises(ValueError, match="Invalid redirect URI"):
            await client_registry.register_client(request)

    async def test_register_client_invalid_grant_type(self, client_registry):
        """Test client registration fails with invalid grant type."""
        request = ClientRegistrationRequest(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=["invalid_grant"],  # Invalid grant type
            response_types=["code"],
        )

        with pytest.raises(ValueError, match="Unsupported grant type"):
            await client_registry.register_client(request)

    async def test_register_client_invalid_response_type(self, client_registry):
        """Test client registration fails with invalid response type."""
        request = ClientRegistrationRequest(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=["authorization_code"],
            response_types=["invalid_response"],  # Invalid response type
        )

        with pytest.raises(ValueError, match="Unsupported response type"):
            await client_registry.register_client(request)

    async def test_register_client_invalid_auth_method(self, client_registry):
        """Test client registration fails with invalid auth method."""
        request = ClientRegistrationRequest(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
            token_endpoint_auth_method="invalid_method",  # Invalid auth method
        )

        with pytest.raises(ValueError, match="Unsupported auth method"):
            await client_registry.register_client(request)

    async def test_get_client_exists(self, client_registry):
        """Test getting existing client."""
        request = ClientRegistrationRequest(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
        )

        registered_client = await client_registry.register_client(request)
        retrieved_client = await client_registry.get_client(registered_client.client_id)

        assert retrieved_client is not None
        assert retrieved_client.client_id == registered_client.client_id

    async def test_get_client_not_exists(self, client_registry):
        """Test getting non-existent client."""
        client = await client_registry.get_client("nonexistent_client")
        assert client is None

    async def test_authenticate_client_success(self, client_registry):
        """Test successful client authentication."""
        request = ClientRegistrationRequest(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
        )

        registered_client = await client_registry.register_client(request)
        authenticated_client = await client_registry.authenticate_client(
            registered_client.client_id, registered_client.client_secret
        )

        assert authenticated_client is not None
        assert authenticated_client.client_id == registered_client.client_id

    async def test_authenticate_client_wrong_secret(self, client_registry):
        """Test client authentication with wrong secret."""
        request = ClientRegistrationRequest(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
        )

        registered_client = await client_registry.register_client(request)
        authenticated_client = await client_registry.authenticate_client(
            registered_client.client_id, "wrong_secret"
        )

        assert authenticated_client is None

    async def test_authenticate_client_nonexistent(self, client_registry):
        """Test authentication of non-existent client."""
        authenticated_client = await client_registry.authenticate_client(
            "nonexistent_client", "any_secret"
        )

        assert authenticated_client is None

    async def test_authenticate_client_expired(self, client_registry):
        """Test authentication of expired client."""
        request = ClientRegistrationRequest(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
        )

        registered_client = await client_registry.register_client(request)

        # Update the stored client with past expiration
        from dataclasses import asdict

        registered_client.expires_at = time.time() - 3600
        await client_registry.client_storage.store_client(
            registered_client.client_id, asdict(registered_client)
        )

        authenticated_client = await client_registry.authenticate_client(
            registered_client.client_id, registered_client.client_secret
        )

        assert authenticated_client is None

    async def test_validate_redirect_uri_valid(self, client_registry):
        """Test redirect URI validation for valid URI."""
        request = ClientRegistrationRequest(
            client_name="Test Client",
            redirect_uris=[
                "http://localhost:8080/callback",
                "https://example.com/callback",
            ],
            grant_types=["authorization_code"],
            response_types=["code"],
        )

        client = await client_registry.register_client(request)

        assert (
            await client_registry.validate_redirect_uri(
                client.client_id, "http://localhost:8080/callback"
            )
            is True
        )
        assert (
            await client_registry.validate_redirect_uri(
                client.client_id, "https://example.com/callback"
            )
            is True
        )

    async def test_validate_redirect_uri_invalid(self, client_registry):
        """Test redirect URI validation for invalid URI."""
        request = ClientRegistrationRequest(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
        )

        client = await client_registry.register_client(request)

        assert (
            await client_registry.validate_redirect_uri(
                client.client_id, "https://evil.com/callback"
            )
            is False
        )

    async def test_validate_redirect_uri_nonexistent_client(self, client_registry):
        """Test redirect URI validation for non-existent client."""
        assert (
            await client_registry.validate_redirect_uri(
                "nonexistent", "http://localhost:8080/callback"
            )
            is False
        )

    async def test_validate_grant_type_valid(self, client_registry):
        """Test grant type validation for valid type."""
        request = ClientRegistrationRequest(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
        )

        client = await client_registry.register_client(request)

        assert (
            await client_registry.validate_grant_type(
                client.client_id, "authorization_code"
            )
            is True
        )
        assert (
            await client_registry.validate_grant_type(client.client_id, "refresh_token")
            is True
        )

    async def test_validate_grant_type_invalid(self, client_registry):
        """Test grant type validation for invalid type."""
        request = ClientRegistrationRequest(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
        )

        client = await client_registry.register_client(request)

        assert (
            await client_registry.validate_grant_type(
                client.client_id, "client_credentials"
            )
            is False
        )

    async def test_validate_response_type_valid(self, client_registry):
        """Test response type validation for valid type."""
        request = ClientRegistrationRequest(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
        )

        client = await client_registry.register_client(request)

        assert (
            await client_registry.validate_response_type(client.client_id, "code")
            is True
        )

    async def test_validate_response_type_invalid(self, client_registry):
        """Test response type validation for invalid type."""
        request = ClientRegistrationRequest(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
        )

        client = await client_registry.register_client(request)

        assert (
            await client_registry.validate_response_type(client.client_id, "token")
            is False
        )

    async def test_generate_client_id_format(self, client_registry):
        """Test client ID generation format."""
        client_id = client_registry._generate_client_id()

        assert client_id.startswith("mcp_client_")
        assert len(client_id) > len("mcp_client_")

    async def test_generate_client_secret_length(self, client_registry):
        """Test client secret generation."""
        secret = client_registry._generate_client_secret()

        assert len(secret) > 20  # Should be reasonably long
        assert isinstance(secret, str)

    async def test_is_valid_redirect_uri_localhost_http(self, client_registry):
        """Test redirect URI validation for localhost HTTP."""
        assert (
            client_registry._is_valid_redirect_uri("http://localhost:8080/callback")
            is True
        )
        assert (
            client_registry._is_valid_redirect_uri("http://127.0.0.1:3000/auth") is True
        )

    async def test_is_valid_redirect_uri_https(self, client_registry):
        """Test redirect URI validation for HTTPS."""
        assert (
            client_registry._is_valid_redirect_uri("https://example.com/callback")
            is True
        )
        assert (
            client_registry._is_valid_redirect_uri(
                "https://app.example.com/oauth/callback"
            )
            is True
        )

    async def test_is_valid_redirect_uri_with_fragment(self, client_registry):
        """Test redirect URI validation rejects fragments."""
        assert (
            client_registry._is_valid_redirect_uri(
                "https://example.com/callback#fragment"
            )
            is False
        )
        assert (
            client_registry._is_valid_redirect_uri(
                "http://localhost:8080/callback#test"
            )
            is False
        )

    async def test_is_valid_redirect_uri_custom_schemes(self, client_registry):
        """Test redirect URI validation for custom schemes."""
        assert client_registry._is_valid_redirect_uri("cursor://auth/callback") is True
        assert (
            client_registry._is_valid_redirect_uri("vscode://vscode.git/authenticate")
            is True
        )
        assert client_registry._is_valid_redirect_uri("myapp://oauth/callback") is True

    async def test_is_valid_redirect_uri_invalid(self, client_registry):
        """Test redirect URI validation for invalid URIs."""
        assert client_registry._is_valid_redirect_uri("") is False
        assert client_registry._is_valid_redirect_uri("not-a-uri") is False
        assert client_registry._is_valid_redirect_uri("http://") is False
        assert (
            client_registry._is_valid_redirect_uri("ftp://example.com/callback")
            is False
        )
