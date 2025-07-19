"""Tests for OAuth server functionality."""

import pytest

from src.auth.models import (
    AuthorizeRequest,
    ClientRegistrationRequest,
    GrantType,
    ResponseType,
    TokenRequest,
    UserInfo,
)
from tests.utils.crypto_helpers import create_invalid_code_challenge, generate_pkce_pair


class TestOAuthServer:
    """Test cases for OAuthServer."""

    def test_oauth_server_initialization(self, oauth_server):
        """Test OAuth server initializes correctly."""
        assert oauth_server.secret_key == "test-secret-key-for-testing-only"
        assert oauth_server.issuer == "http://localhost:8080"
        assert oauth_server.client_registry is not None
        assert oauth_server.token_manager is not None
        assert isinstance(oauth_server.authorization_codes, dict)
        assert isinstance(oauth_server.oauth_states, dict)
        assert isinstance(oauth_server.user_sessions, dict)

    @pytest.mark.asyncio
    async def test_handle_authorize_invalid_client(self, oauth_server):
        """Test authorization with invalid client."""
        request = AuthorizeRequest(
            response_type=ResponseType.CODE,
            client_id="invalid_client",
            redirect_uri="http://localhost:8080/callback",
            scope="read",
            state="test_state",
            code_challenge="test_challenge",
            code_challenge_method="S256",
        )

        redirect_url, error = await oauth_server.handle_authorize(request)

        assert redirect_url == ""
        assert error is not None
        assert error.error == "invalid_client"

    @pytest.mark.asyncio
    async def test_handle_authorize_valid_client(self, oauth_server):
        """Test authorization with valid client."""
        # Register a client first
        registration_request = ClientRegistrationRequest(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
        )

        client_info = oauth_server.client_registry.register_client(registration_request)

        # Create authorization request
        request = AuthorizeRequest(
            response_type="code",
            client_id=client_info.client_id,
            redirect_uri="http://localhost:8080/callback",
            scope="read",
            state="test_state",
            code_challenge="test_challenge",
            code_challenge_method="S256",
            resource="http://localhost:8080/calculator",
        )

        provider_state, error = await oauth_server.handle_authorize(request)

        assert error is None
        assert provider_state is not None
        assert len(provider_state) > 0

        # Check that OAuth state was stored
        oauth_state = oauth_server.oauth_states.get(provider_state)
        assert oauth_state is not None
        assert oauth_state.client_id == client_info.client_id
        assert oauth_state.redirect_uri == "http://localhost:8080/callback"
        assert oauth_state.scope == "read"
        assert oauth_state.client_state == "test_state"

    @pytest.mark.asyncio
    async def test_handle_authorize_invalid_redirect_uri(self, oauth_server):
        """Test authorization with invalid redirect URI."""
        # Register a client first
        registration_request = ClientRegistrationRequest(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
        )

        client_info = oauth_server.client_registry.register_client(registration_request)

        # Create authorization request with invalid redirect URI
        request = AuthorizeRequest(
            response_type="code",
            client_id=client_info.client_id,
            redirect_uri="http://evil.com/callback",  # Invalid redirect URI
            scope="read",
            state="test_state",
            code_challenge="test_challenge",
            code_challenge_method="S256",
        )

        provider_state, error = await oauth_server.handle_authorize(request)

        assert provider_state == ""
        assert error is not None
        assert error.error == "invalid_request"
        assert "Invalid redirect URI" in error.error_description

    @pytest.mark.asyncio
    async def test_handle_token_exchange_success(self, oauth_server):
        """Test successful token exchange."""
        # Register a client
        registration_request = ClientRegistrationRequest(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
        )

        client_info = oauth_server.client_registry.register_client(registration_request)

        # Create and store OAuth state and authorization code
        code_verifier, code_challenge = generate_pkce_pair()

        from src.auth.models import OAuthState

        oauth_state = OAuthState(
            state="test_state",
            client_state="client_state",
            client_id=client_info.client_id,
            redirect_uri="http://localhost:8080/callback",
            scope="read",
            resource="http://localhost:8080/calculator",
            code_challenge=code_challenge,
            code_challenge_method="S256",
            provider="github",
        )

        # Create user info and session
        user_info = UserInfo(
            id="test_user_123",
            email="test@example.com",
            name="Test User",
            provider="github",
        )
        user_id = "github:test_user_123"
        oauth_server.store_user_session(user_id, user_info)

        # Create authorization code
        auth_code = oauth_server.create_authorization_code(user_id, oauth_state)

        # Create token request
        token_request = TokenRequest(
            grant_type="authorization_code",
            code=auth_code,
            redirect_uri="http://localhost:8080/callback",
            client_id=client_info.client_id,
            client_secret=client_info.client_secret,
            code_verifier=code_verifier,
            resource="http://localhost:8080/calculator",
        )

        token_response, error = await oauth_server.handle_token(token_request)

        assert error is None
        assert token_response is not None
        assert token_response.access_token is not None
        assert token_response.token_type == "Bearer"
        assert token_response.expires_in == 3600
        assert token_response.scope == "read"

    @pytest.mark.asyncio
    async def test_handle_token_exchange_invalid_code(self, oauth_server):
        """Test token exchange with invalid authorization code."""
        # Register a client
        registration_request = ClientRegistrationRequest(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
        )

        client_info = oauth_server.client_registry.register_client(registration_request)

        # Create token request with invalid code
        token_request = TokenRequest(
            grant_type=GrantType.AUTHORIZATION_CODE,
            code="invalid_code",
            redirect_uri="http://localhost:8080/callback",
            client_id=client_info.client_id,
            client_secret=client_info.client_secret,
            code_verifier="invalid_verifier",
        )

        token_response, error = await oauth_server.handle_token(token_request)

        assert token_response is None
        assert error is not None
        assert error.error == "invalid_grant"

    @pytest.mark.asyncio
    async def test_handle_token_exchange_invalid_code_verifier(self, oauth_server):
        """Test token exchange with invalid PKCE code verifier."""
        # Register a client
        registration_request = ClientRegistrationRequest(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
        )

        client_info = oauth_server.client_registry.register_client(registration_request)

        # Create and store OAuth state and authorization code
        code_verifier, code_challenge = generate_pkce_pair()

        from src.auth.models import OAuthState

        oauth_state = OAuthState(
            state="test_state",
            client_state="client_state",
            client_id=client_info.client_id,
            redirect_uri="http://localhost:8080/callback",
            scope="read",
            resource=None,
            code_challenge=code_challenge,
            code_challenge_method="S256",
            provider="github",
        )

        # Create user info and session
        user_info = UserInfo(
            id="test_user_123",
            email="test@example.com",
            name="Test User",
            provider="github",
        )
        user_id = "github:test_user_123"
        oauth_server.store_user_session(user_id, user_info)

        # Create authorization code
        auth_code = oauth_server.create_authorization_code(user_id, oauth_state)

        # Create token request with wrong code verifier
        token_request = TokenRequest(
            grant_type="authorization_code",
            code=auth_code,
            redirect_uri="http://localhost:8080/callback",
            client_id=client_info.client_id,
            client_secret=client_info.client_secret,
            code_verifier="wrong_verifier",  # Wrong verifier
        )

        token_response, error = await oauth_server.handle_token(token_request)

        assert token_response is None
        assert error is not None
        assert error.error == "invalid_grant"
        assert "Invalid code verifier" in error.error_description

    def test_create_authorization_code(self, oauth_server):
        """Test authorization code creation."""
        # Create OAuth state
        from src.auth.models import OAuthState

        oauth_state = OAuthState(
            state="test_state",
            client_state="client_state",
            client_id="test_client",
            redirect_uri="http://localhost:8080/callback",
            scope="read write",
            resource="http://localhost:8080/calculator",
            code_challenge="test_challenge",
            code_challenge_method="S256",
            provider="github",
        )

        user_id = "github:test_user_123"

        auth_code = oauth_server.create_authorization_code(user_id, oauth_state)

        assert auth_code is not None
        assert len(auth_code) > 0
        assert auth_code in oauth_server.authorization_codes

        stored_code = oauth_server.authorization_codes[auth_code]
        assert stored_code.client_id == "test_client"
        assert stored_code.user_id == user_id
        assert stored_code.scope == "read write"
        assert stored_code.code_challenge == "test_challenge"
        assert stored_code.code_challenge_method == "S256"
        assert stored_code.resource == "http://localhost:8080/calculator"

    def test_verify_pkce_success(self, oauth_server):
        """Test successful PKCE verification."""
        code_verifier, code_challenge = generate_pkce_pair()

        result = oauth_server._verify_pkce(code_verifier, code_challenge)
        assert result is True

    def test_verify_pkce_failure(self, oauth_server):
        """Test failed PKCE verification."""
        code_verifier, _ = generate_pkce_pair()
        wrong_challenge = create_invalid_code_challenge()

        result = oauth_server._verify_pkce(code_verifier, wrong_challenge)
        assert result is False

    def test_verify_pkce_with_different_verifier(self, oauth_server):
        """Test PKCE verification with different verifier."""
        code_verifier1, code_challenge = generate_pkce_pair()
        code_verifier2, _ = generate_pkce_pair()  # Different verifier

        # Should fail with different verifier
        result = oauth_server._verify_pkce(code_verifier2, code_challenge)
        assert result is False
