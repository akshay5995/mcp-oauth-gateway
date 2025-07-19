"""Tests for provider manager functionality."""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.auth.models import UserInfo
from src.auth.provider_manager import (
    CustomOAuthProvider,
    GitHubOAuthProvider,
    GoogleOAuthProvider,
    OktaOAuthProvider,
)
from src.config.config import OAuthProviderConfig


class TestProviderManager:
    """Test cases for ProviderManager."""

    def test_provider_manager_initialization(self, provider_manager):
        """Test provider manager initializes correctly with single provider."""
        assert len(provider_manager.providers) == 1
        assert "github" in provider_manager.providers
        assert isinstance(provider_manager.providers["github"], GitHubOAuthProvider)
        assert provider_manager.primary_provider_id == "github"

    def test_get_provider_exists(self, provider_manager):
        """Test getting existing provider."""
        provider = provider_manager.get_provider("github")
        assert provider is not None
        assert isinstance(provider, GitHubOAuthProvider)

    def test_get_provider_not_exists(self, provider_manager):
        """Test getting non-existent provider."""
        provider = provider_manager.get_provider("nonexistent")
        assert provider is None

    def test_get_provider_for_service(self, provider_manager):
        """Test getting provider for service with correct provider."""
        provider = provider_manager.get_provider_for_service("github")
        assert provider is not None
        assert isinstance(provider, GitHubOAuthProvider)
    
    def test_get_provider_for_service_wrong_provider(self, provider_manager):
        """Test getting provider for service with wrong provider raises error."""
        with pytest.raises(ValueError, match="Service requests provider 'google' but only 'github' is configured"):
            provider_manager.get_provider_for_service("google")

    def test_generate_callback_state(self, provider_manager):
        """Test callback state generation with correct provider."""
        state = provider_manager.generate_callback_state("github", "oauth_state_123")
        assert state == "github:oauth_state_123"
    
    def test_generate_callback_state_wrong_provider(self, provider_manager):
        """Test callback state generation with wrong provider raises error."""
        with pytest.raises(ValueError, match="Cannot generate callback state for provider 'google'"):
            provider_manager.generate_callback_state("google", "oauth_state_123")

    def test_parse_callback_state_valid(self, provider_manager):
        """Test parsing valid callback state."""
        provider_id, oauth_state = provider_manager.parse_callback_state(
            "github:oauth_state_123"
        )
        assert provider_id == "github"
        assert oauth_state == "oauth_state_123"

    def test_parse_callback_state_invalid(self, provider_manager):
        """Test parsing invalid callback state."""
        provider_id, oauth_state = provider_manager.parse_callback_state(
            "invalid_state"
        )
        assert provider_id == ""
        assert oauth_state == "invalid_state"

    @pytest.mark.asyncio
    async def test_handle_provider_callback_success(self, provider_manager):
        """Test successful provider callback handling."""
        mock_provider = AsyncMock()
        mock_provider.exchange_code_for_token.return_value = {
            "access_token": "test_token"
        }
        mock_provider.get_user_info.return_value = UserInfo(
            id="test_user",
            email="test@example.com",
            name="Test User",
            provider="github",
        )

        provider_manager.providers["github"] = mock_provider

        user_info = await provider_manager.handle_provider_callback(
            "github", "auth_code", "http://localhost:8080/callback"
        )

        assert user_info.id == "test_user"
        assert user_info.email == "test@example.com"
        mock_provider.exchange_code_for_token.assert_called_once_with(
            "auth_code", "http://localhost:8080/callback"
        )
        mock_provider.get_user_info.assert_called_once_with("test_token")

    @pytest.mark.asyncio
    async def test_handle_provider_callback_unknown_provider(self, provider_manager):
        """Test callback with unknown provider."""
        with pytest.raises(ValueError, match="Callback received for provider 'unknown' but only 'github' is configured"):
            await provider_manager.handle_provider_callback(
                "unknown", "auth_code", "http://localhost:8080/callback"
            )

    @pytest.mark.asyncio
    async def test_handle_provider_callback_no_access_token(self, provider_manager):
        """Test callback with no access token in response."""
        mock_provider = AsyncMock()
        mock_provider.exchange_code_for_token.return_value = {}  # No access token

        provider_manager.providers["github"] = mock_provider

        with pytest.raises(ValueError, match="No access token received from provider"):
            await provider_manager.handle_provider_callback(
                "github", "auth_code", "http://localhost:8080/callback"
            )


class TestGoogleOAuthProvider:
    """Test cases for GoogleOAuthProvider."""

    def test_google_provider_initialization(self):
        """Test Google provider initializes with defaults."""
        config = OAuthProviderConfig(client_id="test_id", client_secret="test_secret")

        provider = GoogleOAuthProvider(config)

        assert (
            provider.config.authorization_url
            == "https://accounts.google.com/o/oauth2/v2/auth"
        )
        assert provider.config.token_url == "https://oauth2.googleapis.com/token"
        assert (
            provider.config.userinfo_url
            == "https://www.googleapis.com/oauth2/v2/userinfo"
        )
        assert provider.config.scopes == ["openid", "email", "profile"]

    def test_google_get_authorization_url(self):
        """Test Google authorization URL generation."""
        config = OAuthProviderConfig(
            client_id="test_id", client_secret="test_secret", scopes=["openid", "email"]
        )

        provider = GoogleOAuthProvider(config)
        url = provider.get_authorization_url(
            "test_state", "http://localhost:8080/callback"
        )

        assert "accounts.google.com" in url
        assert "client_id=test_id" in url
        assert "redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback" in url
        assert "scope=openid+email" in url
        assert "state=test_state" in url
        assert "access_type=offline" in url
        assert "prompt=consent" in url

    @pytest.mark.asyncio
    async def test_google_exchange_code_for_token_success(self):
        """Test successful Google token exchange."""
        config = OAuthProviderConfig(client_id="test_id", client_secret="test_secret")

        provider = GoogleOAuthProvider(config)

        mock_response = Mock()
        mock_response.json.return_value = {
            "access_token": "test_token",
            "token_type": "Bearer",
        }
        mock_response.raise_for_status.return_value = None

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post.return_value = (
                mock_response
            )

            result = await provider.exchange_code_for_token(
                "auth_code", "http://localhost:8080/callback"
            )

            assert result["access_token"] == "test_token"

    @pytest.mark.asyncio
    async def test_google_get_user_info_success(self):
        """Test successful Google user info retrieval."""
        config = OAuthProviderConfig(client_id="test_id", client_secret="test_secret")

        provider = GoogleOAuthProvider(config)

        mock_response = Mock()
        mock_response.json.return_value = {
            "id": "123456789",
            "email": "test@gmail.com",
            "name": "Test User",
            "picture": "https://example.com/avatar.jpg",
        }
        mock_response.raise_for_status.return_value = None

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get.return_value = (
                mock_response
            )

            user_info = await provider.get_user_info("test_token")

            assert user_info.id == "123456789"
            assert user_info.email == "test@gmail.com"
            assert user_info.name == "Test User"
            assert user_info.provider == "google"
            assert user_info.avatar_url == "https://example.com/avatar.jpg"


class TestGitHubOAuthProvider:
    """Test cases for GitHubOAuthProvider."""

    def test_github_provider_initialization(self):
        """Test GitHub provider initializes with defaults."""
        config = OAuthProviderConfig(client_id="test_id", client_secret="test_secret")

        provider = GitHubOAuthProvider(config)

        assert (
            provider.config.authorization_url
            == "https://github.com/login/oauth/authorize"
        )
        assert (
            provider.config.token_url == "https://github.com/login/oauth/access_token"
        )
        assert provider.config.userinfo_url == "https://api.github.com/user"
        assert provider.config.scopes == ["user:email"]

    def test_github_get_authorization_url(self):
        """Test GitHub authorization URL generation."""
        config = OAuthProviderConfig(
            client_id="test_id",
            client_secret="test_secret",
            scopes=["user:email", "read:org"],
        )

        provider = GitHubOAuthProvider(config)
        url = provider.get_authorization_url(
            "test_state", "http://localhost:8080/callback"
        )

        assert "github.com/login/oauth/authorize" in url
        assert "client_id=test_id" in url
        assert "redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback" in url
        assert "scope=user%3Aemail+read%3Aorg" in url
        assert "state=test_state" in url

    @pytest.mark.asyncio
    async def test_github_get_user_info_with_public_email(self):
        """Test GitHub user info retrieval with public email."""
        config = OAuthProviderConfig(client_id="test_id", client_secret="test_secret")

        provider = GitHubOAuthProvider(config)

        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 123456,
            "login": "testuser",
            "name": "Test User",
            "email": "test@example.com",
            "avatar_url": "https://avatars.githubusercontent.com/u/123456",
        }
        mock_response.raise_for_status.return_value = None

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get.return_value = (
                mock_response
            )

            user_info = await provider.get_user_info("test_token")

            assert user_info.id == "123456"
            assert user_info.email == "test@example.com"
            assert user_info.name == "Test User"
            assert user_info.provider == "github"

    @pytest.mark.asyncio
    async def test_github_get_user_info_with_private_email(self):
        """Test GitHub user info retrieval with private email."""
        config = OAuthProviderConfig(client_id="test_id", client_secret="test_secret")

        provider = GitHubOAuthProvider(config)

        # Mock user info response without email
        mock_user_response = Mock()
        mock_user_response.json.return_value = {
            "id": 123456,
            "login": "testuser",
            "name": "Test User",
            "email": None,  # Private email
            "avatar_url": "https://avatars.githubusercontent.com/u/123456",
        }
        mock_user_response.raise_for_status.return_value = None

        # Mock emails endpoint response
        mock_email_response = Mock()
        mock_email_response.status_code = 200
        mock_email_response.json.return_value = [
            {"email": "secondary@example.com", "primary": False},
            {"email": "primary@example.com", "primary": True},
        ]

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.get.side_effect = [mock_user_response, mock_email_response]

            user_info = await provider.get_user_info("test_token")

            assert user_info.id == "123456"
            assert user_info.email == "primary@example.com"  # Primary email
            assert user_info.name == "Test User"
            assert user_info.provider == "github"


class TestOktaOAuthProvider:
    """Test cases for OktaOAuthProvider."""

    def test_okta_provider_initialization_success(self):
        """Test Okta provider initialization with valid config."""
        config = OAuthProviderConfig(
            client_id="test_id",
            client_secret="test_secret",
            authorization_url="https://dev-123.okta.com/oauth2/default/v1/authorize",
        )

        provider = OktaOAuthProvider(config)

        assert (
            provider.config.token_url
            == "https://dev-123.okta.com/oauth2/default/v1/token"
        )
        assert (
            provider.config.userinfo_url
            == "https://dev-123.okta.com/oauth2/default/v1/userinfo"
        )
        assert provider.config.scopes == ["openid", "email", "profile"]

    def test_okta_provider_initialization_missing_url(self):
        """Test Okta provider initialization fails without authorization URL."""
        config = OAuthProviderConfig(client_id="test_id", client_secret="test_secret")

        with pytest.raises(
            ValueError, match="authorization_url is required for Okta provider"
        ):
            OktaOAuthProvider(config)


class TestCustomOAuthProvider:
    """Test cases for CustomOAuthProvider."""

    def test_custom_provider_get_authorization_url_success(self):
        """Test custom provider authorization URL generation."""
        config = OAuthProviderConfig(
            client_id="test_id",
            client_secret="test_secret",
            authorization_url="https://custom.example.com/oauth/authorize",
            scopes=["read", "write"],
        )

        provider = CustomOAuthProvider(config)
        url = provider.get_authorization_url(
            "test_state", "http://localhost:8080/callback"
        )

        assert "custom.example.com/oauth/authorize" in url
        assert "client_id=test_id" in url
        assert "scope=read+write" in url

    def test_custom_provider_get_authorization_url_missing_url(self):
        """Test custom provider fails without authorization URL."""
        config = OAuthProviderConfig(client_id="test_id", client_secret="test_secret")

        provider = CustomOAuthProvider(config)

        with pytest.raises(
            ValueError, match="authorization_url is required for custom provider"
        ):
            provider.get_authorization_url(
                "test_state", "http://localhost:8080/callback"
            )

    @pytest.mark.asyncio
    async def test_custom_provider_get_user_info_standard_fields(self):
        """Test custom provider user info with standard field names."""
        config = OAuthProviderConfig(
            client_id="test_id",
            client_secret="test_secret",
            userinfo_url="https://custom.example.com/oauth/userinfo",
        )

        provider = CustomOAuthProvider(config)

        mock_response = Mock()
        mock_response.json.return_value = {
            "id": "user123",
            "email": "test@custom.com",
            "name": "Custom User",
            "avatar_url": "https://custom.example.com/avatar.jpg",
        }
        mock_response.raise_for_status.return_value = None

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get.return_value = (
                mock_response
            )

            user_info = await provider.get_user_info("test_token")

            assert user_info.id == "user123"
            assert user_info.email == "test@custom.com"
            assert user_info.name == "Custom User"
            assert user_info.provider == "custom"
            assert user_info.avatar_url == "https://custom.example.com/avatar.jpg"

    @pytest.mark.asyncio
    async def test_custom_provider_get_user_info_alternative_fields(self):
        """Test custom provider user info with alternative field names."""
        config = OAuthProviderConfig(
            client_id="test_id",
            client_secret="test_secret",
            userinfo_url="https://custom.example.com/oauth/userinfo",
        )

        provider = CustomOAuthProvider(config)

        mock_response = Mock()
        mock_response.json.return_value = {
            "sub": "user123",  # Alternative to 'id'
            "email": "test@custom.com",
            "display_name": "Custom User",  # Alternative to 'name'
            "picture": "https://custom.example.com/pic.jpg",  # Alternative to 'avatar_url'
        }
        mock_response.raise_for_status.return_value = None

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get.return_value = (
                mock_response
            )

            user_info = await provider.get_user_info("test_token")

            assert user_info.id == "user123"
            assert user_info.email == "test@custom.com"
            assert user_info.name == "Custom User"
            assert user_info.provider == "custom"
            assert user_info.avatar_url == "https://custom.example.com/pic.jpg"
