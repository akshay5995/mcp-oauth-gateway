"""Tests for single OAuth provider constraint enforcement."""

from unittest.mock import AsyncMock

import pytest

from src.auth.models import UserInfo
from src.auth.provider_manager import (
    GitHubOAuthProvider,
    GoogleOAuthProvider,
    ProviderManager,
)
from src.config.config import OAuthProviderConfig


class TestSingleProviderConstraint:
    """Test cases for single provider constraint enforcement."""

    def test_single_provider_initialization_success(self):
        """Test that a single provider initializes successfully."""
        config = {
            "google": OAuthProviderConfig(
                client_id="google_client_id",
                client_secret="google_client_secret",
                scopes=["openid", "email", "profile"],
            )
        }

        provider_manager = ProviderManager(config)

        assert len(provider_manager.providers) == 1
        assert "google" in provider_manager.providers
        assert provider_manager.primary_provider_id == "google"
        assert isinstance(provider_manager.providers["google"], GoogleOAuthProvider)

    def test_multiple_providers_raises_error(self):
        """Test that configuring multiple providers raises ValueError."""
        config = {
            "google": OAuthProviderConfig(
                client_id="google_client_id",
                client_secret="google_client_secret",
            ),
            "github": OAuthProviderConfig(
                client_id="github_client_id",
                client_secret="github_client_secret",
            ),
        }

        with pytest.raises(
            ValueError, match="Only one OAuth provider can be configured"
        ):
            ProviderManager(config)

    def test_no_providers_allowed_for_public_only(self):
        """Test that no providers configured is allowed for public-only gateways."""
        config = {}

        # This should now be allowed for public-only gateways
        provider_manager = ProviderManager(config)
        assert len(provider_manager.providers) == 0
        assert provider_manager.primary_provider_id == ""

        # Should return None for provider requests
        assert provider_manager.get_provider_for_service(None) is None
        assert provider_manager.get_provider_for_service("") is None

    def test_get_primary_provider_methods(self):
        """Test primary provider access methods."""
        config = {
            "github": OAuthProviderConfig(
                client_id="github_client_id",
                client_secret="github_client_secret",
            )
        }

        provider_manager = ProviderManager(config)

        assert provider_manager.get_primary_provider_id() == "github"

        primary_provider = provider_manager.get_primary_provider()
        assert primary_provider is not None
        assert isinstance(primary_provider, GitHubOAuthProvider)

        # Should be the same as get_provider
        assert primary_provider == provider_manager.get_provider("github")

    def test_get_provider_for_service_validates_provider(self):
        """Test that get_provider_for_service validates the requested provider."""
        config = {
            "google": OAuthProviderConfig(
                client_id="google_client_id",
                client_secret="google_client_secret",
            )
        }

        provider_manager = ProviderManager(config)

        # Should work with correct provider
        provider = provider_manager.get_provider_for_service("google")
        assert provider is not None

        # Should raise error with wrong provider
        with pytest.raises(
            ValueError,
            match="Service requests provider 'github' but only 'google' is configured",
        ):
            provider_manager.get_provider_for_service("github")

    def test_generate_callback_state_validates_provider(self):
        """Test that callback state generation validates provider ID."""
        config = {
            "google": OAuthProviderConfig(
                client_id="google_client_id",
                client_secret="google_client_secret",
            )
        }

        provider_manager = ProviderManager(config)

        # Should work with correct provider
        state = provider_manager.generate_callback_state("google", "oauth_state_123")
        assert state == "google:oauth_state_123"

        # Should raise error with wrong provider
        with pytest.raises(
            ValueError, match="Cannot generate callback state for provider 'github'"
        ):
            provider_manager.generate_callback_state("github", "oauth_state_123")

    @pytest.mark.asyncio
    async def test_handle_provider_callback_validates_provider(self):
        """Test that provider callback handling validates provider ID."""
        config = {
            "google": OAuthProviderConfig(
                client_id="google_client_id",
                client_secret="google_client_secret",
            )
        }

        provider_manager = ProviderManager(config)

        # Mock the provider
        mock_provider = AsyncMock()
        mock_provider.exchange_code_for_token.return_value = {
            "access_token": "test_token"
        }
        mock_provider.get_user_info.return_value = UserInfo(
            id="user_123",
            email="user@example.com",
            name="Test User",
            provider="google",
        )
        provider_manager.providers["google"] = mock_provider

        # Should work with correct provider
        user_info = await provider_manager.handle_provider_callback(
            "google", "auth_code", "http://localhost:8080/callback"
        )
        assert user_info.provider == "google"

        # Should raise error with wrong provider
        with pytest.raises(
            ValueError,
            match="Callback received for provider 'github' but only 'google' is configured",
        ):
            await provider_manager.handle_provider_callback(
                "github", "auth_code", "http://localhost:8080/callback"
            )


class TestSingleProviderTypes:
    """Test different single provider type configurations."""

    @pytest.mark.parametrize(
        "provider_type,provider_class",
        [
            ("google", GoogleOAuthProvider),
            ("github", GitHubOAuthProvider),
        ],
    )
    def test_single_provider_types(self, provider_type, provider_class):
        """Test initialization of different single provider types."""
        config = {
            provider_type: OAuthProviderConfig(
                client_id=f"{provider_type}_client_id",
                client_secret=f"{provider_type}_client_secret",
            )
        }

        provider_manager = ProviderManager(config)

        assert len(provider_manager.providers) == 1
        assert provider_type in provider_manager.providers
        assert provider_manager.primary_provider_id == provider_type
        assert isinstance(provider_manager.providers[provider_type], provider_class)

    def test_custom_provider_configuration(self):
        """Test custom provider as single provider."""
        from src.auth.provider_manager import CustomOAuthProvider

        config = {
            "custom": OAuthProviderConfig(
                client_id="custom_client_id",
                client_secret="custom_client_secret",
                authorization_url="https://custom.example.com/oauth/authorize",
                token_url="https://custom.example.com/oauth/token",
                userinfo_url="https://custom.example.com/oauth/userinfo",
                scopes=["read", "write"],
            )
        }

        provider_manager = ProviderManager(config)

        assert len(provider_manager.providers) == 1
        assert "custom" in provider_manager.providers
        assert provider_manager.primary_provider_id == "custom"
        assert isinstance(provider_manager.providers["custom"], CustomOAuthProvider)


class TestSingleProviderCallbacks:
    """Test OAuth callbacks with single provider constraint."""

    @pytest.fixture
    def single_provider_manager(self):
        """Provider manager with single Google provider."""
        config = {
            "google": OAuthProviderConfig(
                client_id="google_client_id",
                client_secret="google_client_secret",
            )
        }
        return ProviderManager(config)

    @pytest.mark.asyncio
    async def test_successful_provider_callback(self, single_provider_manager):
        """Test successful provider callback with single provider."""
        # Mock the provider
        mock_provider = AsyncMock()
        mock_provider.exchange_code_for_token.return_value = {
            "access_token": "google_token"
        }
        mock_provider.get_user_info.return_value = UserInfo(
            id="google_user_123",
            email="user@gmail.com",
            name="Google User",
            provider="google",
            avatar_url="https://lh3.googleusercontent.com/avatar.jpg",
        )

        single_provider_manager.providers["google"] = mock_provider

        user_info = await single_provider_manager.handle_provider_callback(
            "google", "auth_code", "http://localhost:8080/callback"
        )

        assert user_info.id == "google_user_123"
        assert user_info.email == "user@gmail.com"
        assert user_info.provider == "google"
        mock_provider.exchange_code_for_token.assert_called_once()
        mock_provider.get_user_info.assert_called_once_with("google_token")

    @pytest.mark.asyncio
    async def test_provider_callback_with_invalid_token(self, single_provider_manager):
        """Test provider callback with invalid token response."""
        # Mock provider with no access token
        mock_provider = AsyncMock()
        mock_provider.exchange_code_for_token.return_value = {}  # No access_token

        single_provider_manager.providers["google"] = mock_provider

        with pytest.raises(ValueError, match="No access token received from provider"):
            await single_provider_manager.handle_provider_callback(
                "google", "auth_code", "http://localhost:8080/callback"
            )

    @pytest.mark.asyncio
    async def test_provider_callback_network_error(self, single_provider_manager):
        """Test provider callback with network error."""
        # Mock provider with network error
        mock_provider = AsyncMock()
        mock_provider.exchange_code_for_token.side_effect = Exception("Network error")

        single_provider_manager.providers["google"] = mock_provider

        with pytest.raises(Exception, match="Network error"):
            await single_provider_manager.handle_provider_callback(
                "google", "auth_code", "http://localhost:8080/callback"
            )


class TestBackwardCompatibility:
    """Test backward compatibility and error messages."""

    def test_helpful_error_messages(self):
        """Test that error messages are helpful for migration."""
        # Multiple providers error should be clear
        config = {
            "google": OAuthProviderConfig(client_id="id1", client_secret="secret1"),
            "github": OAuthProviderConfig(client_id="id2", client_secret="secret2"),
            "okta": OAuthProviderConfig(client_id="id3", client_secret="secret3"),
        }

        with pytest.raises(ValueError) as exc_info:
            ProviderManager(config)

        error_message = str(exc_info.value)
        assert "Only one OAuth provider can be configured" in error_message
        assert "Found 3 providers" in error_message
        assert (
            "google" in error_message
            and "github" in error_message
            and "okta" in error_message
        )
        assert "OAuth 2.1 resource parameter constraints" in error_message

    def test_service_provider_mismatch_error(self):
        """Test error when service requests wrong provider."""
        config = {
            "google": OAuthProviderConfig(
                client_id="google_client_id",
                client_secret="google_client_secret",
            )
        }

        provider_manager = ProviderManager(config)

        with pytest.raises(ValueError) as exc_info:
            provider_manager.get_provider_for_service("github")

        error_message = str(exc_info.value)
        assert "Service requests provider 'github'" in error_message
        assert "but only 'google' is configured" in error_message
        assert "All services must use the same OAuth provider" in error_message
