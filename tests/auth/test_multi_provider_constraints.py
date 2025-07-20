"""Tests for multiple OAuth provider constraint validation."""

import pytest

from src.auth.provider_manager import ProviderManager
from src.config.config import (
    ConfigManager,
    OAuthProviderConfig,
)


class TestMultipleProviderConstraints:
    """Test cases for multiple provider constraint enforcement."""

    def test_multiple_providers_raises_error(self, multi_provider_config):
        """Test that configuring multiple providers raises ValueError."""
        with pytest.raises(
            ValueError, match="Only one OAuth provider can be configured"
        ):
            ProviderManager(multi_provider_config)

    def test_no_providers_allowed_for_public_only(self):
        """Test that no providers configured is allowed for public-only gateways."""
        # This should now be allowed for public-only gateways
        provider_manager = ProviderManager({})
        assert len(provider_manager.providers) == 0
        assert provider_manager.primary_provider_id == ""

    def test_multiple_providers_error_message_details(self, multi_provider_config):
        """Test that multiple providers error message contains helpful details."""
        with pytest.raises(ValueError) as exc_info:
            ProviderManager(multi_provider_config)

        error_message = str(exc_info.value)
        assert "Found 2 providers" in error_message
        assert "github" in error_message
        assert "google" in error_message
        assert "OAuth 2.1 resource parameter constraints" in error_message


class TestConfigurationConstraints:
    """Test configuration-level constraints."""

    def test_config_multiple_providers_validation(
        self, tmp_path, multi_provider_config
    ):
        """Test that config validation catches multiple providers."""
        # Create a config file with multiple providers
        config_file = tmp_path / "config.yaml"
        config_content = """
host: "0.0.0.0"
port: 8080
issuer: "http://localhost:8080"
session_secret: "test-secret"

oauth_providers:
  github:
    client_id: "github_id"
    client_secret: "github_secret"
    scopes: ["user:email"]
  google:
    client_id: "google_id"
    client_secret: "google_secret"
    scopes: ["openid", "email", "profile"]

mcp_services:
  calculator:
    name: "Calculator"
    url: "http://localhost:3001/mcp"
    oauth_provider: "github"
    auth_required: true
"""
        config_file.write_text(config_content)

        config_manager = ConfigManager(str(config_file))

        with pytest.raises(
            ValueError, match="Only one OAuth provider can be configured"
        ):
            config_manager.load_config()

    def test_config_service_provider_mismatch_validation(self, tmp_path):
        """Test that config validation catches service-provider mismatches."""
        # Create a config file with service referencing wrong provider
        config_file = tmp_path / "config.yaml"
        config_content = """
host: "0.0.0.0"
port: 8080
issuer: "http://localhost:8080"
session_secret: "test-secret"

oauth_providers:
  github:
    client_id: "github_id"
    client_secret: "github_secret"
    scopes: ["user:email"]

mcp_services:
  calculator:
    name: "Calculator"
    url: "http://localhost:3001/mcp"
    oauth_provider: "google"  # Wrong provider!
    auth_required: true
"""
        config_file.write_text(config_content)

        config_manager = ConfigManager(str(config_file))

        with pytest.raises(
            ValueError, match="Service 'calculator' specifies OAuth provider 'google'"
        ):
            config_manager.load_config()

    def test_config_no_providers_with_auth_services_validation(self, tmp_path):
        """Test that config validation catches missing providers when auth is required."""
        # Create a config file with auth-required services but no providers
        config_file = tmp_path / "config.yaml"
        config_content = """
host: "0.0.0.0"
port: 8080
issuer: "http://localhost:8080"
session_secret: "test-secret"

# No oauth_providers section

mcp_services:
  calculator:
    name: "Calculator"
    url: "http://localhost:3001/mcp"
    oauth_provider: "github"
    auth_required: true
"""
        config_file.write_text(config_content)

        config_manager = ConfigManager(str(config_file))

        with pytest.raises(
            ValueError, match="Services \\['calculator'\\] require authentication"
        ):
            config_manager.load_config()

    def test_config_valid_single_provider(self, tmp_path):
        """Test that valid single provider configuration loads successfully."""
        # Create a valid config file with single provider
        config_file = tmp_path / "config.yaml"
        config_content = """
host: "0.0.0.0"
port: 8080
issuer: "http://localhost:8080"
session_secret: "test-secret"

oauth_providers:
  github:
    client_id: "github_id"
    client_secret: "github_secret"
    scopes: ["user:email"]

mcp_services:
  calculator:
    name: "Calculator"
    url: "http://localhost:3001/mcp"
    oauth_provider: "github"
    auth_required: true
  public:
    name: "Public Service"
    url: "http://localhost:3002/mcp"
    auth_required: false
"""
        config_file.write_text(config_content)

        config_manager = ConfigManager(str(config_file))
        config = config_manager.load_config()

        # Should load successfully
        assert len(config.oauth_providers) == 1
        assert "github" in config.oauth_providers
        assert len(config.mcp_services) == 2
        assert config.mcp_services["calculator"].oauth_provider == "github"


class TestBackwardCompatibilityMessages:
    """Test that error messages help users migrate from multi-provider setups."""

    def test_provider_manager_helpful_error_messages(self):
        """Test that ProviderManager gives helpful migration messages."""
        # Test with various multi-provider scenarios
        multi_provider_scenarios = [
            {
                "google": OAuthProviderConfig(client_id="id1", client_secret="secret1"),
                "github": OAuthProviderConfig(client_id="id2", client_secret="secret2"),
            },
            {
                "google": OAuthProviderConfig(client_id="id1", client_secret="secret1"),
                "github": OAuthProviderConfig(client_id="id2", client_secret="secret2"),
                "okta": OAuthProviderConfig(
                    client_id="id3",
                    client_secret="secret3",
                    authorization_url="https://dev.okta.com/oauth2/default/v1/authorize",
                ),
            },
        ]

        for config in multi_provider_scenarios:
            with pytest.raises(ValueError) as exc_info:
                ProviderManager(config)

            error_message = str(exc_info.value)

            # Should mention OAuth 2.1 constraints
            assert "OAuth 2.1 resource parameter constraints" in error_message

            # Should mention number of providers found
            assert f"Found {len(config)} providers" in error_message

            # Should list the provider names
            for provider_name in config.keys():
                assert provider_name in error_message

    def test_service_provider_mismatch_helpful_error(
        self, single_google_provider_config
    ):
        """Test that service-provider mismatch gives helpful error message."""
        provider_manager = ProviderManager(single_google_provider_config)

        with pytest.raises(ValueError) as exc_info:
            provider_manager.get_provider_for_service("github")

        error_message = str(exc_info.value)
        assert "Service requests provider 'github'" in error_message
        assert "but only 'google' is configured" in error_message
        assert "All services must use the same OAuth provider" in error_message
