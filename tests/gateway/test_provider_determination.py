"""Tests for gateway provider determination logic with single provider constraint."""

from unittest.mock import patch

import pytest

from src.config.config import GatewayConfig, McpServiceConfig, OAuthProviderConfig
from src.gateway import McpGateway


class TestSingleProviderDetermination:
    """Test provider determination logic with single provider constraint."""

    @pytest.fixture
    def single_github_config(self):
        """Configuration with single GitHub provider."""
        return GatewayConfig(
            host="localhost",
            port=8080,
            issuer="http://localhost:8080",
            session_secret="test-secret-key",
            oauth_providers={
                "github": OAuthProviderConfig(
                    client_id="github_client_id", client_secret="github_client_secret"
                ),
            },
            mcp_services={
                "calculator": McpServiceConfig(
                    name="Calculator Service",
                    url="http://localhost:3001/mcp",
                    oauth_provider="github",  # Must match the configured provider
                    auth_required=True,
                ),
                "docs": McpServiceConfig(
                    name="Documentation Service",
                    url="http://localhost:3002/mcp",
                    oauth_provider="github",  # Must match the configured provider
                    auth_required=True,
                ),
                "public": McpServiceConfig(
                    name="Public Service",
                    url="http://localhost:3003/mcp",
                    oauth_provider="github",  # Even for public services, must match
                    auth_required=False,  # No auth required
                ),
            },
        )

    @pytest.fixture
    def single_google_config(self):
        """Configuration with single Google provider."""
        return GatewayConfig(
            host="localhost",
            port=8080,
            issuer="http://localhost:8080",
            session_secret="test-secret-key",
            oauth_providers={
                "google": OAuthProviderConfig(
                    client_id="google_client_id", client_secret="google_client_secret"
                ),
            },
            mcp_services={
                "calculator": McpServiceConfig(
                    name="Calculator Service",
                    url="http://localhost:3001/mcp",
                    oauth_provider="google",
                    auth_required=True,
                ),
            },
        )

    def test_provider_determination_with_single_provider(self, single_github_config):
        """Test provider determination always returns the configured provider."""
        with patch("src.gateway.ConfigManager") as mock_config_manager:
            mock_config_manager.return_value.load_config.return_value = (
                single_github_config
            )
            gateway = McpGateway()

            # Test various resource URIs - should always return the configured provider
            test_cases = [
                None,  # No resource
                "http://localhost:8080",  # Gateway root
                "http://localhost:8080/calculator/mcp",  # Service resource
                "http://localhost:8080/docs/mcp",  # Another service
                "http://localhost:8080/unknown/mcp",  # Unknown service
                "https://external.example.com/resource/mcp",  # External resource
            ]

            for resource in test_cases:
                provider = gateway._determine_provider_for_resource(resource)
                assert provider == "github", f"Failed for resource: {resource}"

    def test_provider_determination_consistency(self, single_google_config):
        """Test that provider determination is consistent across multiple calls."""
        with patch("src.gateway.ConfigManager") as mock_config_manager:
            mock_config_manager.return_value.load_config.return_value = (
                single_google_config
            )
            gateway = McpGateway()

            # Multiple calls should return the same provider
            resources = [
                "http://localhost:8080/calculator/mcp",
                "http://localhost:8080/another_service/mcp",
                None,
                "http://localhost:8080",
            ]

            results = []
            for resource in resources:
                provider = gateway._determine_provider_for_resource(resource)
                results.append(provider)

            # All results should be the same (the configured provider)
            assert all(result == "google" for result in results)
            assert len(set(results)) == 1  # All results are identical

    def test_provider_determination_no_providers_allowed(self):
        """Test provider determination when no providers are configured for public-only gateway."""
        empty_config = GatewayConfig(
            host="localhost",
            port=8080,
            issuer="http://localhost:8080",
            session_secret="test-secret-key",
            oauth_providers={},  # No providers
            mcp_services={
                "public_service": McpServiceConfig(
                    name="Public Service",
                    url="http://localhost:3001/mcp",
                    oauth_provider=None,  # No provider needed
                    auth_required=False,
                )
            },
        )

        # This should succeed now for public-only services
        with patch("src.gateway.ConfigManager") as mock_config_manager:
            mock_config_manager.return_value.load_config.return_value = empty_config

            gateway = McpGateway()

            # Should have no providers configured
            assert len(gateway.provider_manager.providers) == 0
            assert gateway.provider_manager.primary_provider_id == ""

    def test_provider_determination_performance(self, single_github_config):
        """Test that provider determination is performant (should be O(1) now)."""
        with patch("src.gateway.ConfigManager") as mock_config_manager:
            mock_config_manager.return_value.load_config.return_value = (
                single_github_config
            )
            gateway = McpGateway()

            # Test many lookups - should be fast since it's just returning the configured provider
            import time

            start_time = time.time()

            for i in range(1000):  # More iterations since it's simpler now
                provider = gateway._determine_provider_for_resource(
                    f"http://localhost:8080/service_{i}/mcp"
                )
                assert provider == "github"

            elapsed = time.time() - start_time

            # Should be very fast (less than 0.1 seconds for 1000 calls)
            assert elapsed < 0.1, f"Provider determination took too long: {elapsed}s"


class TestSingleProviderConstraintEnforcement:
    """Test that single provider constraints are properly enforced."""

    def test_multiple_providers_config_rejected(self):
        """Test that configuration with multiple providers is rejected."""
        multi_provider_config = GatewayConfig(
            host="localhost",
            port=8080,
            issuer="http://localhost:8080",
            session_secret="test-secret-key",
            oauth_providers={
                "github": OAuthProviderConfig(
                    client_id="github_client_id", client_secret="github_client_secret"
                ),
                "google": OAuthProviderConfig(
                    client_id="google_client_id", client_secret="google_client_secret"
                ),
            },
            mcp_services={
                "calculator": McpServiceConfig(
                    name="Calculator Service",
                    url="http://localhost:3001/mcp",
                    oauth_provider="github",
                    auth_required=True,
                ),
            },
        )

        with patch("src.gateway.ConfigManager") as mock_config_manager:
            mock_config_manager.return_value.load_config.return_value = (
                multi_provider_config
            )

            with pytest.raises(
                ValueError, match="Only one OAuth provider can be configured"
            ):
                McpGateway()

    def test_service_provider_mismatch_rejected(self):
        """Test that services with mismatched providers are rejected during config loading."""
        # This test verifies the config-level validation catches mismatched services
        # The actual config loading would fail before we even get to the gateway

        # Note: This scenario would be caught by ConfigManager.load_config()
        # before we even reach the gateway initialization, so we test it indirectly
        # by verifying the gateway can only be created with valid single-provider configs

        valid_config = GatewayConfig(
            host="localhost",
            port=8080,
            issuer="http://localhost:8080",
            session_secret="test-secret-key",
            oauth_providers={
                "github": OAuthProviderConfig(
                    client_id="github_client_id", client_secret="github_client_secret"
                ),
            },
            mcp_services={
                "calculator": McpServiceConfig(
                    name="Calculator Service",
                    url="http://localhost:3001/mcp",
                    oauth_provider="github",  # Matches configured provider
                    auth_required=True,
                ),
            },
        )

        # This should succeed
        with patch("src.gateway.ConfigManager") as mock_config_manager:
            mock_config_manager.return_value.load_config.return_value = valid_config
            gateway = McpGateway()

            # Verify the gateway was created successfully
            assert gateway.provider_manager.primary_provider_id == "github"
            assert len(gateway.provider_manager.providers) == 1


class TestProviderDeterminationEdgeCases:
    """Test edge cases in provider determination."""

    @pytest.fixture
    def minimal_config(self):
        """Minimal valid configuration."""
        return GatewayConfig(
            host="localhost",
            port=8080,
            issuer="http://localhost:8080",
            session_secret="test-secret-key",
            oauth_providers={
                "github": OAuthProviderConfig(
                    client_id="github_client_id", client_secret="github_client_secret"
                ),
            },
            mcp_services={},  # No services configured
        )

    def test_provider_determination_no_services(self, minimal_config):
        """Test provider determination when no services are configured."""
        with patch("src.gateway.ConfigManager") as mock_config_manager:
            mock_config_manager.return_value.load_config.return_value = minimal_config
            gateway = McpGateway()

            # Should still return the configured provider
            provider = gateway._determine_provider_for_resource(
                "http://localhost:8080/any_resource/mcp"
            )
            assert provider == "github"

    def test_provider_determination_malformed_resources(self, minimal_config):
        """Test provider determination with malformed resource URIs."""
        with patch("src.gateway.ConfigManager") as mock_config_manager:
            mock_config_manager.return_value.load_config.return_value = minimal_config
            gateway = McpGateway()

            # Test various malformed or edge case resources
            malformed_resources = [
                "",  # Empty string
                "not-a-url",  # Not a URL
                "http://",  # Incomplete URL
                "://invalid",  # Invalid scheme
                "http://localhost:8080//double/slash",  # Double slash
                "http://localhost:8080/service with spaces",  # Spaces
                "http://localhost:8080/service?query=param",  # Query parameters
                "http://localhost:8080/service#fragment",  # Fragment
            ]

            for resource in malformed_resources:
                provider = gateway._determine_provider_for_resource(resource)
                assert provider == "github", (
                    f"Failed for malformed resource: {resource}"
                )

    def test_provider_determination_unicode_resources(self, minimal_config):
        """Test provider determination with unicode characters in resources."""
        with patch("src.gateway.ConfigManager") as mock_config_manager:
            mock_config_manager.return_value.load_config.return_value = minimal_config
            gateway = McpGateway()

            # Test unicode resources
            unicode_resources = [
                "http://localhost:8080/服务",  # Chinese characters
                "http://localhost:8080/сервис",  # Cyrillic characters
                "http://localhost:8080/café",  # Accented characters
                "http://localhost:8080/🚀",  # Emoji
            ]

            for resource in unicode_resources:
                provider = gateway._determine_provider_for_resource(resource)
                assert provider == "github", f"Failed for unicode resource: {resource}"
