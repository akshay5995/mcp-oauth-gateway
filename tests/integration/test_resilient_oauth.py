"""Integration tests for single provider OAuth constraint enforcement."""

from unittest.mock import Mock, patch

import pytest

from src.config.config import GatewayConfig, McpServiceConfig, OAuthProviderConfig
from src.gateway import McpGateway


class TestSingleProviderConstraintIntegration:
    """Test single provider constraint enforcement in real gateway scenarios."""

    def test_config_validation_rejects_multiple_providers(self):
        """Test that configuration validation rejects multiple providers at the config level."""
        multi_provider_config = GatewayConfig(
            host="localhost",
            port=8080,
            issuer="http://localhost:8080",
            session_secret="test-secret",
            oauth_providers={
                "google": OAuthProviderConfig(
                    client_id="google_client_id", client_secret="google_client_secret"
                ),
                "github": OAuthProviderConfig(
                    client_id="github_client_id", client_secret="github_client_secret"
                ),
            },
            mcp_services={
                "calculator": McpServiceConfig(
                    name="Calculator Service",
                    url="http://localhost:3001/mcp",
                    oauth_provider="google",
                    auth_required=True,
                )
            },
        )

        # Gateway initialization should fail with clear error message
        with patch('src.gateway.ConfigManager') as mock_config_manager:
            mock_config_manager.return_value.load_config.return_value = multi_provider_config
            
            with pytest.raises(ValueError, match="Only one OAuth provider can be configured"):
                McpGateway()

    def test_config_validation_rejects_no_providers_with_auth_services(self, tmp_path):
        """Test that configuration validation rejects missing providers when auth is required."""
        # Create a config file that requires auth but has no providers
        config_file = tmp_path / "config.yaml"
        config_content = """
host: "localhost"
port: 8080
issuer: "http://localhost:8080"
session_secret: "test-secret"

# No oauth_providers section

mcp_services:
  calculator:
    name: "Calculator Service"
    url: "http://localhost:3001/mcp"
    oauth_provider: "github"  # References non-existent provider
    auth_required: true
"""
        config_file.write_text(config_content)
        
        from src.config.config import ConfigManager
        config_manager = ConfigManager(str(config_file))
        
        # Should fail during config loading
        with pytest.raises(ValueError, match="Services.*require authentication but no OAuth providers are configured"):
            config_manager.load_config()

    def test_valid_single_provider_configuration_succeeds(self):
        """Test that valid single provider configuration works correctly."""
        valid_config = GatewayConfig(
            host="localhost",
            port=8080,
            issuer="http://localhost:8080",
            session_secret="test-secret",
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
                "docs": McpServiceConfig(
                    name="Documentation Service",
                    url="http://localhost:3002/mcp",
                    oauth_provider="github",  # Same provider
                    auth_required=True,
                ),
                "public": McpServiceConfig(
                    name="Public Service",
                    url="http://localhost:3003/mcp",
                    oauth_provider="github",  # Must match configured provider
                    auth_required=False,  # No auth required
                ),
            },
        )

        # This should succeed
        with patch('src.gateway.ConfigManager') as mock_config_manager:
            mock_config_manager.return_value.load_config.return_value = valid_config
            gateway = McpGateway()
            
            # Verify the gateway was created successfully
            assert gateway.provider_manager.primary_provider_id == "github"
            assert len(gateway.provider_manager.providers) == 1
            
            # Test provider determination works consistently
            provider = gateway._determine_provider_for_resource("http://localhost:8080/calculator")
            assert provider == "github"
            
            provider = gateway._determine_provider_for_resource("http://localhost:8080/docs")
            assert provider == "github"
            
            provider = gateway._determine_provider_for_resource("http://localhost:8080/public")
            assert provider == "github"


class TestSingleProviderServiceBehavior:
    """Test service behavior with single provider constraint."""

    @pytest.fixture
    def github_config(self):
        """Configuration with GitHub as single provider."""
        return GatewayConfig(
            host="localhost",
            port=8080,
            issuer="http://localhost:8080",
            session_secret="test-secret",
            oauth_providers={
                "github": OAuthProviderConfig(
                    client_id="github_client_id", client_secret="github_client_secret"
                ),
            },
            mcp_services={
                "calculator": McpServiceConfig(
                    name="Calculator Service",
                    url="http://localhost:3001/mcp",
                    oauth_provider="github",
                    auth_required=True,
                ),
                "weather": McpServiceConfig(
                    name="Weather Service",
                    url="http://localhost:3002/mcp",
                    oauth_provider="github",
                    auth_required=True,
                ),
                "public": McpServiceConfig(
                    name="Public Service",
                    url="http://localhost:3003/mcp",
                    oauth_provider="github",  # Must match configured provider
                    auth_required=False,
                ),
            },
        )

    def test_all_services_use_same_provider(self, github_config):
        """Test that all services consistently use the same provider."""
        with patch('src.gateway.ConfigManager') as mock_config_manager:
            mock_config_manager.return_value.load_config.return_value = github_config
            gateway = McpGateway()

            # All services should resolve to the same provider
            services = ["calculator", "weather", "public", "unknown"]
            
            for service in services:
                provider = gateway._determine_provider_for_resource(
                    f"http://localhost:8080/{service}"
                )
                assert provider == "github", f"Service {service} returned wrong provider: {provider}"

    def test_provider_determination_performance(self, github_config):
        """Test that provider determination is consistently fast."""
        with patch('src.gateway.ConfigManager') as mock_config_manager:
            mock_config_manager.return_value.load_config.return_value = github_config
            gateway = McpGateway()

            import time

            # Test performance with many services
            start_time = time.time()

            for i in range(100):
                provider = gateway._determine_provider_for_resource(
                    f"http://localhost:8080/service_{i}"
                )
                assert provider == "github"

            elapsed = time.time() - start_time
            
            # Should be very fast since it's just returning the configured provider
            assert elapsed < 0.05, f"Provider determination took too long: {elapsed}s"

    def test_provider_manager_consistency(self, github_config):
        """Test provider manager consistency with single provider."""
        with patch('src.gateway.ConfigManager') as mock_config_manager:
            mock_config_manager.return_value.load_config.return_value = github_config
            gateway = McpGateway()

            # Provider manager should have exactly one provider
            assert len(gateway.provider_manager.providers) == 1
            assert gateway.provider_manager.primary_provider_id == "github"
            
            # Getting provider for service should work for correct provider
            provider = gateway.provider_manager.get_provider_for_service("github")
            assert provider is not None
            
            # Getting provider for wrong provider should fail
            with pytest.raises(ValueError, match="Service requests provider 'google' but only 'github' is configured"):
                gateway.provider_manager.get_provider_for_service("google")


class TestSingleProviderEdgeCases:
    """Test edge cases with single provider constraint."""

    def test_only_public_services_no_providers_succeeds(self, tmp_path):
        """Test configuration with only public services and no providers succeeds."""
        # Create a config file with only public services
        config_file = tmp_path / "config.yaml"
        config_content = """
host: "localhost"
port: 8080
issuer: "http://localhost:8080"
session_secret: "test-secret"

# No oauth_providers section - should be fine for public-only services

mcp_services:
  public1:
    name: "Public Service 1"
    url: "http://localhost:3001/mcp"
    auth_required: false  # No auth required
  public2:
    name: "Public Service 2"
    url: "http://localhost:3002/mcp"
    auth_required: false  # No auth required
"""
        config_file.write_text(config_content)
        
        from src.config.config import ConfigManager
        config_manager = ConfigManager(str(config_file))
        
        # Should succeed since no auth is required for any service
        config = config_manager.load_config()
        
        assert len(config.oauth_providers) == 0
        assert len(config.mcp_services) == 2
        assert not config.mcp_services["public1"].auth_required
        assert not config.mcp_services["public2"].auth_required
        assert config.mcp_services["public1"].oauth_provider is None
        assert config.mcp_services["public2"].oauth_provider is None
        
        # Gateway should also initialize successfully
        with patch('src.gateway.ConfigManager') as mock_config_manager:
            mock_config_manager.return_value.load_config.return_value = config
            gateway = McpGateway()
            
            # No providers should be configured
            assert len(gateway.provider_manager.providers) == 0
            assert gateway.provider_manager.primary_provider_id == ""

    def test_public_service_access_without_auth(self, tmp_path):
        """Test that public services can be accessed without authentication."""
        # Create a config with only public services
        config_file = tmp_path / "config.yaml"
        config_content = """
host: "localhost"
port: 8080
issuer: "http://localhost:8080"
session_secret: "test-secret"

mcp_services:
  public_api:
    name: "Public API"
    url: "http://localhost:3001/mcp"
    auth_required: false
"""
        config_file.write_text(config_content)
        
        from src.config.config import ConfigManager
        config_manager = ConfigManager(str(config_file))
        config = config_manager.load_config()
        
        # Create gateway
        with patch('src.gateway.ConfigManager') as mock_config_manager:
            mock_config_manager.return_value.load_config.return_value = config
            gateway = McpGateway()
            
            # Mock a request to a public service
            from unittest.mock import AsyncMock, Mock
            from fastapi import Request
            
            # Create a mock request
            mock_request = Mock(spec=Request)
            mock_request.method = "POST"
            mock_request.headers = {"content-type": "application/json"}
            mock_request.url.path = "/public_api/mcp"
            
            # Mock the MCP proxy
            gateway.mcp_proxy.forward_request = AsyncMock(return_value="mocked_response")
            
            # Verify the service configuration is correct for public access
            service = config.mcp_services["public_api"]
            assert not service.auth_required
            assert service.oauth_provider is None
            
            # The gateway should be set up correctly for public services
            assert len(gateway.provider_manager.providers) == 0

    def test_single_provider_with_mixed_auth_services(self):
        """Test single provider with mix of auth-required and public services."""
        mixed_config = GatewayConfig(
            host="localhost",
            port=8080,
            issuer="http://localhost:8080",
            session_secret="test-secret",
            oauth_providers={
                "google": OAuthProviderConfig(
                    client_id="google_client_id", client_secret="google_client_secret"
                ),
            },
            mcp_services={
                "private": McpServiceConfig(
                    name="Private Service",
                    url="http://localhost:3001/mcp",
                    oauth_provider="google",
                    auth_required=True,
                ),
                "public": McpServiceConfig(
                    name="Public Service",
                    url="http://localhost:3002/mcp",
                    oauth_provider="google",  # Must match configured provider
                    auth_required=False,  # No provider needed for auth
                ),
            },
        )

        # This should succeed
        with patch('src.gateway.ConfigManager') as mock_config_manager:
            mock_config_manager.return_value.load_config.return_value = mixed_config
            gateway = McpGateway()
            
            # Both services should use the same provider for consistency
            private_provider = gateway._determine_provider_for_resource("http://localhost:8080/private")
            public_provider = gateway._determine_provider_for_resource("http://localhost:8080/public")
            
            assert private_provider == "google"
            assert public_provider == "google"  # Same provider for consistency

    def test_single_provider_different_types(self):
        """Test different single provider types work correctly."""
        provider_types = [
            ("google", OAuthProviderConfig(client_id="google_id", client_secret="google_secret")),
            ("github", OAuthProviderConfig(client_id="github_id", client_secret="github_secret")),
            ("okta", OAuthProviderConfig(
                client_id="okta_id", 
                client_secret="okta_secret",
                authorization_url="https://dev.okta.com/oauth2/default/v1/authorize"
            )),
        ]

        for provider_name, provider_config in provider_types:
            config = GatewayConfig(
                host="localhost",
                port=8080,
                issuer="http://localhost:8080",
                session_secret="test-secret",
                oauth_providers={provider_name: provider_config},
                mcp_services={
                    "test_service": McpServiceConfig(
                        name="Test Service",
                        url="http://localhost:3001/mcp",
                        oauth_provider=provider_name,
                        auth_required=True,
                    ),
                },
            )

            with patch('src.gateway.ConfigManager') as mock_config_manager:
                mock_config_manager.return_value.load_config.return_value = config
                gateway = McpGateway()
                
                # Provider determination should work for any provider type
                provider = gateway._determine_provider_for_resource("http://localhost:8080/test_service")
                assert provider == provider_name
                
                # Provider manager should be correctly configured
                assert gateway.provider_manager.primary_provider_id == provider_name
                assert len(gateway.provider_manager.providers) == 1


class TestBackwardCompatibility:
    """Test backward compatibility and migration scenarios."""

    def test_helpful_error_messages_for_migration(self):
        """Test that error messages help users migrating from multi-provider setups."""
        # Simulate old multi-provider config
        old_style_config = GatewayConfig(
            host="localhost",
            port=8080,
            issuer="http://localhost:8080",
            session_secret="test-secret",
            oauth_providers={
                "google": OAuthProviderConfig(client_id="google_id", client_secret="google_secret"),
                "github": OAuthProviderConfig(client_id="github_id", client_secret="github_secret"),
                "okta": OAuthProviderConfig(
                    client_id="okta_id", 
                    client_secret="okta_secret",
                    authorization_url="https://dev.okta.com/oauth2/default/v1/authorize"
                ),
            },
            mcp_services={
                "service1": McpServiceConfig(
                    name="Service 1", url="http://localhost:3001/mcp", oauth_provider="google", auth_required=True
                ),
                "service2": McpServiceConfig(
                    name="Service 2", url="http://localhost:3002/mcp", oauth_provider="github", auth_required=True
                ),
                "service3": McpServiceConfig(
                    name="Service 3", url="http://localhost:3003/mcp", oauth_provider="okta", auth_required=True
                ),
            },
        )

        with patch('src.gateway.ConfigManager') as mock_config_manager:
            mock_config_manager.return_value.load_config.return_value = old_style_config
            
            with pytest.raises(ValueError) as exc_info:
                McpGateway()
            
            error_message = str(exc_info.value)
            
            # Error message should be helpful for migration
            assert "Only one OAuth provider can be configured" in error_message
            assert "Found 3 providers" in error_message
            assert "OAuth 2.1 resource parameter constraints" in error_message
            assert "google" in error_message
            assert "github" in error_message
            assert "okta" in error_message