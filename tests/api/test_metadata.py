"""Tests for OAuth metadata API functionality."""

import pytest

from src.api.metadata import MetadataProvider
from src.config.config import GatewayConfig, McpServiceConfig, OAuthProviderConfig


class TestMetadataProvider:
    """Test cases for MetadataProvider."""

    @pytest.fixture
    def basic_config(self):
        """Basic gateway configuration fixture."""
        return GatewayConfig(
            host="localhost",
            port=8080,
            issuer="https://gateway.example.com",
            session_secret="test-secret",
            oauth_providers={
                "github": OAuthProviderConfig(
                    client_id="github_id",
                    client_secret="github_secret",
                    scopes=["user:email"],
                )
            },
            mcp_services={
                "calculator": McpServiceConfig(
                    name="Calculator Service",
                    url="http://localhost:3001/mcp",
                    oauth_provider="github",
                    auth_required=True,
                    scopes=["read", "calculate"],
                ),
                "weather": McpServiceConfig(
                    name="Weather Service",
                    url="http://localhost:3002/mcp",
                    oauth_provider="github",
                    auth_required=True,
                    scopes=["read", "weather"],
                ),
            },
        )

    @pytest.fixture
    def metadata_provider(self, basic_config):
        """Metadata provider fixture."""
        return MetadataProvider(basic_config)

    def test_metadata_provider_initialization(self, metadata_provider, basic_config):
        """Test metadata provider initializes correctly."""
        assert metadata_provider.config == basic_config

    def test_get_authorization_server_metadata_structure(self, metadata_provider):
        """Test authorization server metadata has correct structure."""
        metadata = metadata_provider.get_authorization_server_metadata()

        # Check required fields per RFC 8414
        required_fields = [
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "registration_endpoint",
            "scopes_supported",
            "response_types_supported",
            "grant_types_supported",
        ]

        for field in required_fields:
            assert field in metadata, f"Missing required field: {field}"

    def test_get_authorization_server_metadata_values(self, metadata_provider):
        """Test authorization server metadata contains correct values."""
        metadata = metadata_provider.get_authorization_server_metadata()

        assert metadata["issuer"] == "https://gateway.example.com"
        assert (
            metadata["authorization_endpoint"]
            == "https://gateway.example.com/oauth/authorize"
        )
        assert metadata["token_endpoint"] == "https://gateway.example.com/oauth/token"
        assert (
            metadata["registration_endpoint"]
            == "https://gateway.example.com/oauth/register"
        )
        assert (
            metadata["userinfo_endpoint"]
            == "https://gateway.example.com/oauth/userinfo"
        )
        assert metadata["jwks_uri"] == "https://gateway.example.com/oauth/jwks"

        assert metadata["response_types_supported"] == ["code"]
        assert metadata["grant_types_supported"] == [
            "authorization_code",
            "refresh_token",
        ]
        assert metadata["code_challenge_methods_supported"] == ["S256"]
        assert metadata["token_endpoint_auth_methods_supported"] == [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ]
        assert metadata["resource_parameter_supported"] is True
        assert metadata["subject_types_supported"] == ["public"]

    def test_get_authorization_server_metadata_scopes(self, metadata_provider):
        """Test authorization server metadata includes correct scopes."""
        metadata = metadata_provider.get_authorization_server_metadata()

        scopes = metadata["scopes_supported"]

        # Should include default scopes plus service-specific scopes
        expected_scopes = {"read", "write", "calculate", "weather"}
        assert set(scopes) == expected_scopes
        assert scopes == sorted(scopes)  # Should be sorted

    def test_get_protected_resource_metadata_base(self, metadata_provider):
        """Test protected resource metadata without specific service."""
        metadata = metadata_provider.get_protected_resource_metadata()

        # Check required fields per RFC 9728
        required_fields = [
            "resource",
            "authorization_servers",
            "scopes_supported",
            "bearer_methods_supported",
        ]

        for field in required_fields:
            assert field in metadata, f"Missing required field: {field}"

    def test_get_protected_resource_metadata_values(self, metadata_provider):
        """Test protected resource metadata contains correct values."""
        metadata = metadata_provider.get_protected_resource_metadata()

        assert metadata["resource"] == "https://gateway.example.com"
        assert metadata["authorization_servers"] == ["https://gateway.example.com"]
        assert metadata["bearer_methods_supported"] == ["header"]
        assert (
            metadata["resource_documentation"] == "https://gateway.example.com/services"
        )

        # Should include all scopes
        expected_scopes = {"read", "write", "calculate", "weather"}
        assert set(metadata["scopes_supported"]) == expected_scopes

    def test_get_protected_resource_metadata_service_specific(self, metadata_provider):
        """Test protected resource metadata for specific service."""
        metadata = metadata_provider.get_protected_resource_metadata("calculator")

        assert metadata["resource"] == "https://gateway.example.com/calculator/mcp"
        assert metadata["authorization_servers"] == ["https://gateway.example.com"]
        assert metadata["scopes_supported"] == ["read", "calculate"]

    def test_get_protected_resource_metadata_nonexistent_service(
        self, metadata_provider
    ):
        """Test protected resource metadata for non-existent service."""
        metadata = metadata_provider.get_protected_resource_metadata("nonexistent")

        # Should return base metadata when service doesn't exist
        assert metadata["resource"] == "https://gateway.example.com"
        expected_scopes = {"read", "write", "calculate", "weather"}
        assert set(metadata["scopes_supported"]) == expected_scopes

    def test_get_supported_scopes_default_only(self):
        """Test supported scopes with no services configured."""
        config = GatewayConfig(
            issuer="https://test.example.com", session_secret="test-secret"
        )
        provider = MetadataProvider(config)

        scopes = provider._get_supported_scopes()

        assert set(scopes) == {"read", "write"}
        assert scopes == sorted(scopes)

    def test_get_supported_scopes_with_services(self, metadata_provider):
        """Test supported scopes includes service-specific scopes."""
        scopes = metadata_provider._get_supported_scopes()

        expected_scopes = {"read", "write", "calculate", "weather"}
        assert set(scopes) == expected_scopes
        assert scopes == sorted(scopes)

    def test_get_supported_scopes_empty_service_scopes(self):
        """Test supported scopes with services that have empty scopes."""
        config = GatewayConfig(
            issuer="https://test.example.com",
            session_secret="test-secret",
            mcp_services={
                "service1": McpServiceConfig(
                    name="Service 1",
                    url="http://service1/mcp",
                    oauth_provider="github",
                    scopes=[],  # Empty scopes
                ),
                "service2": McpServiceConfig(
                    name="Service 2",
                    url="http://service2/mcp",
                    oauth_provider="github",
                    scopes=["custom"],
                ),
            },
        )
        provider = MetadataProvider(config)

        scopes = provider._get_supported_scopes()

        # Should include defaults plus non-empty service scopes
        expected_scopes = {"read", "write", "custom"}
        assert set(scopes) == expected_scopes

    def test_get_supported_scopes_duplicate_scopes(self):
        """Test that duplicate scopes are handled correctly."""
        config = GatewayConfig(
            issuer="https://test.example.com",
            session_secret="test-secret",
            mcp_services={
                "service1": McpServiceConfig(
                    name="Service 1",
                    url="http://service1/mcp",
                    oauth_provider="github",
                    scopes=["read", "custom"],  # read is also default
                ),
                "service2": McpServiceConfig(
                    name="Service 2",
                    url="http://service2/mcp",
                    oauth_provider="github",
                    scopes=["custom", "other"],  # custom is duplicate
                ),
            },
        )
        provider = MetadataProvider(config)

        scopes = provider._get_supported_scopes()

        # Should deduplicate scopes
        expected_scopes = {"read", "write", "custom", "other"}
        assert set(scopes) == expected_scopes
        assert len(scopes) == len(set(scopes))  # No duplicates

    def test_metadata_with_different_issuer(self):
        """Test metadata with different issuer configuration."""
        config = GatewayConfig(
            issuer="https://auth.company.com:8443", session_secret="test-secret"
        )
        provider = MetadataProvider(config)

        auth_metadata = provider.get_authorization_server_metadata()
        resource_metadata = provider.get_protected_resource_metadata()

        # Check that all URLs use the configured issuer
        assert auth_metadata["issuer"] == "https://auth.company.com:8443"
        assert (
            auth_metadata["authorization_endpoint"]
            == "https://auth.company.com:8443/oauth/authorize"
        )
        assert (
            auth_metadata["token_endpoint"]
            == "https://auth.company.com:8443/oauth/token"
        )

        assert resource_metadata["resource"] == "https://auth.company.com:8443"
        assert resource_metadata["authorization_servers"] == [
            "https://auth.company.com:8443"
        ]

    def test_service_specific_metadata_with_empty_scopes(self):
        """Test service-specific metadata when service has empty scopes."""
        config = GatewayConfig(
            issuer="https://test.example.com",
            session_secret="test-secret",
            mcp_services={
                "empty_scopes": McpServiceConfig(
                    name="Empty Scopes Service",
                    url="http://service/mcp",
                    oauth_provider="github",
                    scopes=[],  # Empty scopes
                )
            },
        )
        provider = MetadataProvider(config)

        metadata = provider.get_protected_resource_metadata("empty_scopes")

        # Should fall back to default scopes when service has empty scopes
        assert set(metadata["scopes_supported"]) == {"read", "write"}

    def test_authorization_server_metadata_signing_algorithms(self, metadata_provider):
        """Test that signing algorithms are properly specified."""
        metadata = metadata_provider.get_authorization_server_metadata()

        assert "id_token_signing_alg_values_supported" in metadata
        assert "token_endpoint_auth_signing_alg_values_supported" in metadata

        id_token_algs = metadata["id_token_signing_alg_values_supported"]
        auth_algs = metadata["token_endpoint_auth_signing_alg_values_supported"]

        assert "HS256" in id_token_algs
        assert "RS256" in id_token_algs
        assert "HS256" in auth_algs
        assert "RS256" in auth_algs

    def test_metadata_endpoints_consistency(self, metadata_provider):
        """Test that metadata endpoints are consistent between auth server and resource."""
        auth_metadata = metadata_provider.get_authorization_server_metadata()
        resource_metadata = metadata_provider.get_protected_resource_metadata()

        # Issuer should be consistent
        assert auth_metadata["issuer"] == resource_metadata["authorization_servers"][0]

        # Scopes should be consistent
        assert set(auth_metadata["scopes_supported"]) == set(
            resource_metadata["scopes_supported"]
        )

    def test_get_service_canonical_uri(self, metadata_provider):
        """Test service canonical URI generation per RFC 8707 and MCP spec."""
        # Test basic service canonical URI
        uri = metadata_provider.get_service_canonical_uri("calculator")
        assert uri == "https://gateway.example.com/calculator/mcp"

        # Test with different service ID
        uri = metadata_provider.get_service_canonical_uri("weather")
        assert uri == "https://gateway.example.com/weather/mcp"

    def test_get_service_canonical_uri_trailing_slash(self):
        """Test canonical URI generation with issuer having trailing slash."""
        config = GatewayConfig(
            issuer="https://gateway.example.com/",  # Note trailing slash
            session_secret="test-secret",
        )
        provider = MetadataProvider(config)

        uri = provider.get_service_canonical_uri("calculator")
        assert uri == "https://gateway.example.com/calculator/mcp"

    def test_get_all_service_canonical_uris(self, metadata_provider):
        """Test getting all service canonical URIs."""
        uris = metadata_provider.get_all_service_canonical_uris()

        expected = {
            "calculator": "https://gateway.example.com/calculator/mcp",
            "weather": "https://gateway.example.com/weather/mcp",
        }
        assert uris == expected
