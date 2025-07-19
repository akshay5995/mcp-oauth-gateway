"""Shared test configuration and fixtures."""

from unittest.mock import AsyncMock

import pytest

from src.auth.client_registry import ClientRegistry
from src.auth.oauth_server import OAuthServer
from src.auth.provider_manager import ProviderManager
from src.auth.token_manager import TokenManager
from src.config.config import (
    CorsConfig,
    GatewayConfig,
    McpServiceConfig,
    OAuthProviderConfig,
)


@pytest.fixture
def test_config():
    """Test configuration fixture."""
    return GatewayConfig(
        host="localhost",
        port=8080,
        issuer="http://localhost:8080",
        session_secret="test-secret-key-for-testing-only",
        debug=True,
        cors=CorsConfig(),
        oauth_providers={
            "github": OAuthProviderConfig(
                client_id="test_client_id",
                client_secret="test_client_secret",
                scopes=["user:email"],
            ),
            # Note: Only one provider configured due to single provider constraint
        },
        mcp_services={
            "calculator": McpServiceConfig(
                name="Test Calculator",
                url="http://localhost:3001/mcp",
                oauth_provider="github",  # Must match the configured provider
                auth_required=True,
                scopes=["read", "calculate"],
                timeout=30000,
            ),
            "public_service": McpServiceConfig(
                name="Public Service",
                url="http://localhost:3002/mcp",
                oauth_provider="github",  # Must match the configured provider
                auth_required=False,
                timeout=10000,
            ),
        },
    )


@pytest.fixture
def oauth_server(test_config):
    """OAuth server fixture."""
    return OAuthServer(secret_key=test_config.session_secret, issuer=test_config.issuer)


@pytest.fixture
def token_manager(test_config):
    """Token manager fixture."""
    return TokenManager(
        secret_key=test_config.session_secret, issuer=test_config.issuer
    )


@pytest.fixture
def client_registry():
    """Client registry fixture."""
    return ClientRegistry()


@pytest.fixture
def provider_manager(test_config):
    """Provider manager fixture."""
    return ProviderManager(test_config.oauth_providers)


@pytest.fixture
def mock_httpx_client():
    """Mock httpx async client."""
    return AsyncMock()


@pytest.fixture
def multi_provider_config():
    """Invalid multi-provider configuration for testing error conditions."""
    return {
        "github": OAuthProviderConfig(
            client_id="github_client_id",
            client_secret="github_client_secret",
            scopes=["user:email"],
        ),
        "google": OAuthProviderConfig(
            client_id="google_client_id",
            client_secret="google_client_secret",
            scopes=["openid", "email", "profile"],
        ),
    }


@pytest.fixture
def single_google_provider_config():
    """Single Google provider configuration for testing."""
    return {
        "google": OAuthProviderConfig(
            client_id="google_client_id",
            client_secret="google_client_secret",
            scopes=["openid", "email", "profile"],
        )
    }
