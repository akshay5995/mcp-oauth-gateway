"""Shared test configuration and fixtures."""

from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from src.auth.client_registry import ClientRegistry
from src.auth.oauth_server import OAuthServer
from src.auth.provider_manager import ProviderManager
from src.auth.token_manager import TokenManager
from src.config.config import (
    CorsConfig,
    GatewayConfig,
    McpServiceConfig,
    OAuthProviderConfig,
    StorageConfig,
)
from src.storage.manager import StorageManager
from src.storage.memory import MemoryStorage


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
        storage=StorageConfig(type="memory"),
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


@pytest_asyncio.fixture
async def oauth_server(
    test_config,
    memory_storage,
    client_registry_with_storage,
    token_manager_with_storage,
):
    """OAuth server fixture."""
    return OAuthServer(
        secret_key=test_config.session_secret,
        issuer=test_config.issuer,
        session_storage=memory_storage,
        client_registry=client_registry_with_storage,
        token_manager=token_manager_with_storage,
    )


@pytest_asyncio.fixture
async def token_manager(test_config, memory_storage):
    """Token manager fixture."""
    return TokenManager(
        secret_key=test_config.session_secret,
        issuer=test_config.issuer,
        token_storage=memory_storage,
    )


@pytest_asyncio.fixture
async def client_registry(memory_storage):
    """Client registry fixture."""
    return ClientRegistry(client_storage=memory_storage)


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


# Storage-related fixtures


@pytest.fixture
def storage_config():
    """Default storage configuration for testing."""
    return StorageConfig(type="memory")


@pytest_asyncio.fixture
async def memory_storage():
    """Memory storage fixture."""
    storage = MemoryStorage()
    await storage.start()
    yield storage
    await storage.stop()


@pytest_asyncio.fixture
async def storage_manager(storage_config):
    """Storage manager fixture."""
    manager = StorageManager(storage_config)
    storage = await manager.start_storage()
    yield manager, storage
    await manager.stop_storage()


@pytest_asyncio.fixture
async def token_manager_with_storage(test_config, memory_storage):
    """Token manager fixture with storage backend."""
    return TokenManager(
        secret_key=test_config.session_secret,
        issuer=test_config.issuer,
        token_storage=memory_storage,
    )


@pytest_asyncio.fixture
async def client_registry_with_storage(memory_storage):
    """Client registry fixture with storage backend."""
    return ClientRegistry(client_storage=memory_storage)


@pytest_asyncio.fixture
async def oauth_server_with_storage(
    test_config,
    memory_storage,
    client_registry_with_storage,
    token_manager_with_storage,
):
    """OAuth server fixture with storage backend."""
    return OAuthServer(
        secret_key=test_config.session_secret,
        issuer=test_config.issuer,
        session_storage=memory_storage,
        client_registry=client_registry_with_storage,
        token_manager=token_manager_with_storage,
    )
