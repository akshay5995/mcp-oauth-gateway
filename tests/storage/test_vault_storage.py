"""Improved tests for Vault storage backend - behavior-focused."""

import asyncio

import pytest
import pytest_asyncio

from src.config.config import VaultStorageConfig
from tests.storage.fakes import FakeVaultStorage

# Mark all async functions in this module as asyncio tests
pytestmark = pytest.mark.asyncio


class TestVaultStorageBehavior:
    """Test Vault storage behavior using fake implementation."""

    @pytest.fixture
    def vault_config(self):
        """Create Vault configuration for testing."""
        return VaultStorageConfig(
            url="http://localhost:8200",
            token="test-token",
            mount_point="secret",
            path_prefix="mcp-gateway-test",
            auth_method="token",
        )

    @pytest_asyncio.fixture
    async def vault_storage(self):
        """Create and start a fake Vault storage instance."""
        storage = FakeVaultStorage()
        await storage.start()
        yield storage
        await storage.stop()

    async def test_storage_lifecycle(self):
        """Test storage start/stop lifecycle."""
        storage = FakeVaultStorage()

        # Initially not started
        assert await storage.health_check() is False

        # Start storage
        await storage.start()
        assert await storage.health_check() is True

        # Verify background task is created
        assert storage._token_renewal_task is not None
        assert not storage._token_renewal_task.done()

        # Stop storage
        await storage.stop()
        assert await storage.health_check() is False

        # Verify background task is cleaned up
        assert storage._token_renewal_task is None or storage._token_renewal_task.done()

    async def test_connection_failure_handling(self):
        """Test handling of connection failures."""
        storage = FakeVaultStorage(should_fail=True)

        # Start should fail
        with pytest.raises(ConnectionError, match="Failed to connect to Vault"):
            await storage.start()

        # Health check should indicate failure
        assert await storage.health_check() is False

    async def test_authentication_failure_handling(self):
        """Test handling of authentication failures."""
        storage = FakeVaultStorage(auth_should_fail=True)

        # Start should fail with auth error
        with pytest.raises(ValueError, match="Vault authentication failed"):
            await storage.start()

        # Health check should indicate failure
        assert await storage.health_check() is False

    async def test_basic_storage_operations(self, vault_storage):
        """Test fundamental storage operations work correctly."""
        # Test storing and retrieving data
        test_data = {
            "client_id": "app123",
            "redirect_uri": "https://app.example.com/callback",
        }
        await vault_storage.set("oauth_client:123", test_data)

        result = await vault_storage.get("oauth_client:123")
        assert result == test_data

        # Test key existence
        assert await vault_storage.exists("oauth_client:123") is True
        assert await vault_storage.exists("nonexistent") is False

        # Test deletion
        assert await vault_storage.delete("oauth_client:123") is True
        assert await vault_storage.get("oauth_client:123") is None
        assert await vault_storage.exists("oauth_client:123") is False

        # Test deleting non-existent key
        assert await vault_storage.delete("nonexistent") is False

    async def test_ttl_behavior(self, vault_storage):
        """Test TTL (time-to-live) functionality."""
        test_data = {"authorization_code": "abc123", "expires": "soon"}

        # Set data with short TTL
        await vault_storage.set("auth_code:temp", test_data, ttl=1)

        # Should exist immediately
        assert await vault_storage.exists("auth_code:temp") is True
        assert await vault_storage.get("auth_code:temp") == test_data

        # Wait for expiration
        await asyncio.sleep(1.1)

        # Should be expired and cleaned up
        assert await vault_storage.get("auth_code:temp") is None
        assert await vault_storage.exists("auth_code:temp") is False

    async def test_key_pattern_matching(self, vault_storage):
        """Test key listing with pattern matching."""
        # Setup test data with different patterns
        await vault_storage.set("user:123", {"name": "Alice"})
        await vault_storage.set("user:456", {"name": "Bob"})
        await vault_storage.set("token:abc", {"access_token": "xyz"})
        await vault_storage.set("config:app", {"setting": "value"})

        # Test pattern matching
        user_keys = await vault_storage.keys("user:*")
        assert len(user_keys) == 2
        assert "user:123" in user_keys
        assert "user:456" in user_keys
        assert "token:abc" not in user_keys

        # Test all keys
        all_keys = await vault_storage.keys("*")
        assert len(all_keys) == 4

        # Test specific pattern
        token_keys = await vault_storage.keys("token:*")
        assert len(token_keys) == 1
        assert "token:abc" in token_keys

    async def test_clear_operation(self, vault_storage):
        """Test clearing all stored data."""
        # Store multiple items including ones with TTL
        await vault_storage.set("secret1", {"data": "confidential1"})
        await vault_storage.set("secret2", {"data": "confidential2"})
        await vault_storage.set("temp_secret", {"data": "expires"}, ttl=3600)

        # Verify data exists
        assert len(await vault_storage.keys("*")) == 3

        # Clear all data
        await vault_storage.clear()

        # Verify all data is gone
        assert len(await vault_storage.keys("*")) == 0
        assert await vault_storage.get("secret1") is None
        assert await vault_storage.get("secret2") is None
        assert await vault_storage.get("temp_secret") is None

    async def test_storage_statistics(self, vault_storage):
        """Test storage statistics reporting."""
        # Add some test data
        await vault_storage.set("secret1", {"data": "value1"})
        await vault_storage.set("secret2", {"data": "value2"})

        stats = await vault_storage.get_stats()

        # Verify basic stats structure
        assert stats["backend_type"] == "vault"
        assert stats["healthy"] is True
        assert stats["total_keys"] == 2
        assert stats["authenticated"] is True
        assert "vault_version" in stats
        assert "cluster_id" in stats
        assert "mount_point" in stats
        assert "path_prefix" in stats

    async def test_statistics_when_not_initialized(self):
        """Test statistics when storage is not started."""
        storage = FakeVaultStorage()
        # Don't start the storage

        stats = await storage.get_stats()

        assert stats["backend_type"] == "vault"
        assert stats["healthy"] is False
        assert stats["error"] == "Not initialized"

    async def test_operations_fail_when_not_initialized(self):
        """Test that operations fail gracefully when storage not started."""
        storage = FakeVaultStorage()
        # Don't start the storage

        with pytest.raises(RuntimeError, match="Vault storage not initialized"):
            await storage.get("test_key")

        with pytest.raises(RuntimeError, match="Vault storage not initialized"):
            await storage.set("test_key", {"secret": "value"})

        with pytest.raises(RuntimeError, match="Vault storage not initialized"):
            await storage.delete("test_key")

    async def test_error_handling_during_operations(self, vault_storage):
        """Test error handling when operations fail after initialization."""
        # Simulate Vault becoming unavailable after start
        vault_storage._should_fail = True

        # Operations should fail with connection errors
        with pytest.raises(ConnectionError, match="Vault operation .* failed"):
            await vault_storage.get("test_key")

        with pytest.raises(ConnectionError, match="Vault operation .* failed"):
            await vault_storage.set("test_key", {"secret": "value"})

    async def test_sensitive_data_storage(self, vault_storage):
        """Test storage of sensitive OAuth data structures."""
        # Test storing OAuth tokens
        access_token_data = {
            "token": "eyJhbGciOiJIUzI1NiIs...",
            "expires_at": 1640995200,
            "scope": "read write",
            "user_id": "user123",
        }
        await vault_storage.set("access_token:abc123", access_token_data)

        # Test storing authorization codes
        auth_code_data = {
            "code": "auth_code_xyz",
            "client_id": "client123",
            "redirect_uri": "https://app.example.com/callback",
            "code_challenge": "challenge123",
            "user_id": "user123",
        }
        await vault_storage.set("auth_code:xyz789", auth_code_data, ttl=600)

        # Test storing user sessions
        user_session_data = {
            "user_id": "user123",
            "email": "user@example.com",
            "provider": "google",
            "authenticated_at": 1640990000,
        }
        await vault_storage.set("user_session:session123", user_session_data, ttl=86400)

        # Verify all data can be retrieved correctly
        retrieved_token = await vault_storage.get("access_token:abc123")
        assert retrieved_token == access_token_data

        retrieved_code = await vault_storage.get("auth_code:xyz789")
        assert retrieved_code == auth_code_data

        retrieved_session = await vault_storage.get("user_session:session123")
        assert retrieved_session == user_session_data

    async def test_concurrent_secret_operations(self, vault_storage):
        """Test that Vault storage handles concurrent operations correctly."""

        async def store_secrets(category: str, count: int):
            for i in range(count):
                secret_data = {
                    "category": category,
                    "index": i,
                    "secret_value": f"secret_{category}_{i}",
                    "created_at": f"2024-01-{i + 1:02d}",
                }
                await vault_storage.set(f"{category}:secret_{i}", secret_data)

        # Run concurrent writes for different secret categories
        await asyncio.gather(
            store_secrets("tokens", 5),
            store_secrets("codes", 5),
            store_secrets("sessions", 5),
        )

        # Verify all data was stored correctly
        all_keys = await vault_storage.keys("*")
        assert len(all_keys) == 15

        # Verify data integrity for each category
        for category in ["tokens", "codes", "sessions"]:
            category_keys = await vault_storage.keys(f"{category}:*")
            assert len(category_keys) == 5

            for i in range(5):
                key = f"{category}:secret_{i}"
                data = await vault_storage.get(key)
                assert data["category"] == category
                assert data["index"] == i
                assert data["secret_value"] == f"secret_{category}_{i}"

    async def test_token_renewal_lifecycle(self):
        """Test token renewal task lifecycle management."""
        storage = FakeVaultStorage()

        # Initially no renewal task
        assert storage._token_renewal_task is None

        # Start storage
        await storage.start()

        # Renewal task should be created
        assert storage._token_renewal_task is not None
        assert not storage._token_renewal_task.done()

        # Stop storage
        await storage.stop()

        # Renewal task should be cancelled and cleaned up
        assert storage._token_renewal_task is None or storage._token_renewal_task.done()

    async def test_vault_specific_error_scenarios(self, vault_storage):
        """Test Vault-specific error scenarios."""
        # Test handling of sealed Vault (simulated by setting failure flag)
        vault_storage._should_fail = True

        # Health check should fail
        assert await vault_storage.health_check() is False

        # Operations should fail appropriately
        with pytest.raises(ConnectionError):
            await vault_storage.get("any_key")

    async def test_complex_nested_data_structures(self, vault_storage):
        """Test storage of complex nested data structures typical in OAuth."""
        complex_oauth_data = {
            "client_info": {
                "client_id": "complex_client_123",
                "client_name": "Complex OAuth App",
                "redirect_uris": [
                    "https://app.example.com/callback",
                    "https://app.example.com/mobile/callback",
                ],
                "scopes": ["read", "write", "admin"],
                "metadata": {
                    "created_at": "2024-01-01T00:00:00Z",
                    "last_used": "2024-01-15T12:30:00Z",
                    "usage_count": 42,
                },
            },
            "tokens": {
                "access": {
                    "value": "complex_access_token_value",
                    "expires_at": 1640995200,
                    "scopes": ["read", "write"],
                },
                "refresh": {
                    "value": "complex_refresh_token_value",
                    "expires_at": 1643587200,
                },
            },
            "user_context": {
                "user_id": "complex_user_123",
                "provider_data": {
                    "google": {
                        "sub": "google_user_id",
                        "email": "user@gmail.com",
                        "verified": True,
                    }
                },
                "permissions": ["oauth.read", "oauth.write"],
            },
        }

        # Store complex data
        await vault_storage.set("complex_oauth:session_123", complex_oauth_data)

        # Retrieve and verify structure integrity
        result = await vault_storage.get("complex_oauth:session_123")
        assert result == complex_oauth_data

        # Verify nested access works
        assert result["client_info"]["client_id"] == "complex_client_123"
        assert len(result["client_info"]["redirect_uris"]) == 2
        assert result["tokens"]["access"]["scopes"] == ["read", "write"]
        assert result["user_context"]["provider_data"]["google"]["verified"] is True
