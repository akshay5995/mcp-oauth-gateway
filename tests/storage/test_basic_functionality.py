"""Basic tests to verify storage functionality works."""

import pytest

from src.config.config import StorageConfig
from src.storage.manager import StorageManager
from src.storage.memory import MemoryStorage

# Mark all async functions in this module as asyncio tests
pytestmark = pytest.mark.asyncio


class TestBasicStorageFunctionality:
    """Basic storage functionality tests."""

    async def test_memory_storage_basic_operations(self):
        """Test that memory storage basic operations work."""
        storage = MemoryStorage()
        await storage.start()

        try:
            # Test basic operations
            await storage.set("test_key", {"data": "test_value"})
            result = await storage.get("test_key")
            assert result == {"data": "test_value"}

            # Test exists
            assert await storage.exists("test_key") is True
            assert await storage.exists("nonexistent") is False

            # Test delete
            assert await storage.delete("test_key") is True
            assert await storage.get("test_key") is None

            # Test health check
            assert await storage.health_check() is True

            # Test stats
            stats = await storage.get_stats()
            assert stats["backend_type"] == "memory"
            assert stats["healthy"] is True

        finally:
            await storage.stop()

    async def test_storage_manager_functionality(self):
        """Test that storage manager works."""
        config = StorageConfig(type="memory")
        manager = StorageManager(config)

        # Start storage
        storage = await manager.start_storage()

        try:
            # Test that we got a working storage backend
            await storage.set("manager_test", {"test": "data"})
            result = await storage.get("manager_test")
            assert result == {"test": "data"}

            # Test health check
            assert await manager.health_check() is True

            # Test storage info
            info = manager.get_storage_info()
            assert info["type"] == "memory"
            assert info["healthy"] is True

        finally:
            await manager.stop_storage()

    async def test_unified_storage_interface(self):
        """Test unified storage interface methods."""
        storage = MemoryStorage()
        await storage.start()

        try:
            # Test OAuth state storage
            state_data = {"client_id": "test", "scope": "read"}
            await storage.store_oauth_state("state123", state_data)

            retrieved = await storage.get_oauth_state("state123")
            assert retrieved == state_data

            # Test token storage
            token_data = {"user_id": "user1", "client_id": "client1"}
            await storage.store_access_token("token123", token_data)

            retrieved = await storage.get_access_token("token123")
            assert retrieved == token_data

            # Test client storage
            client_data = {"client_name": "Test App"}
            await storage.store_client("client123", client_data)

            retrieved = await storage.get_client("client123")
            assert retrieved == client_data

            # Test list clients
            clients = await storage.list_clients()
            assert len(clients) == 1
            assert clients[0] == client_data

        finally:
            await storage.stop()

    async def test_ttl_functionality(self):
        """Test TTL (time-to-live) functionality."""
        storage = MemoryStorage()
        await storage.start()

        try:
            # Set key with short TTL
            await storage.set("ttl_test", {"expires": "soon"}, ttl=1)

            # Should exist immediately
            assert await storage.exists("ttl_test") is True

            # Wait for expiration
            import asyncio

            await asyncio.sleep(1.1)

            # Should be expired now
            assert await storage.get("ttl_test") is None

        finally:
            await storage.stop()

    def test_storage_import_structure(self):
        """Test that storage imports work correctly."""
        from src.storage import (
            ClientStorage,
            SessionStorage,
            TokenStorage,
            UnifiedStorage,
        )
        from src.storage.base import BaseStorage
        from src.storage.base import UnifiedStorage as BaseUnifiedStorage
        from src.storage.memory import MemoryStorage

        # Test that the imports work
        assert UnifiedStorage is BaseUnifiedStorage
        assert ClientStorage is UnifiedStorage
        assert SessionStorage is UnifiedStorage
        assert TokenStorage is UnifiedStorage

        # Test that we can create instances
        storage = MemoryStorage()
        assert isinstance(storage, BaseStorage)
        assert isinstance(storage, UnifiedStorage)

    def test_storage_configuration(self):
        """Test storage configuration classes."""
        from src.config.config import (
            RedisStorageConfig,
            StorageConfig,
            VaultStorageConfig,
        )

        # Test memory config
        memory_config = StorageConfig(type="memory")
        assert memory_config.type == "memory"

        # Test redis config
        redis_config = StorageConfig(
            type="redis", redis=RedisStorageConfig(host="localhost", port=6379)
        )
        assert redis_config.type == "redis"
        assert redis_config.redis.host == "localhost"

        # Test vault config
        vault_config = StorageConfig(
            type="vault",
            vault=VaultStorageConfig(url="http://vault:8200", token="test"),
        )
        assert vault_config.type == "vault"
        assert vault_config.vault.url == "http://vault:8200"
