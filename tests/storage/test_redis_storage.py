"""Improved tests for Redis storage backend - behavior-focused."""

import asyncio

import pytest
import pytest_asyncio

from src.config.config import RedisStorageConfig
from tests.storage.fakes import FakeRedisStorage

# Mark all async functions in this module as asyncio tests
pytestmark = pytest.mark.asyncio


class TestRedisStorageBehavior:
    """Test Redis storage behavior using fake implementation."""

    @pytest.fixture
    def redis_config(self):
        """Create Redis configuration for testing."""
        return RedisStorageConfig(
            host="localhost",
            port=6379,
            password="test_password",
            db=0,
            ssl=False,
            max_connections=10,
        )

    @pytest_asyncio.fixture
    async def redis_storage(self):
        """Create and start a fake Redis storage instance."""
        storage = FakeRedisStorage()
        await storage.start()
        yield storage
        await storage.stop()

    @pytest_asyncio.fixture
    async def failing_redis_storage(self):
        """Create a Redis storage that fails on connection."""
        storage = FakeRedisStorage(should_fail=True)
        return storage

    async def test_storage_lifecycle(self, redis_config):
        """Test storage start/stop lifecycle."""
        storage = FakeRedisStorage()

        # Initially not started
        assert await storage.health_check() is False

        # Start storage
        await storage.start()
        assert await storage.health_check() is True

        # Stop storage
        await storage.stop()
        assert await storage.health_check() is False

    async def test_connection_failure_handling(self):
        """Test handling of connection failures."""
        storage = FakeRedisStorage(should_fail=True)

        # Start should fail
        with pytest.raises(ConnectionError, match="Failed to connect to Redis"):
            await storage.start()

        # Health check should indicate failure
        assert await storage.health_check() is False

    async def test_basic_storage_operations(self, redis_storage):
        """Test fundamental storage operations work correctly."""
        # Test storing and retrieving data
        test_data = {"user_id": "123", "email": "test@example.com"}
        await redis_storage.set("user:123", test_data)

        result = await redis_storage.get("user:123")
        assert result == test_data

        # Test key existence
        assert await redis_storage.exists("user:123") is True
        assert await redis_storage.exists("nonexistent") is False

        # Test deletion
        assert await redis_storage.delete("user:123") is True
        assert await redis_storage.get("user:123") is None
        assert await redis_storage.exists("user:123") is False

        # Test deleting non-existent key
        assert await redis_storage.delete("nonexistent") is False

    async def test_ttl_behavior(self, redis_storage):
        """Test TTL (time-to-live) functionality."""
        test_data = {"session": "active"}

        # Set data with short TTL
        await redis_storage.set("session:temp", test_data, ttl=1)

        # Should exist immediately
        assert await redis_storage.exists("session:temp") is True
        assert await redis_storage.get("session:temp") == test_data

        # Wait for expiration
        await asyncio.sleep(1.1)

        # Should be expired and cleaned up
        assert await redis_storage.get("session:temp") is None
        assert await redis_storage.exists("session:temp") is False

    async def test_expire_existing_key(self, redis_storage):
        """Test setting TTL on existing keys."""
        # Set data without TTL
        await redis_storage.set("persistent:key", {"data": "value"})

        # Add TTL to existing key
        result = await redis_storage.expire("persistent:key", 1)
        assert result is True

        # Key should still exist immediately
        assert await redis_storage.exists("persistent:key") is True

        # Wait for expiration
        await asyncio.sleep(1.1)

        # Should be expired
        assert await redis_storage.exists("persistent:key") is False

        # Test expire on non-existent key
        result = await redis_storage.expire("nonexistent", 60)
        assert result is False

    async def test_key_pattern_matching(self, redis_storage):
        """Test key listing with pattern matching."""
        # Setup test data with different patterns
        await redis_storage.set("user:123", {"name": "Alice"})
        await redis_storage.set("user:456", {"name": "Bob"})
        await redis_storage.set("session:abc", {"token": "xyz"})
        await redis_storage.set("config:app", {"setting": "value"})

        # Test pattern matching
        user_keys = await redis_storage.keys("user:*")
        assert len(user_keys) == 2
        assert "user:123" in user_keys
        assert "user:456" in user_keys
        assert "session:abc" not in user_keys

        # Test all keys
        all_keys = await redis_storage.keys("*")
        assert len(all_keys) == 4

        # Test specific pattern
        session_keys = await redis_storage.keys("session:*")
        assert len(session_keys) == 1
        assert "session:abc" in session_keys

    async def test_clear_operation(self, redis_storage):
        """Test clearing all stored data."""
        # Store multiple items
        await redis_storage.set("key1", "value1")
        await redis_storage.set("key2", "value2")
        await redis_storage.set("key3", "value3", ttl=60)

        # Verify data exists
        assert len(await redis_storage.keys("*")) == 3

        # Clear all data
        await redis_storage.clear()

        # Verify all data is gone
        assert len(await redis_storage.keys("*")) == 0
        assert await redis_storage.get("key1") is None
        assert await redis_storage.get("key2") is None
        assert await redis_storage.get("key3") is None

    async def test_increment_operations(self, redis_storage):
        """Test numeric increment operations."""
        # Test incrementing non-existent key (should start at 0)
        result = await redis_storage.increment("counter")
        assert result == 1

        # Test incrementing existing key
        result = await redis_storage.increment("counter", 5)
        assert result == 6

        # Test negative increment (decrement)
        result = await redis_storage.increment("counter", -2)
        assert result == 4

    async def test_storage_statistics(self, redis_storage):
        """Test storage statistics reporting."""
        # Add some test data
        await redis_storage.set("test1", "value1")
        await redis_storage.set("test2", "value2")

        stats = await redis_storage.get_stats()

        # Verify basic stats structure
        assert stats["backend_type"] == "redis"
        assert stats["healthy"] is True
        assert stats["total_keys"] == 2
        assert "redis_version" in stats
        assert "used_memory" in stats

    async def test_statistics_when_not_initialized(self):
        """Test statistics when storage is not started."""
        storage = FakeRedisStorage()
        # Don't start the storage

        stats = await storage.get_stats()

        assert stats["backend_type"] == "redis"
        assert stats["healthy"] is False
        assert stats["error"] == "Not initialized"

    async def test_operations_fail_when_not_initialized(self):
        """Test that operations fail gracefully when storage not started."""
        storage = FakeRedisStorage()
        # Don't start the storage

        with pytest.raises(RuntimeError, match="Redis storage not initialized"):
            await storage.get("test_key")

        with pytest.raises(RuntimeError, match="Redis storage not initialized"):
            await storage.set("test_key", "value")

        with pytest.raises(RuntimeError, match="Redis storage not initialized"):
            await storage.delete("test_key")

    async def test_error_handling_during_operations(self):
        """Test error handling when operations fail."""
        # Create storage that fails on specific operations
        storage = FakeRedisStorage(fail_on_operations=["get", "set"])
        await storage.start()

        # Operations should fail with connection errors
        with pytest.raises(ConnectionError, match="Redis operation 'get' failed"):
            await storage.get("test_key")

        with pytest.raises(ConnectionError, match="Redis operation 'set' failed"):
            await storage.set("test_key", "value")

        # Other operations should still work
        assert await storage.health_check() is True

    async def test_concurrent_operations(self, redis_storage):
        """Test that storage handles concurrent operations correctly."""

        async def store_data(prefix: str, count: int):
            for i in range(count):
                await redis_storage.set(f"{prefix}:{i}", {"index": i, "prefix": prefix})

        # Run concurrent writes
        await asyncio.gather(
            store_data("set1", 10), store_data("set2", 10), store_data("set3", 10)
        )

        # Verify all data was stored correctly
        all_keys = await redis_storage.keys("*")
        assert len(all_keys) == 30

        # Verify data integrity
        for prefix in ["set1", "set2", "set3"]:
            for i in range(10):
                key = f"{prefix}:{i}"
                data = await redis_storage.get(key)
                assert data == {"index": i, "prefix": prefix}

    async def test_data_types_support(self, redis_storage):
        """Test storage of different data types."""
        test_cases = [
            ("string", "simple string"),
            ("number", 42),
            ("float", 3.14159),
            ("boolean", True),
            ("list", [1, 2, 3, "four"]),
            ("dict", {"nested": {"data": "structure"}}),
            ("none", None),
        ]

        # Store all test data
        for key, value in test_cases:
            await redis_storage.set(key, value)

        # Verify all data can be retrieved correctly
        for key, expected_value in test_cases:
            result = await redis_storage.get(key)
            assert result == expected_value

    async def test_large_data_handling(self, redis_storage):
        """Test handling of reasonably large data structures."""
        # Create a large data structure
        large_data = {
            "users": [{"id": i, "data": f"user_{i}" * 100} for i in range(100)],
            "metadata": {"created": "2024-01-01", "size": "large"},
        }

        await redis_storage.set("large_data", large_data)
        result = await redis_storage.get("large_data")

        assert result == large_data
        assert len(result["users"]) == 100
        assert result["metadata"]["size"] == "large"
