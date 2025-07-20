"""Tests for memory storage backend."""

import asyncio

import pytest
import pytest_asyncio

from src.storage.memory import MemoryStorage

# Mark all async functions in this module as asyncio tests
pytestmark = pytest.mark.asyncio


class TestMemoryStorage:
    """Test cases for MemoryStorage backend."""

    @pytest_asyncio.fixture
    async def storage(self):
        """Create and start a memory storage instance."""
        storage = MemoryStorage()
        await storage.start()
        yield storage
        await storage.stop()

    async def test_initialization(self, storage):
        """Test storage initialization."""
        assert storage._data == {}
        assert storage._ttl == {}
        assert storage._cleanup_task is not None
        assert not storage._cleanup_task.done()

    async def test_basic_operations(self, storage):
        """Test basic get/set/delete operations."""
        # Test set and get
        await storage.set("test_key", {"value": "test_data"})
        result = await storage.get("test_key")
        assert result == {"value": "test_data"}

        # Test exists
        assert await storage.exists("test_key") is True
        assert await storage.exists("nonexistent") is False

        # Test delete
        assert await storage.delete("test_key") is True
        assert await storage.get("test_key") is None
        assert await storage.delete("nonexistent") is False

    async def test_ttl_operations(self, storage):
        """Test TTL (time-to-live) functionality."""
        # Set with TTL
        await storage.set("ttl_key", {"data": "expires"}, ttl=1)

        # Should exist immediately
        assert await storage.exists("ttl_key") is True
        result = await storage.get("ttl_key")
        assert result == {"data": "expires"}

        # Wait for expiration
        await asyncio.sleep(1.1)

        # Should be expired
        assert await storage.get("ttl_key") is None
        assert await storage.exists("ttl_key") is False

    async def test_keys_listing(self, storage):
        """Test key listing with patterns."""
        # Setup test data
        await storage.set("user:123", {"name": "Alice"})
        await storage.set("user:456", {"name": "Bob"})
        await storage.set("session:abc", {"token": "xyz"})

        # Test pattern matching
        user_keys = await storage.keys("user:*")
        assert len(user_keys) == 2
        assert "user:123" in user_keys
        assert "user:456" in user_keys

        # Test all keys
        all_keys = await storage.keys("*")
        assert len(all_keys) == 3

        # Test specific pattern
        session_keys = await storage.keys("session:*")
        assert len(session_keys) == 1
        assert "session:abc" in session_keys

    async def test_clear_operation(self, storage):
        """Test clearing all data."""
        # Setup test data
        await storage.set("key1", "value1")
        await storage.set("key2", "value2", ttl=60)

        # Verify data exists
        assert len(await storage.keys("*")) == 2

        # Clear all data
        await storage.clear()

        # Verify all data cleared
        assert len(await storage.keys("*")) == 0
        assert await storage.get("key1") is None
        assert await storage.get("key2") is None

    async def test_ttl_cleanup(self, storage):
        """Test background TTL cleanup."""
        # Create keys with short TTL
        await storage.set("temp1", "data1", ttl=1)
        await storage.set("temp2", "data2", ttl=1)
        await storage.set("permanent", "data3")  # No TTL

        # Verify all keys exist
        assert len(await storage.keys("*")) == 3

        # Wait for TTL expiration
        await asyncio.sleep(1.1)

        # Manually trigger cleanup (simulate background task)
        await storage._cleanup_expired_keys_sync()

        # Verify expired keys removed, permanent key remains
        remaining_keys = await storage.keys("*")
        assert len(remaining_keys) == 1
        assert "permanent" in remaining_keys

    async def test_health_check(self, storage):
        """Test health check functionality."""
        assert await storage.health_check() is True

    async def test_get_stats(self, storage):
        """Test statistics retrieval."""
        stats = await storage.get_stats()
        assert stats["backend_type"] == "memory"
        assert stats["healthy"] is True
        assert "total_keys" in stats
        assert "keys_with_ttl" in stats

    async def test_unified_storage_interface(self, storage):
        """Test unified storage interface methods."""
        # Test OAuth state storage
        state_data = {"client_id": "test", "redirect_uri": "http://test.com"}
        await storage.store_oauth_state("state123", state_data, ttl=600)

        retrieved = await storage.get_oauth_state("state123")
        assert retrieved == state_data

        assert await storage.delete_oauth_state("state123") is True

        # Test authorization code storage
        code_data = {"user_id": "user123", "scope": "read"}
        await storage.store_authorization_code("code456", code_data, ttl=600)

        retrieved = await storage.get_authorization_code("code456")
        assert retrieved == code_data

        # Test user session storage
        user_data = {"email": "test@example.com", "name": "Test User"}
        await storage.store_user_session("user789", user_data, ttl=86400)

        retrieved = await storage.get_user_session("user789")
        assert retrieved == user_data

        # Test token storage
        token_data = {"client_id": "client1", "user_id": "user1"}
        await storage.store_access_token("token123", token_data, ttl=3600)

        retrieved = await storage.get_access_token("token123")
        assert retrieved == token_data

        # Test refresh token storage
        refresh_data = {"client_id": "client1", "user_id": "user1"}
        await storage.store_refresh_token("refresh456", refresh_data, ttl=2592000)

        retrieved = await storage.get_refresh_token("refresh456")
        assert retrieved == refresh_data

        # Test client storage
        client_data = {"client_name": "Test App", "redirect_uris": ["http://test.com"]}
        await storage.store_client("client123", client_data)

        retrieved = await storage.get_client("client123")
        assert retrieved == client_data

        # Test list clients
        clients = await storage.list_clients()
        assert len(clients) == 1
        assert clients[0] == client_data

    async def test_token_revocation(self, storage):
        """Test token revocation functionality."""
        # Setup tokens for multiple users
        await storage.store_access_token(
            "token1", {"user_id": "user1", "client_id": "client1"}
        )
        await storage.store_access_token(
            "token2", {"user_id": "user2", "client_id": "client1"}
        )
        await storage.store_refresh_token(
            "refresh1", {"user_id": "user1", "client_id": "client1"}
        )
        await storage.store_refresh_token(
            "refresh2", {"user_id": "user2", "client_id": "client1"}
        )

        # Revoke all tokens for user1
        revoked_count = await storage.revoke_user_tokens("user1")
        assert revoked_count == 2

        # Verify user1 tokens revoked, user2 tokens remain
        assert await storage.get_access_token("token1") is None
        assert await storage.get_refresh_token("refresh1") is None
        assert await storage.get_access_token("token2") is not None
        assert await storage.get_refresh_token("refresh2") is not None

    async def test_client_deduplication(self, storage):
        """Test client deduplication by redirect URIs."""
        redirect_uris = [
            "http://app.example.com/callback",
            "http://localhost:3000/auth",
        ]

        # Store first client
        client1_data = {"client_name": "Test App", "redirect_uris": redirect_uris}
        await storage.store_client("client1", client1_data)

        # Find client by redirect URIs
        found_client = await storage.find_client_by_redirect_uris(redirect_uris)
        assert found_client == client1_data

        # Test with different redirect URIs
        different_uris = ["http://other.example.com/callback"]
        found_client = await storage.find_client_by_redirect_uris(different_uris)
        assert found_client is None

    async def test_concurrent_operations(self, storage):
        """Test concurrent storage operations."""

        async def write_data(key_prefix: str, count: int):
            for i in range(count):
                await storage.set(f"{key_prefix}:{i}", {"index": i})

        # Run concurrent writes
        await asyncio.gather(
            write_data("set1", 10), write_data("set2", 10), write_data("set3", 10)
        )

        # Verify all data written
        all_keys = await storage.keys("*")
        assert len(all_keys) == 30

        # Verify data integrity
        for i in range(10):
            data1 = await storage.get(f"set1:{i}")
            data2 = await storage.get(f"set2:{i}")
            data3 = await storage.get(f"set3:{i}")

            assert data1 == {"index": i}
            assert data2 == {"index": i}
            assert data3 == {"index": i}

    async def test_lifecycle_management(self):
        """Test storage lifecycle (start/stop)."""
        storage = MemoryStorage()

        # Should not be started initially
        assert storage._cleanup_task is None

        # Start storage
        await storage.start()
        assert storage._cleanup_task is not None
        assert not storage._cleanup_task.done()

        # Stop storage
        await storage.stop()
        assert storage._cleanup_task.done()
        assert len(storage._data) == 0
        assert len(storage._ttl) == 0
