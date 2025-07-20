"""Fake storage implementations for testing."""

import asyncio
import fnmatch
import time
from typing import Any, Dict, List, Optional

from src.storage.base import BaseStorage


class FakeRedisStorage(BaseStorage):
    """Fake Redis storage implementation for testing without Redis dependency.

    This fake implementation follows the same behavioral contract as RedisStorage
    but stores data in memory, allowing us to test storage behavior without
    mocking implementation details.
    """

    def __init__(self, should_fail: bool = False, fail_on_operations: List[str] = None):
        """Initialize fake Redis storage.

        Args:
            should_fail: If True, simulate connection failures
            fail_on_operations: List of operations that should fail
        """
        self._data: Dict[str, Any] = {}
        self._ttl: Dict[str, float] = {}
        self._is_started = False
        self._should_fail = should_fail
        self._fail_on_operations = fail_on_operations or []
        self._stats = {
            "connected_clients": 1,
            "used_memory": 1024,
            "used_memory_human": "1K",
            "redis_version": "fake-7.0.0",
        }

    async def start(self) -> None:
        """Start the fake Redis storage."""
        if self._should_fail:
            raise ConnectionError("Failed to connect to Redis")
        self._is_started = True

    async def stop(self) -> None:
        """Stop the fake Redis storage."""
        self._is_started = False
        self._data.clear()
        self._ttl.clear()

    async def health_check(self) -> bool:
        """Check if fake Redis is healthy."""
        if self._should_fail or not self._is_started:
            return False
        return True

    def _check_if_should_fail(self, operation: str) -> None:
        """Check if this operation should fail."""
        if not self._is_started:
            raise RuntimeError("Redis storage not initialized")
        if self._should_fail or operation in self._fail_on_operations:
            raise ConnectionError(f"Redis operation '{operation}' failed")

    def _cleanup_expired(self) -> None:
        """Remove expired keys."""
        current_time = time.time()
        expired_keys = [
            key for key, expiry in self._ttl.items() if expiry <= current_time
        ]
        for key in expired_keys:
            self._data.pop(key, None)
            self._ttl.pop(key, None)

    async def get(self, key: str) -> Optional[Any]:
        """Get a value by key."""
        self._check_if_should_fail("get")
        self._cleanup_expired()
        return self._data.get(key)

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set a value with optional TTL."""
        self._check_if_should_fail("set")
        self._data[key] = value
        if ttl:
            self._ttl[key] = time.time() + ttl

    async def delete(self, key: str) -> bool:
        """Delete a key."""
        self._check_if_should_fail("delete")
        self._cleanup_expired()
        if key in self._data:
            self._data.pop(key)
            self._ttl.pop(key, None)
            return True
        return False

    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        self._check_if_should_fail("exists")
        self._cleanup_expired()
        return key in self._data

    async def keys(self, pattern: str = "*") -> List[str]:
        """List keys matching pattern."""
        self._check_if_should_fail("keys")
        self._cleanup_expired()
        if pattern == "*":
            return list(self._data.keys())
        return [key for key in self._data.keys() if fnmatch.fnmatch(key, pattern)]

    async def clear(self) -> None:
        """Clear all data."""
        self._check_if_should_fail("clear")
        self._data.clear()
        self._ttl.clear()

    async def get_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        if not self._is_started:
            return {
                "backend_type": "redis",
                "healthy": False,
                "error": "Not initialized",
            }

        self._cleanup_expired()
        return {
            "backend_type": "redis",
            "healthy": True,
            **self._stats,
            "total_keys": len(self._data),
        }

    async def increment(self, key: str, amount: int = 1) -> int:
        """Increment a numeric value."""
        self._check_if_should_fail("increment")
        current = self._data.get(key, 0)
        new_value = current + amount
        self._data[key] = new_value
        return new_value

    async def expire(self, key: str, ttl: int) -> bool:
        """Set TTL for existing key."""
        self._check_if_should_fail("expire")
        if key in self._data:
            self._ttl[key] = time.time() + ttl
            return True
        return False


class FakeVaultStorage(BaseStorage):
    """Fake Vault storage implementation for testing without Vault dependency.

    This fake implementation follows the same behavioral contract as VaultStorage
    but stores data in memory with simulated Vault-like behavior.
    """

    def __init__(self, should_fail: bool = False, auth_should_fail: bool = False):
        """Initialize fake Vault storage.

        Args:
            should_fail: If True, simulate connection failures
            auth_should_fail: If True, simulate authentication failures
        """
        self._data: Dict[str, Any] = {}
        self._is_started = False
        self._should_fail = should_fail
        self._auth_should_fail = auth_should_fail
        self._token_renewal_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start the fake Vault storage."""
        if self._should_fail:
            raise ConnectionError("Failed to connect to Vault")
        if self._auth_should_fail:
            raise ValueError("Vault authentication failed")

        self._is_started = True
        # Simulate token renewal task
        self._token_renewal_task = asyncio.create_task(self._token_renewal_loop())

    async def stop(self) -> None:
        """Stop the fake Vault storage."""
        if self._token_renewal_task:
            self._token_renewal_task.cancel()
            try:
                await self._token_renewal_task
            except asyncio.CancelledError:
                pass
            self._token_renewal_task = None

        self._is_started = False
        self._data.clear()

    async def _token_renewal_loop(self) -> None:
        """Simulate token renewal."""
        try:
            while True:
                await asyncio.sleep(3600)  # Renew every hour
        except asyncio.CancelledError:
            pass

    async def health_check(self) -> bool:
        """Check if fake Vault is healthy."""
        return self._is_started and not self._should_fail

    def _check_if_should_fail(self, operation: str) -> None:
        """Check if this operation should fail."""
        if not self._is_started:
            raise RuntimeError("Vault storage not initialized")
        if self._should_fail:
            raise ConnectionError(f"Vault operation '{operation}' failed")

    def _cleanup_expired(self) -> None:
        """Remove expired keys."""
        current_time = time.time()
        expired_keys = []

        for key, data in self._data.items():
            if isinstance(data, dict) and "ttl" in data and "timestamp" in data:
                if current_time - data["timestamp"] > data["ttl"]:
                    expired_keys.append(key)

        for key in expired_keys:
            self._data.pop(key, None)

    async def get(self, key: str) -> Optional[Any]:
        """Get a value by key."""
        self._check_if_should_fail("get")
        self._cleanup_expired()

        data = self._data.get(key)
        if data is None:
            return None

        # Handle TTL data format
        if isinstance(data, dict) and "value" in data:
            return data["value"]
        return data

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set a value with optional TTL."""
        self._check_if_should_fail("set")

        if ttl:
            self._data[key] = {"value": value, "ttl": ttl, "timestamp": time.time()}
        else:
            self._data[key] = {"value": value}

    async def delete(self, key: str) -> bool:
        """Delete a key."""
        self._check_if_should_fail("delete")
        self._cleanup_expired()

        if key in self._data:
            self._data.pop(key)
            return True
        return False

    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        self._check_if_should_fail("exists")
        self._cleanup_expired()
        return key in self._data

    async def keys(self, pattern: str = "*") -> List[str]:
        """List keys matching pattern."""
        self._check_if_should_fail("keys")
        self._cleanup_expired()

        if pattern == "*":
            return list(self._data.keys())
        return [key for key in self._data.keys() if fnmatch.fnmatch(key, pattern)]

    async def clear(self) -> None:
        """Clear all data."""
        self._check_if_should_fail("clear")
        self._data.clear()

    async def get_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        if not self._is_started:
            return {
                "backend_type": "vault",
                "healthy": False,
                "error": "Not initialized",
            }

        self._cleanup_expired()
        return {
            "backend_type": "vault",
            "healthy": True,
            "vault_version": "fake-1.9.0",
            "cluster_id": "fake-cluster",
            "total_keys": len(self._data),
            "authenticated": True,
            "mount_point": "secret",
            "path_prefix": "mcp-gateway-test",
        }
