"""In-memory storage backend implementation."""

import asyncio
import time
from typing import Any, Dict, List, Optional

from .base import UnifiedStorage


class MemoryStorage(UnifiedStorage):
    """In-memory storage backend using dictionaries.

    This is the default storage backend, suitable for:
    - Development and testing
    - Single-instance deployments
    - Non-persistent storage requirements
    """

    def __init__(self):
        self._data: Dict[str, Any] = {}
        self._ttl: Dict[str, float] = {}
        self._cleanup_task: Optional[asyncio.Task] = None
        self._cleanup_interval = 60  # Run cleanup every 60 seconds

    async def start(self) -> None:
        """Initialize the memory storage backend."""
        self._data.clear()
        self._ttl.clear()

        # Start cleanup task for expired keys
        self._cleanup_task = asyncio.create_task(self._cleanup_expired_keys())

    async def stop(self) -> None:
        """Cleanup memory storage resources."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        self._data.clear()
        self._ttl.clear()

    async def health_check(self) -> bool:
        """Check if memory storage is healthy."""
        return True  # Memory storage is always healthy

    async def get(self, key: str) -> Optional[Any]:
        """Get a value by key."""
        # Check if key has expired
        if key in self._ttl:
            if time.time() > self._ttl[key]:
                # Key has expired, remove it
                await self.delete(key)
                return None

        return self._data.get(key)

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set a value with optional TTL in seconds."""
        self._data[key] = value

        if ttl is not None:
            self._ttl[key] = time.time() + ttl
        else:
            # Remove TTL if it exists
            self._ttl.pop(key, None)

    async def delete(self, key: str) -> bool:
        """Delete a key. Returns True if key existed."""
        existed = key in self._data
        self._data.pop(key, None)
        self._ttl.pop(key, None)
        return existed

    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        # This will also handle TTL expiration
        value = await self.get(key)
        return value is not None

    async def keys(self, pattern: str = "*") -> List[str]:
        """List keys matching pattern."""
        import fnmatch

        # Clean up expired keys first
        await self._cleanup_expired_keys_sync()

        if pattern == "*":
            return list(self._data.keys())

        return [key for key in self._data.keys() if fnmatch.fnmatch(key, pattern)]

    async def clear(self) -> None:
        """Clear all data (use with caution)."""
        self._data.clear()
        self._ttl.clear()

    async def _cleanup_expired_keys(self) -> None:
        """Background task to cleanup expired keys."""
        while True:
            try:
                await asyncio.sleep(self._cleanup_interval)
                await self._cleanup_expired_keys_sync()
            except asyncio.CancelledError:
                break
            except Exception as e:
                # Log error but continue cleanup
                import logging

                logger = logging.getLogger(__name__)
                logger.error(f"Error during memory storage cleanup: {e}")

    async def _cleanup_expired_keys_sync(self) -> None:
        """Synchronously cleanup expired keys."""
        current_time = time.time()
        expired_keys = [
            key for key, expiry_time in self._ttl.items() if current_time > expiry_time
        ]

        for key in expired_keys:
            self._data.pop(key, None)
            self._ttl.pop(key, None)

    async def get_stats(self) -> Dict[str, Any]:
        """Get memory storage statistics."""
        return {
            "total_keys": len(self._data),
            "keys_with_ttl": len(self._ttl),
            "backend_type": "memory",
            "healthy": True,
        }
