"""Redis storage backend implementation."""

import json
import logging
from typing import Any, List, Optional

try:
    # Try modern redis-py first (recommended for Python 3.11+)
    import redis.asyncio as redis

    REDIS_AVAILABLE = True
    REDIS_LIBRARY = "redis-py"
except ImportError:
    try:
        # Fallback to aioredis for older installations
        import aioredis as redis

        REDIS_AVAILABLE = True
        REDIS_LIBRARY = "aioredis"
    except ImportError:
        REDIS_AVAILABLE = False
        REDIS_LIBRARY = None

from ..config.config import RedisStorageConfig
from .base import UnifiedStorage

logger = logging.getLogger(__name__)


class RedisStorage(UnifiedStorage):
    """Redis storage backend implementation.

    This backend is suitable for:
    - Production deployments
    - Multi-instance gateway deployments
    - High-performance caching requirements
    - Automatic TTL-based cleanup
    """

    def __init__(self, config: RedisStorageConfig):
        if not REDIS_AVAILABLE:
            raise ImportError(
                "Redis library is required for Redis storage backend. "
                "Install with: pip install redis[hiredis] (recommended) or pip install aioredis"
            )

        self.config = config
        self.redis: Optional[Any] = None  # Support both redis-py and aioredis
        self._connection_pool: Optional[Any] = (
            None  # Support both connection pool types
        )
        self._library = REDIS_LIBRARY

    async def start(self) -> None:
        """Initialize Redis connection."""
        try:
            if self._library == "redis-py":
                # Use modern redis-py library
                self.redis = redis.Redis(
                    host=self.config.host,
                    port=self.config.port,
                    password=self.config.password,
                    db=self.config.db,
                    ssl=self.config.ssl,
                    max_connections=self.config.max_connections,
                    socket_timeout=getattr(self.config, "socket_timeout", 5.0),
                    retry_on_timeout=True,
                    decode_responses=False,  # We handle decoding manually
                )
            else:
                # Use legacy aioredis library
                self._connection_pool = redis.ConnectionPool(
                    host=self.config.host,
                    port=self.config.port,
                    password=self.config.password,
                    db=self.config.db,
                    ssl=self.config.ssl,
                    max_connections=self.config.max_connections,
                    retry_on_timeout=True,
                    health_check_interval=30,
                )
                self.redis = redis.Redis(connection_pool=self._connection_pool)

            # Test connection
            await self.redis.ping()
            logger.info(
                f"Redis storage connected ({self._library}): {self.config.host}:{self.config.port}"
            )

        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    async def stop(self) -> None:
        """Cleanup Redis connections."""
        if self.redis:
            try:
                if self._library == "redis-py":
                    await self.redis.close()
                else:
                    await self.redis.close()
                logger.info("Redis storage disconnected")
            except Exception as e:
                logger.error(f"Error disconnecting from Redis: {e}")
            finally:
                self.redis = None

        if self._connection_pool:
            try:
                if hasattr(self._connection_pool, "disconnect"):
                    await self._connection_pool.disconnect()
                elif hasattr(self._connection_pool, "close"):
                    await self._connection_pool.close()
            except Exception as e:
                logger.error(f"Error closing Redis connection pool: {e}")
            finally:
                self._connection_pool = None

    async def health_check(self) -> bool:
        """Check if Redis is healthy."""
        if not self.redis:
            return False

        try:
            await self.redis.ping()
            return True
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return False

    async def get(self, key: str) -> Optional[Any]:
        """Get a value by key."""
        if not self.redis:
            raise RuntimeError("Redis storage not initialized")

        try:
            value = await self.redis.get(key)
            if value is None:
                return None

            # Handle both string and bytes responses
            if isinstance(value, bytes):
                value = value.decode("utf-8")

            return json.loads(value)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode JSON for key '{key}': {e}")
            return None
        except Exception as e:
            logger.error(f"Redis get error for key '{key}': {e}")
            raise

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set a value with optional TTL in seconds."""
        if not self.redis:
            raise RuntimeError("Redis storage not initialized")

        try:
            serialized_value = json.dumps(value)
            if ttl is not None:
                await self.redis.setex(key, ttl, serialized_value)
            else:
                await self.redis.set(key, serialized_value)
        except Exception as e:
            logger.error(f"Redis set error for key '{key}': {e}")
            raise

    async def delete(self, key: str) -> bool:
        """Delete a key. Returns True if key existed."""
        if not self.redis:
            raise RuntimeError("Redis storage not initialized")

        try:
            result = await self.redis.delete(key)
            return result > 0
        except Exception as e:
            logger.error(f"Redis delete error for key '{key}': {e}")
            raise

    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        if not self.redis:
            raise RuntimeError("Redis storage not initialized")

        try:
            result = await self.redis.exists(key)
            return result > 0
        except Exception as e:
            logger.error(f"Redis exists error for key '{key}': {e}")
            raise

    async def keys(self, pattern: str = "*") -> List[str]:
        """List keys matching pattern."""
        if not self.redis:
            raise RuntimeError("Redis storage not initialized")

        try:
            keys = await self.redis.keys(pattern)
            # Handle both string and bytes responses
            result = []
            for key in keys:
                if isinstance(key, bytes):
                    result.append(key.decode("utf-8"))
                else:
                    result.append(str(key))
            return result
        except Exception as e:
            logger.error(f"Redis keys error for pattern '{pattern}': {e}")
            raise

    async def clear(self) -> None:
        """Clear all data (use with caution)."""
        if not self.redis:
            raise RuntimeError("Redis storage not initialized")

        try:
            await self.redis.flushdb()
            logger.warning("Redis database cleared")
        except Exception as e:
            logger.error(f"Redis clear error: {e}")
            raise

    async def get_stats(self) -> dict:
        """Get Redis storage statistics."""
        if not self.redis:
            return {
                "backend_type": "redis",
                "healthy": False,
                "error": "Not initialized",
            }

        try:
            info = await self.redis.info()
            return {
                "backend_type": "redis",
                "healthy": True,
                "connected_clients": info.get("connected_clients", 0),
                "used_memory": info.get("used_memory", 0),
                "used_memory_human": info.get("used_memory_human", "0B"),
                "total_keys": await self.redis.dbsize(),
                "redis_version": info.get("redis_version", "unknown"),
            }
        except Exception as e:
            logger.error(f"Failed to get Redis stats: {e}")
            return {"backend_type": "redis", "healthy": False, "error": str(e)}

    async def increment(self, key: str, amount: int = 1) -> int:
        """Increment a numeric value."""
        if not self.redis:
            raise RuntimeError("Redis storage not initialized")

        try:
            return await self.redis.incrby(key, amount)
        except Exception as e:
            logger.error(f"Redis increment error for key '{key}': {e}")
            raise

    async def expire(self, key: str, ttl: int) -> bool:
        """Set TTL for an existing key."""
        if not self.redis:
            raise RuntimeError("Redis storage not initialized")

        try:
            result = await self.redis.expire(key, ttl)
            return result
        except Exception as e:
            logger.error(f"Redis expire error for key '{key}': {e}")
            raise
