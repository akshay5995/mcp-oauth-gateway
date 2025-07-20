"""Storage manager and factory for creating storage backends."""

import logging
from typing import Optional

from ..config.config import StorageConfig
from .base import UnifiedStorage
from .memory import MemoryStorage

logger = logging.getLogger(__name__)


class StorageManager:
    """Manages storage backend creation and configuration.

    Similar to ProviderManager, this class handles the creation and management
    of storage backends based on configuration.
    """

    def __init__(self, storage_config: StorageConfig):
        self.config = storage_config
        self._storage_backend: Optional[UnifiedStorage] = None

    def create_storage_backend(self) -> UnifiedStorage:
        """Create and return the configured storage backend."""
        if self._storage_backend is not None:
            return self._storage_backend

        storage_type = self.config.type.lower()

        if storage_type == "memory":
            self._storage_backend = self._create_memory_storage()
        elif storage_type == "redis":
            self._storage_backend = self._create_redis_storage()
        elif storage_type == "vault":
            self._storage_backend = self._create_vault_storage()
        else:
            logger.warning(
                f"Unknown storage type '{storage_type}', falling back to memory storage"
            )
            self._storage_backend = self._create_memory_storage()

        return self._storage_backend

    def _create_memory_storage(self) -> UnifiedStorage:
        """Create memory storage backend."""
        logger.info("Initializing memory storage backend")
        return MemoryStorage()

    def _create_redis_storage(self) -> UnifiedStorage:
        """Create Redis storage backend."""
        try:
            from .redis import RedisStorage

            logger.info(
                f"Initializing Redis storage backend: {self.config.redis.host}:{self.config.redis.port}"
            )
            return RedisStorage(self.config.redis)
        except ImportError:
            logger.error(
                "Redis storage requested but Redis library not installed. Falling back to memory storage."
            )
            logger.info(
                "Install with: pip install 'redis[hiredis]' (recommended) or pip install aioredis"
            )
            return self._create_memory_storage()
        except Exception as e:
            logger.error(
                f"Failed to initialize Redis storage: {e}. Falling back to memory storage."
            )
            return self._create_memory_storage()

    def _create_vault_storage(self) -> UnifiedStorage:
        """Create Vault storage backend."""
        try:
            from .vault import VaultStorage

            logger.info(f"Initializing Vault storage backend: {self.config.vault.url}")
            return VaultStorage(self.config.vault)
        except ImportError:
            logger.error(
                "Vault storage requested but 'hvac' not installed. Falling back to memory storage."
            )
            logger.info("Install with: pip install hvac")
            return self._create_memory_storage()
        except Exception as e:
            logger.error(
                f"Failed to initialize Vault storage: {e}. Falling back to memory storage."
            )
            return self._create_memory_storage()

    async def start_storage(self) -> UnifiedStorage:
        """Create and start the storage backend."""
        storage = self.create_storage_backend()
        try:
            await storage.start()
            logger.info(f"Storage backend started successfully: {self.config.type}")
            return storage
        except Exception as e:
            logger.error(f"Failed to start storage backend '{self.config.type}': {e}")
            # Try to fallback to memory storage if configured backend fails
            if self.config.type != "memory":
                logger.info("Attempting fallback to memory storage")
                fallback_storage = self._create_memory_storage()
                await fallback_storage.start()
                self._storage_backend = fallback_storage
                return fallback_storage
            raise

    async def stop_storage(self) -> None:
        """Stop the storage backend."""
        if self._storage_backend:
            try:
                await self._storage_backend.stop()
                logger.info("Storage backend stopped successfully")
            except Exception as e:
                logger.error(f"Error stopping storage backend: {e}")
            finally:
                self._storage_backend = None

    async def health_check(self) -> bool:
        """Check if storage backend is healthy."""
        if self._storage_backend:
            try:
                return await self._storage_backend.health_check()
            except Exception as e:
                logger.error(f"Storage health check failed: {e}")
                return False
        return False

    def get_storage_info(self) -> dict:
        """Get information about the current storage backend."""
        return {
            "type": self.config.type,
            "backend": (
                type(self._storage_backend).__name__
                if self._storage_backend
                else "None"
            ),
            "healthy": True if self._storage_backend else False,
        }
