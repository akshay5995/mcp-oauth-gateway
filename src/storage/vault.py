"""Vault storage backend implementation."""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

try:
    import aiohttp
    import hvac

    VAULT_AVAILABLE = True
except ImportError:
    VAULT_AVAILABLE = False

from ..config.config import VaultStorageConfig
from .base import UnifiedStorage

logger = logging.getLogger(__name__)


class VaultStorage(UnifiedStorage):
    """HashiCorp Vault storage backend implementation.

    This backend is suitable for:
    - Enterprise environments
    - Compliance requirements
    - High-security deployments
    - Encrypted storage at rest
    - Audit logging requirements
    """

    def __init__(self, config: VaultStorageConfig):
        if not VAULT_AVAILABLE:
            raise ImportError(
                "hvac is required for Vault storage backend. Install with: pip install hvac"
            )

        self.config = config
        self.client: Optional[hvac.Client] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._token_renewal_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Initialize Vault connection."""
        try:
            # Create aiohttp session for async operations
            self._session = aiohttp.ClientSession()

            # Create Vault client (without session for now due to type issues)
            self.client = hvac.Client(
                url=self.config.url,
                token=self.config.token,
            )

            # Authenticate based on auth method
            await self._authenticate()

            # Verify connection and permissions
            if not self.client.is_authenticated():
                raise ValueError("Vault authentication failed")

            # Test access to KV store
            await self._test_kv_access()

            # Start token renewal if using token auth
            if self.config.auth_method == "token":
                self._token_renewal_task = asyncio.create_task(
                    self._token_renewal_loop()
                )

            logger.info(f"Vault storage connected: {self.config.url}")

        except Exception as e:
            logger.error(f"Failed to connect to Vault: {e}")
            await self.stop()
            raise

    async def stop(self) -> None:
        """Cleanup Vault connections."""
        # Stop token renewal
        if self._token_renewal_task:
            self._token_renewal_task.cancel()
            try:
                await self._token_renewal_task
            except asyncio.CancelledError:
                pass
            self._token_renewal_task = None

        # Close HTTP session
        if self._session:
            try:
                await self._session.close()
                logger.info("Vault storage disconnected")
            except Exception as e:
                logger.error(f"Error disconnecting from Vault: {e}")
            finally:
                self._session = None

        self.client = None

    async def health_check(self) -> bool:
        """Check if Vault is healthy."""
        if not self.client:
            return False

        try:
            # Check Vault health status
            health = self.client.sys.read_health_status()
            return health.get("initialized", False) and not health.get("sealed", True)
        except Exception as e:
            logger.error(f"Vault health check failed: {e}")
            return False

    async def get(self, key: str) -> Optional[Any]:
        """Get a value by key."""
        if not self.client:
            raise RuntimeError("Vault storage not initialized")

        try:
            vault_path = self._get_vault_path(key)
            if not self.client:
                raise RuntimeError("Vault storage not initialized")
            response = self.client.secrets.kv.v2.read_secret(
                path=vault_path, mount_point=self.config.mount_point
            )

            if response and "data" in response and "data" in response["data"]:
                data = response["data"]["data"]

                # Check TTL if present
                if "ttl" in data and "timestamp" in data:
                    ttl = data["ttl"]
                    timestamp = data["timestamp"]
                    if time.time() > timestamp + ttl:
                        # Key has expired, delete it
                        await self.delete(key)
                        return None

                return data.get("value")

            return None

        except Exception as e:
            # Check if it's a path not found error (key doesn't exist)
            if "path not found" in str(e).lower() or "invalid path" in str(e).lower():
                return None
            # Log and re-raise other exceptions
            logger.error(f"Vault get error for key '{key}': {e}")
            raise

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set a value with optional TTL in seconds."""
        if not self.client:
            raise RuntimeError("Vault storage not initialized")

        try:
            vault_path = self._get_vault_path(key)
            if not self.client:
                raise RuntimeError("Vault storage not initialized")
            data = {"value": value}

            if ttl is not None:
                data["ttl"] = ttl
                data["timestamp"] = time.time()

            self.client.secrets.kv.v2.create_or_update_secret(
                path=vault_path, secret=data, mount_point=self.config.mount_point
            )

        except Exception as e:
            logger.error(f"Vault set error for key '{key}': {e}")
            raise

    async def delete(self, key: str) -> bool:
        """Delete a key. Returns True if key existed."""
        if not self.client:
            raise RuntimeError("Vault storage not initialized")

        try:
            vault_path = self._get_vault_path(key)
            if not self.client:
                raise RuntimeError("Vault storage not initialized")

            # Check if key exists first
            try:
                self.client.secrets.kv.v2.read_secret(
                    path=vault_path, mount_point=self.config.mount_point
                )
                key_existed = True
            except Exception as e:
                # Check if it's a path not found error
                if (
                    "path not found" in str(e).lower()
                    or "invalid path" in str(e).lower()
                ):
                    key_existed = False
                else:
                    raise

            if key_existed:
                self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                    path=vault_path, mount_point=self.config.mount_point
                )

            return key_existed

        except Exception as e:
            logger.error(f"Vault delete error for key '{key}': {e}")
            raise

    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        value = await self.get(key)
        return value is not None

    async def keys(self, pattern: str = "*") -> List[str]:
        """List keys matching pattern."""
        if not self.client:
            raise RuntimeError("Vault storage not initialized")

        try:
            # List all secrets in the path prefix
            base_path = self.config.path_prefix
            if not self.client:
                raise RuntimeError("Vault storage not initialized")
            response = self.client.secrets.kv.v2.list_secrets(
                path=base_path, mount_point=self.config.mount_point
            )

            if response and "data" in response and "keys" in response["data"]:
                vault_keys = response["data"]["keys"]

                # Convert vault paths back to keys and apply pattern matching
                import fnmatch

                keys = []
                for vault_key in vault_keys:
                    # Remove vault prefix to get original key
                    if vault_key.startswith(f"{base_path}/"):
                        original_key = vault_key[len(f"{base_path}/") :]
                        if pattern == "*" or fnmatch.fnmatch(original_key, pattern):
                            keys.append(original_key)

                return keys

            return []

        except Exception as e:
            # Check if it's a path not found error
            if "path not found" in str(e).lower() or "invalid path" in str(e).lower():
                return []
            # Re-raise other exceptions
            logger.error(f"Vault keys error for pattern '{pattern}': {e}")
            raise

    async def clear(self) -> None:
        """Clear all data (use with caution)."""
        if not self.client:
            raise RuntimeError("Vault storage not initialized")

        try:
            # Get all keys and delete them
            all_keys = await self.keys("*")
            for key in all_keys:
                await self.delete(key)

            logger.warning(f"Vault storage cleared: {len(all_keys)} keys deleted")

        except Exception as e:
            logger.error(f"Vault clear error: {e}")
            raise

    def _get_vault_path(self, key: str) -> str:
        """Convert storage key to Vault path."""
        return f"{self.config.path_prefix}/{key}"

    async def _authenticate(self) -> None:
        """Authenticate with Vault based on auth method."""
        if self.config.auth_method == "token":
            # Token auth is already configured in client
            pass
        elif self.config.auth_method == "approle":
            # TODO: Implement AppRole authentication
            raise NotImplementedError("AppRole authentication not yet implemented")
        elif self.config.auth_method == "kubernetes":
            # TODO: Implement Kubernetes authentication
            raise NotImplementedError("Kubernetes authentication not yet implemented")
        else:
            raise ValueError(
                f"Unsupported Vault auth method: {self.config.auth_method}"
            )

    async def _test_kv_access(self) -> None:
        """Test access to KV store."""
        test_path = f"{self.config.path_prefix}/test"
        try:
            if not self.client:
                raise RuntimeError("Vault storage not initialized")
            # Try to write and read a test value
            self.client.secrets.kv.v2.create_or_update_secret(
                path=test_path,
                secret={"test": "value"},
                mount_point=self.config.mount_point,
            )

            self.client.secrets.kv.v2.read_secret(
                path=test_path, mount_point=self.config.mount_point
            )

            # Clean up test value
            self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=test_path, mount_point=self.config.mount_point
            )

        except Exception as e:
            raise ValueError(f"Vault KV access test failed: {e}") from e

    async def _token_renewal_loop(self) -> None:
        """Background task to renew Vault token."""
        while True:
            try:
                # Renew token every 30 minutes
                await asyncio.sleep(1800)

                if self.client and self.client.is_authenticated():
                    try:
                        self.client.auth.token.renew_self()
                        logger.debug("Vault token renewed")
                    except Exception as e:
                        logger.error(f"Failed to renew Vault token: {e}")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in token renewal loop: {e}")

    async def get_stats(self) -> Dict[str, Any]:
        """Get Vault storage statistics."""
        if not self.client:
            return {
                "backend_type": "vault",
                "healthy": False,
                "error": "Not initialized",
            }

        try:
            health = self.client.sys.read_health_status()
            key_count = len(await self.keys("*"))

            return {
                "backend_type": "vault",
                "healthy": health.get("initialized", False)
                and not health.get("sealed", True),
                "vault_version": health.get("version", "unknown"),
                "cluster_id": health.get("cluster_id", "unknown"),
                "total_keys": key_count,
                "authenticated": self.client.is_authenticated(),
                "mount_point": self.config.mount_point,
                "path_prefix": self.config.path_prefix,
            }

        except Exception as e:
            logger.error(f"Failed to get Vault stats: {e}")
            return {"backend_type": "vault", "healthy": False, "error": str(e)}
