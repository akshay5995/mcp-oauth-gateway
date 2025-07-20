"""Abstract base classes for storage backends."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseStorage(ABC):
    """Base abstract class for all storage backends."""

    @abstractmethod
    async def start(self) -> None:
        """Initialize the storage backend."""
        pass

    @abstractmethod
    async def stop(self) -> None:
        """Cleanup storage backend resources."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if storage backend is healthy."""
        pass

    @abstractmethod
    async def get(self, key: str) -> Optional[Any]:
        """Get a value by key."""
        pass

    @abstractmethod
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set a value with optional TTL in seconds."""
        pass

    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete a key. Returns True if key existed."""
        pass

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        pass

    @abstractmethod
    async def keys(self, pattern: str = "*") -> List[str]:
        """List keys matching pattern."""
        pass

    @abstractmethod
    async def clear(self) -> None:
        """Clear all data (use with caution)."""
        pass

    @abstractmethod
    async def get_stats(self) -> Dict[str, Any]:
        """Get storage backend statistics."""
        pass


class UnifiedStorage(BaseStorage):
    """Unified storage interface that includes all storage operations.

    This class combines session, token, and client storage operations
    to avoid multiple inheritance issues.
    """

    # Session storage methods
    async def store_oauth_state(
        self, state_id: str, state_data: Dict[str, Any], ttl: int = 600
    ) -> None:
        """Store OAuth state with 10-minute default TTL."""
        await self.set(f"oauth_state:{state_id}", state_data, ttl)

    async def get_oauth_state(self, state_id: str) -> Optional[Dict[str, Any]]:
        """Get OAuth state by ID."""
        return await self.get(f"oauth_state:{state_id}")

    async def delete_oauth_state(self, state_id: str) -> bool:
        """Delete OAuth state."""
        return await self.delete(f"oauth_state:{state_id}")

    async def store_authorization_code(
        self, code: str, code_data: Dict[str, Any], ttl: int = 600
    ) -> None:
        """Store authorization code with 10-minute default TTL."""
        await self.set(f"auth_code:{code}", code_data, ttl)

    async def get_authorization_code(self, code: str) -> Optional[Dict[str, Any]]:
        """Get authorization code data."""
        return await self.get(f"auth_code:{code}")

    async def delete_authorization_code(self, code: str) -> bool:
        """Delete authorization code."""
        return await self.delete(f"auth_code:{code}")

    async def store_user_session(
        self, user_id: str, user_data: Dict[str, Any], ttl: int = 86400
    ) -> None:
        """Store user session with 24-hour default TTL."""
        await self.set(f"user_session:{user_id}", user_data, ttl)

    async def get_user_session(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user session data."""
        return await self.get(f"user_session:{user_id}")

    async def delete_user_session(self, user_id: str) -> bool:
        """Delete user session."""
        return await self.delete(f"user_session:{user_id}")

    # Token storage methods
    async def store_access_token(
        self, token_id: str, token_data: Dict[str, Any], ttl: int = 3600
    ) -> None:
        """Store access token with 1-hour default TTL."""
        await self.set(f"access_token:{token_id}", token_data, ttl)

    async def get_access_token(self, token_id: str) -> Optional[Dict[str, Any]]:
        """Get access token data."""
        return await self.get(f"access_token:{token_id}")

    async def delete_access_token(self, token_id: str) -> bool:
        """Delete access token."""
        return await self.delete(f"access_token:{token_id}")

    async def store_refresh_token(
        self, token_id: str, token_data: Dict[str, Any], ttl: int = 2592000
    ) -> None:
        """Store refresh token with 30-day default TTL."""
        await self.set(f"refresh_token:{token_id}", token_data, ttl)

    async def get_refresh_token(self, token_id: str) -> Optional[Dict[str, Any]]:
        """Get refresh token data."""
        return await self.get(f"refresh_token:{token_id}")

    async def delete_refresh_token(self, token_id: str) -> bool:
        """Delete refresh token."""
        return await self.delete(f"refresh_token:{token_id}")

    async def revoke_user_tokens(self, user_id: str) -> int:
        """Revoke all tokens for a user. Returns count of revoked tokens."""
        access_keys = await self.keys("access_token:*")
        refresh_keys = await self.keys("refresh_token:*")

        revoked_count = 0
        # Check access tokens
        for key in access_keys:
            token_data = await self.get(key)
            if token_data and token_data.get("user_id") == user_id:
                await self.delete(key)
                revoked_count += 1

        # Check refresh tokens
        for key in refresh_keys:
            token_data = await self.get(key)
            if token_data and token_data.get("user_id") == user_id:
                await self.delete(key)
                revoked_count += 1

        return revoked_count

    # Client storage methods
    async def store_client(self, client_id: str, client_data: Dict[str, Any]) -> None:
        """Store client data (no TTL - persistent)."""
        await self.set(f"client:{client_id}", client_data)

    async def get_client(self, client_id: str) -> Optional[Dict[str, Any]]:
        """Get client data by client ID."""
        return await self.get(f"client:{client_id}")

    async def delete_client(self, client_id: str) -> bool:
        """Delete client registration."""
        return await self.delete(f"client:{client_id}")

    async def list_clients(self) -> List[Dict[str, Any]]:
        """List all registered clients."""
        client_keys = await self.keys("client:*")
        clients = []
        for key in client_keys:
            client_data = await self.get(key)
            if client_data:
                clients.append(client_data)
        return clients

    async def find_client_by_redirect_uris(
        self, redirect_uris: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Find client by matching redirect URIs (for deduplication)."""
        clients = await self.list_clients()
        for client in clients:
            if set(client.get("redirect_uris", [])) == set(redirect_uris):
                return client
        return None


# Type aliases for backwards compatibility
SessionStorage = UnifiedStorage
TokenStorage = UnifiedStorage
ClientStorage = UnifiedStorage
