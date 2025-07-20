"""JWT token management for OAuth 2.1."""

import secrets
import time
from dataclasses import asdict
from typing import Any, Dict, Optional

from jose import JWTError, jwt

from ..storage.base import TokenStorage
from .models import AccessToken, RefreshToken, UserInfo


class TokenManager:
    """Manages JWT token creation and validation."""

    def __init__(
        self,
        secret_key: str,
        issuer: str,
        token_storage: TokenStorage,
        algorithm: str = "HS256",
    ):
        self.secret_key = secret_key
        self.issuer = issuer
        self.algorithm = algorithm
        self.token_storage = token_storage

    async def create_access_token(
        self,
        client_id: str,
        user_id: str,
        scope: str,
        resource: Optional[str] = None,
        expires_in: int = 3600,
        user_info: Optional[UserInfo] = None,
    ) -> str:
        """Create JWT access token."""
        now = time.time()
        expires_at = now + expires_in

        # JWT payload
        # Normalize resource to ensure consistent audience
        audience = resource.rstrip("/") if resource else self.issuer.rstrip("/")

        payload = {
            "iss": self.issuer,
            "sub": user_id,
            "aud": audience,
            "client_id": client_id,
            "scope": scope,
            "iat": int(now),
            "exp": int(expires_at),
            "jti": secrets.token_urlsafe(16),
        }

        if resource:
            payload["resource"] = resource

        # Add user info to token payload if available
        if user_info:
            if user_info.email:
                payload["email"] = user_info.email
            if user_info.name:
                payload["name"] = user_info.name
            if user_info.avatar_url:
                payload["avatar_url"] = user_info.avatar_url
            if user_info.provider:
                payload["provider"] = user_info.provider

        # Create JWT
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

        # Store token info
        access_token = AccessToken(
            token=token,
            client_id=client_id,
            user_id=user_id,
            scope=scope,
            resource=resource,
            expires_at=expires_at,
        )

        # Store token info in storage
        await self.token_storage.store_access_token(
            token, asdict(access_token), ttl=expires_in
        )

        return token

    async def create_refresh_token(
        self,
        client_id: str,
        user_id: str,
        scope: str,
        expires_in: int = 86400 * 30,  # 30 days
    ) -> str:
        """Create refresh token."""
        token = secrets.token_urlsafe(32)
        expires_at = time.time() + expires_in

        refresh_token = RefreshToken(
            token=token,
            client_id=client_id,
            user_id=user_id,
            scope=scope,
            expires_at=expires_at,
        )

        # Store refresh token info in storage
        await self.token_storage.store_refresh_token(
            token, asdict(refresh_token), ttl=expires_in
        )

        return token

    async def validate_access_token(
        self, token: str, resource: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Validate JWT access token."""
        try:
            # Decode JWT
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_aud": False},  # We'll verify audience manually
            )

            # Verify issuer
            if payload.get("iss") != self.issuer:
                return None

            # Verify audience if resource is specified
            if resource:
                token_audience = payload.get("aud")
                # Normalize both sides by removing trailing slashes for comparison
                normalized_resource = resource.rstrip("/")
                normalized_audience = (
                    token_audience.rstrip("/") if token_audience else ""
                )
                if normalized_audience != normalized_resource:
                    return None

            # Check if token is stored (for revocation support)
            stored_token_data = await self.token_storage.get_access_token(token)
            if stored_token_data:
                stored_token = AccessToken(**stored_token_data)
                if stored_token.is_expired():
                    await self.token_storage.delete_access_token(token)
                    return None

            return payload

        except JWTError:
            return None

    async def validate_refresh_token(self, token: str) -> Optional[RefreshToken]:
        """Validate refresh token."""
        refresh_token_data = await self.token_storage.get_refresh_token(token)
        if not refresh_token_data:
            return None

        refresh_token = RefreshToken(**refresh_token_data)
        if refresh_token.is_expired():
            await self.token_storage.delete_refresh_token(token)
            return None

        return refresh_token

    async def revoke_access_token(self, token: str) -> bool:
        """Revoke access token."""
        return await self.token_storage.delete_access_token(token)

    async def revoke_refresh_token(self, token: str) -> bool:
        """Revoke refresh token."""
        return await self.token_storage.delete_refresh_token(token)

    async def revoke_all_tokens_for_client(self, client_id: str) -> int:
        """Revoke all tokens for a specific client."""
        revoked_count = 0

        # Get all access tokens
        access_keys = await self.token_storage.keys("access_token:*")
        for key in access_keys:
            token_data = await self.token_storage.get(key)
            if token_data and token_data.get("client_id") == client_id:
                await self.token_storage.delete(key)
                revoked_count += 1

        # Get all refresh tokens
        refresh_keys = await self.token_storage.keys("refresh_token:*")
        for key in refresh_keys:
            token_data = await self.token_storage.get(key)
            if token_data and token_data.get("client_id") == client_id:
                await self.token_storage.delete(key)
                revoked_count += 1

        return revoked_count

    async def revoke_all_tokens_for_user(self, user_id: str) -> int:
        """Revoke all tokens for a specific user."""
        return await self.token_storage.revoke_user_tokens(user_id)

    async def cleanup_expired_tokens(self) -> int:
        """Clean up expired tokens."""
        # Storage backends with TTL will handle this automatically,
        # but we can check for any manually expired tokens
        cleaned_count = 0

        # Check access tokens
        access_keys = await self.token_storage.keys("access_token:*")
        for key in access_keys:
            token_data = await self.token_storage.get(key)
            if token_data:
                token = AccessToken(**token_data)
                if token.is_expired():
                    await self.token_storage.delete(key)
                    cleaned_count += 1

        # Check refresh tokens
        refresh_keys = await self.token_storage.keys("refresh_token:*")
        for key in refresh_keys:
            token_data = await self.token_storage.get(key)
            if token_data:
                token = RefreshToken(**token_data)
                if token.is_expired():
                    await self.token_storage.delete(key)
                    cleaned_count += 1

        return cleaned_count

    async def introspect_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Introspect token per RFC 7662."""
        payload = await self.validate_access_token(token)
        if not payload:
            return {"active": False}

        return {
            "active": True,
            "client_id": payload.get("client_id"),
            "username": payload.get("sub"),
            "scope": payload.get("scope"),
            "aud": payload.get("aud"),
            "iss": payload.get("iss"),
            "exp": payload.get("exp"),
            "iat": payload.get("iat"),
            "token_type": "Bearer",
        }
