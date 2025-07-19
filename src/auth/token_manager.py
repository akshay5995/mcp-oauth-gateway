"""JWT token management for OAuth 2.1."""

import secrets
import time
from typing import Any, Dict, Optional

from jose import JWTError, jwt

from .models import AccessToken, RefreshToken, UserInfo


class TokenManager:
    """Manages JWT token creation and validation."""

    def __init__(self, secret_key: str, issuer: str, algorithm: str = "HS256"):
        self.secret_key = secret_key
        self.issuer = issuer
        self.algorithm = algorithm
        self.access_tokens: Dict[str, AccessToken] = {}
        self.refresh_tokens: Dict[str, RefreshToken] = {}

    def create_access_token(
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

        self.access_tokens[token] = access_token

        return token

    def create_refresh_token(
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

        self.refresh_tokens[token] = refresh_token

        return token

    def validate_access_token(
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
            stored_token = self.access_tokens.get(token)
            if stored_token and stored_token.is_expired():
                del self.access_tokens[token]
                return None

            return payload

        except JWTError:
            return None

    def validate_refresh_token(self, token: str) -> Optional[RefreshToken]:
        """Validate refresh token."""
        refresh_token = self.refresh_tokens.get(token)
        if not refresh_token:
            return None

        if refresh_token.is_expired():
            del self.refresh_tokens[token]
            return None

        return refresh_token

    def revoke_access_token(self, token: str) -> bool:
        """Revoke access token."""
        if token in self.access_tokens:
            del self.access_tokens[token]
            return True
        return False

    def revoke_refresh_token(self, token: str) -> bool:
        """Revoke refresh token."""
        if token in self.refresh_tokens:
            del self.refresh_tokens[token]
            return True
        return False

    def revoke_all_tokens_for_client(self, client_id: str) -> int:
        """Revoke all tokens for a specific client."""
        revoked_count = 0

        # Revoke access tokens
        access_tokens_to_remove = [
            token
            for token, token_info in self.access_tokens.items()
            if token_info.client_id == client_id
        ]

        for token in access_tokens_to_remove:
            del self.access_tokens[token]
            revoked_count += 1

        # Revoke refresh tokens
        refresh_tokens_to_remove = [
            token
            for token, token_info in self.refresh_tokens.items()
            if token_info.client_id == client_id
        ]

        for token in refresh_tokens_to_remove:
            del self.refresh_tokens[token]
            revoked_count += 1

        return revoked_count

    def revoke_all_tokens_for_user(self, user_id: str) -> int:
        """Revoke all tokens for a specific user."""
        revoked_count = 0

        # Revoke access tokens
        access_tokens_to_remove = [
            token
            for token, token_info in self.access_tokens.items()
            if token_info.user_id == user_id
        ]

        for token in access_tokens_to_remove:
            del self.access_tokens[token]
            revoked_count += 1

        # Revoke refresh tokens
        refresh_tokens_to_remove = [
            token
            for token, token_info in self.refresh_tokens.items()
            if token_info.user_id == user_id
        ]

        for token in refresh_tokens_to_remove:
            del self.refresh_tokens[token]
            revoked_count += 1

        return revoked_count

    def cleanup_expired_tokens(self) -> int:
        """Clean up expired tokens."""
        cleaned_count = 0

        # Clean access tokens
        expired_access_tokens = [
            token
            for token, token_info in self.access_tokens.items()
            if token_info.is_expired()
        ]

        for token in expired_access_tokens:
            del self.access_tokens[token]
            cleaned_count += 1

        # Clean refresh tokens
        expired_refresh_tokens = [
            token
            for token, token_info in self.refresh_tokens.items()
            if token_info.is_expired()
        ]

        for token in expired_refresh_tokens:
            del self.refresh_tokens[token]
            cleaned_count += 1

        return cleaned_count

    def introspect_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Introspect token per RFC 7662."""
        payload = self.validate_access_token(token)
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
