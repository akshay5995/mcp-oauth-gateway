"""OAuth 2.1 Authorization Server implementation."""

import base64
import hashlib
import logging
import secrets
from dataclasses import asdict
from typing import Optional, Tuple

from ..storage.base import SessionStorage
from .client_registry import ClientRegistry
from .models import (
    AuthorizationCode,
    AuthorizeRequest,
    ClientRegistrationRequest,
    ErrorResponse,
    OAuthState,
    TokenRequest,
    TokenResponse,
    UserInfo,
)
from .token_manager import TokenManager

logger = logging.getLogger(__name__)


class OAuthServer:
    """OAuth 2.1 Authorization Server."""

    def __init__(
        self,
        secret_key: str,
        issuer: str,
        session_storage: SessionStorage,
        client_registry: ClientRegistry,
        token_manager: TokenManager,
    ):
        self.secret_key = secret_key
        self.issuer = issuer
        self.session_storage = session_storage
        self.client_registry = client_registry
        self.token_manager = token_manager

    async def handle_authorize(
        self, request: AuthorizeRequest
    ) -> Tuple[str, Optional[ErrorResponse]]:
        """Handle authorization endpoint request."""
        try:
            # Validate client
            client = await self.client_registry.get_client(request.client_id)
            if not client:
                return "", ErrorResponse("invalid_client", "Client not found")

            # Validate redirect URI
            if not await self.client_registry.validate_redirect_uri(
                request.client_id, request.redirect_uri
            ):
                return "", ErrorResponse("invalid_request", "Invalid redirect URI")

            # Validate response type
            if not await self.client_registry.validate_response_type(
                request.client_id, request.response_type
            ):
                return "", ErrorResponse(
                    "unsupported_response_type", "Unsupported response type"
                )

            if request.response_type != "code":
                return "", ErrorResponse(
                    "unsupported_response_type",
                    "Only 'code' response type is supported",
                )

            # Validate PKCE
            if request.code_challenge and request.code_challenge_method != "S256":
                return "", ErrorResponse(
                    "invalid_request", "Only S256 code challenge method is supported"
                )

            # Validate scope
            scope = request.scope or ""

            # Generate state for provider authentication
            provider_state = self._generate_state()

            # Store OAuth state
            oauth_state = OAuthState(
                state=provider_state,
                client_state=request.state or "",  # Store original client state
                client_id=request.client_id,
                redirect_uri=request.redirect_uri,
                scope=scope,
                resource=request.resource,
                code_challenge=request.code_challenge,
                code_challenge_method=request.code_challenge_method,
                provider="",  # Will be set by provider manager
            )

            await self.session_storage.set(
                f"oauth_state:{provider_state}", asdict(oauth_state), ttl=600
            )  # 10 minutes

            # Return state for provider authentication
            return provider_state, None

        except Exception as e:
            return "", ErrorResponse("server_error", str(e))

    async def handle_token(
        self, request: TokenRequest
    ) -> Tuple[Optional[TokenResponse], Optional[ErrorResponse]]:
        """Handle token endpoint request."""
        try:
            if request.grant_type == "authorization_code":
                return await self._handle_authorization_code_grant(request)
            elif request.grant_type == "refresh_token":
                return await self._handle_refresh_token_grant(request)
            else:
                return None, ErrorResponse(
                    "unsupported_grant_type", "Unsupported grant type"
                )

        except Exception as e:
            return None, ErrorResponse("server_error", str(e))

    async def _handle_authorization_code_grant(
        self, request: TokenRequest
    ) -> Tuple[Optional[TokenResponse], Optional[ErrorResponse]]:
        """Handle authorization code grant."""
        # Authenticate client
        client = None
        if request.client_secret:
            client = await self.client_registry.authenticate_client(
                request.client_id, request.client_secret
            )
        else:
            client = await self.client_registry.get_client(request.client_id)

        if not client:
            return None, ErrorResponse("invalid_client", "Client authentication failed")

        # Validate authorization code
        if not request.code:
            return None, ErrorResponse("invalid_request", "Authorization code required")

        auth_code_data = await self.session_storage.get(f"auth_code:{request.code}")
        if not auth_code_data:
            return None, ErrorResponse("invalid_grant", "Invalid authorization code")

        auth_code = AuthorizationCode(**auth_code_data)
        if auth_code.is_expired():
            await self.session_storage.delete(f"auth_code:{request.code}")
            return None, ErrorResponse("invalid_grant", "Authorization code expired")

        if auth_code.client_id != request.client_id:
            return None, ErrorResponse(
                "invalid_grant", "Authorization code client mismatch"
            )

        if auth_code.redirect_uri != request.redirect_uri:
            return None, ErrorResponse("invalid_grant", "Redirect URI mismatch")

        # Validate PKCE
        if auth_code.code_challenge:
            if not request.code_verifier:
                return None, ErrorResponse("invalid_request", "Code verifier required")

            # Verify code challenge
            if not self._verify_pkce(request.code_verifier, auth_code.code_challenge):
                logger.warning("PKCE verification failed")
                return None, ErrorResponse("invalid_grant", "Invalid code verifier")

        # Get user info
        user_data = await self.session_storage.get(f"user_session:{auth_code.user_id}")
        if not user_data:
            return None, ErrorResponse("invalid_grant", "User session not found")

        # Create tokens
        token_resource = auth_code.resource or request.resource
        logger.info("Creating access token")

        # Get user info for token creation
        user_info = await self.get_user_info(auth_code.user_id)

        access_token = await self.token_manager.create_access_token(
            client_id=request.client_id,
            user_id=auth_code.user_id,
            scope=auth_code.scope,
            resource=token_resource,
            user_info=user_info,
        )

        refresh_token = await self.token_manager.create_refresh_token(
            client_id=request.client_id,
            user_id=auth_code.user_id,
            scope=auth_code.scope,
        )

        # Clean up authorization code
        await self.session_storage.delete(f"auth_code:{request.code}")

        return (
            TokenResponse(
                access_token=access_token,
                token_type="Bearer",
                expires_in=3600,
                scope=auth_code.scope,
                resource=auth_code.resource,
                refresh_token=refresh_token,
            ),
            None,
        )

    async def _handle_refresh_token_grant(
        self, request: TokenRequest
    ) -> Tuple[Optional[TokenResponse], Optional[ErrorResponse]]:
        """Handle refresh token grant."""
        # Authenticate client
        if not request.client_secret:
            return None, ErrorResponse("invalid_client", "Client secret required")

        client = await self.client_registry.authenticate_client(
            request.client_id, request.client_secret
        )
        if not client:
            logger.warning("Client authentication failed for refresh token request")
            return None, ErrorResponse("invalid_client", "Client authentication failed")

        # Validate refresh token
        if not request.refresh_token:
            return None, ErrorResponse("invalid_request", "Refresh token required")

        refresh_token = await self.token_manager.validate_refresh_token(
            request.refresh_token
        )
        if not refresh_token:
            return None, ErrorResponse("invalid_grant", "Invalid refresh token")

        if refresh_token.client_id != request.client_id:
            return None, ErrorResponse("invalid_grant", "Refresh token client mismatch")

        # Get user info for token creation
        user_info = await self.get_user_info(refresh_token.user_id)

        # Create new access token
        access_token = await self.token_manager.create_access_token(
            client_id=refresh_token.client_id,
            user_id=refresh_token.user_id,
            scope=refresh_token.scope,
            resource=request.resource,
            user_info=user_info,
        )

        # Optionally rotate refresh token (recommended for public clients)
        new_refresh_token = request.refresh_token
        if client.token_endpoint_auth_method == "none":  # Public client
            new_refresh_token = await self.token_manager.create_refresh_token(
                client_id=refresh_token.client_id,
                user_id=refresh_token.user_id,
                scope=refresh_token.scope,
            )
            # Revoke old refresh token
            await self.token_manager.revoke_refresh_token(request.refresh_token)

        return (
            TokenResponse(
                access_token=access_token,
                token_type="Bearer",
                expires_in=3600,
                scope=refresh_token.scope,
                resource=request.resource,
                refresh_token=(
                    new_refresh_token
                    if new_refresh_token != request.refresh_token
                    else None
                ),
            ),
            None,
        )

    async def handle_client_registration(
        self, request: ClientRegistrationRequest
    ) -> Tuple[Optional[dict], Optional[ErrorResponse]]:
        """Handle client registration request."""
        try:
            client = await self.client_registry.register_client(request)

            return {
                "client_id": client.client_id,
                "client_secret": client.client_secret,
                "client_name": client.client_name,
                "redirect_uris": client.redirect_uris,
                "grant_types": client.grant_types,
                "response_types": client.response_types,
                "token_endpoint_auth_method": client.token_endpoint_auth_method,
                "scope": client.scope,
                "client_id_issued_at": int(client.created_at),
                "client_secret_expires_at": int(client.expires_at),
            }, None

        except ValueError as e:
            return None, ErrorResponse("invalid_request", str(e))
        except Exception as e:
            return None, ErrorResponse("server_error", str(e))

    async def create_authorization_code(
        self, user_id: str, oauth_state: OAuthState
    ) -> str:
        """Create authorization code after user authentication."""
        code = secrets.token_urlsafe(32)

        auth_code = AuthorizationCode(
            code=code,
            client_id=oauth_state.client_id,
            user_id=user_id,
            redirect_uri=oauth_state.redirect_uri,
            scope=oauth_state.scope,
            resource=oauth_state.resource,
            code_challenge=oauth_state.code_challenge,
            code_challenge_method=oauth_state.code_challenge_method,
        )

        await self.session_storage.set(
            f"auth_code:{code}", asdict(auth_code), ttl=600
        )  # 10 minutes

        return code

    async def get_oauth_state(self, state: str) -> Optional[OAuthState]:
        """Get OAuth state."""
        oauth_state_data = await self.session_storage.get(f"oauth_state:{state}")
        if not oauth_state_data:
            return None

        oauth_state = OAuthState(**oauth_state_data)
        if oauth_state.is_expired():
            await self.session_storage.delete(f"oauth_state:{state}")
            return None
        return oauth_state

    async def store_user_session(self, user_id: str, user_info: UserInfo) -> None:
        """Store user session."""
        await self.session_storage.set(
            f"user_session:{user_id}", asdict(user_info), ttl=3600
        )  # 1 hour

    async def get_user_info(self, user_id: str) -> Optional[UserInfo]:
        """Get user info by ID."""
        user_data = await self.session_storage.get(f"user_session:{user_id}")
        if not user_data:
            return None
        return UserInfo(**user_data)

    async def validate_access_token(
        self, token: str, resource: Optional[str] = None
    ) -> Optional[dict]:
        """Validate access token."""
        return await self.token_manager.validate_access_token(token, resource)

    def _generate_state(self) -> str:
        """Generate state parameter."""
        return secrets.token_urlsafe(32)

    def _verify_pkce(self, code_verifier: str, code_challenge: str) -> bool:
        """Verify PKCE code challenge."""
        # Generate challenge from verifier
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )

        return challenge == code_challenge

    async def cleanup_expired_data(self) -> None:
        """Clean up expired data."""
        # The storage backends handle TTL automatically,
        # but we can still trigger token cleanup
        await self.token_manager.cleanup_expired_tokens()
