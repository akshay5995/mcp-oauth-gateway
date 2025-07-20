"""Dynamic Client Registration (RFC 7591) implementation."""

import secrets
import time
from dataclasses import asdict
from typing import Optional

from ..storage.base import ClientStorage
from .models import ClientInfo, ClientRegistrationRequest


class ClientRegistry:
    """Manages OAuth client registration and storage."""

    def __init__(self, client_storage: ClientStorage):
        self.client_storage = client_storage

    async def register_client(self, request: ClientRegistrationRequest) -> ClientInfo:
        """Register a new OAuth client per RFC 7591."""
        # Validate request
        self._validate_registration_request(request)

        # Check if a client with the same redirect URIs already exists (deduplication)
        # This helps with MCP clients that may register multiple times
        existing_client_data = await self.client_storage.find_client_by_redirect_uris(
            request.redirect_uris
        )
        if (
            existing_client_data
            and existing_client_data.get("client_name") == request.client_name
        ):
            return ClientInfo(**existing_client_data)

        # Generate client credentials
        client_id = self._generate_client_id()
        client_secret = self._generate_client_secret()

        # Create client info
        client = ClientInfo(
            client_id=client_id,
            client_secret=client_secret,
            client_name=request.client_name,
            redirect_uris=request.redirect_uris,
            grant_types=request.grant_types,
            response_types=request.response_types,
            token_endpoint_auth_method=request.token_endpoint_auth_method,
            scope=request.scope,
        )

        # Store client
        await self.client_storage.store_client(client_id, asdict(client))

        return client

    async def get_client(self, client_id: str) -> Optional[ClientInfo]:
        """Get client by ID."""
        client_data = await self.client_storage.get_client(client_id)
        if not client_data:
            return None
        return ClientInfo(**client_data)

    async def authenticate_client(
        self, client_id: str, client_secret: str
    ) -> Optional[ClientInfo]:
        """Authenticate client credentials."""
        client = await self.get_client(client_id)
        if not client:
            return None

        if client.client_secret != client_secret:
            return None

        # Check if client is expired
        if client.expires_at > 0 and time.time() > client.expires_at:
            return None

        return client

    async def validate_redirect_uri(self, client_id: str, redirect_uri: str) -> bool:
        """Validate redirect URI for client."""
        client = await self.get_client(client_id)
        if not client:
            return False

        return redirect_uri in client.redirect_uris

    async def validate_grant_type(self, client_id: str, grant_type: str) -> bool:
        """Validate grant type for client."""
        client = await self.get_client(client_id)
        if not client:
            return False

        return grant_type in client.grant_types

    async def validate_response_type(self, client_id: str, response_type: str) -> bool:
        """Validate response type for client."""
        client = await self.get_client(client_id)
        if not client:
            return False

        return response_type in client.response_types

    def _generate_client_id(self) -> str:
        """Generate unique client ID."""
        return f"mcp_client_{secrets.token_urlsafe(16)}"

    def _generate_client_secret(self) -> str:
        """Generate client secret."""
        return secrets.token_urlsafe(32)

    def _validate_registration_request(
        self, request: ClientRegistrationRequest
    ) -> None:
        """Validate client registration request."""
        if not request.client_name:
            raise ValueError("client_name is required")

        if not request.redirect_uris:
            raise ValueError("redirect_uris is required")

        # Validate redirect URIs
        for uri in request.redirect_uris:
            if not self._is_valid_redirect_uri(uri):
                raise ValueError(f"Invalid redirect URI: {uri}")

        # Validate grant types
        valid_grant_types = [
            "authorization_code",
            "client_credentials",
            "refresh_token",
        ]
        for grant_type in request.grant_types:
            if grant_type not in valid_grant_types:
                raise ValueError(f"Unsupported grant type: {grant_type}")

        # Validate response types
        valid_response_types = ["code"]
        for response_type in request.response_types:
            if response_type not in valid_response_types:
                raise ValueError(f"Unsupported response type: {response_type}")

        # Validate auth method
        valid_auth_methods = ["client_secret_basic", "client_secret_post", "none"]
        if request.token_endpoint_auth_method not in valid_auth_methods:
            raise ValueError(
                f"Unsupported auth method: {request.token_endpoint_auth_method}"
            )

    def _is_valid_redirect_uri(self, uri: str) -> bool:
        """Validate redirect URI format."""
        if not uri:
            return False

        # Allow localhost for development (HTTP)
        if uri.startswith("http://localhost:") or uri.startswith("http://127.0.0.1:"):
            # No fragments allowed
            if "#" in uri:
                return False
            # Must have more than just the protocol and host
            if uri in ["http://localhost:", "http://127.0.0.1:"]:
                return False
            return True

        # Allow HTTPS URLs
        if uri.startswith("https://"):
            # Basic validation - no fragments allowed
            if "#" in uri:
                return False
            return True

        # Allow custom schemes for native apps (e.g., cursor://, vscode://, etc.)
        # This is common for desktop applications and IDE integrations
        if "://" in uri:
            parts = uri.split("://", 1)
            if len(parts) != 2:
                return False
            scheme, rest = parts

            # Reject well-known protocols that should not be used for OAuth redirects
            forbidden_schemes = {
                "ftp",
                "file",
                "data",
                "javascript",
                "mailto",
                "tel",
                "sms",
            }
            if scheme.lower() in forbidden_schemes:
                return False

            # Scheme must not be empty and must be alphanumeric (with allowed chars)
            if not scheme or not scheme.replace("-", "").replace(".", "").isalnum():
                return False
            # Must have content after the scheme
            if not rest:
                return False
            # No fragments allowed
            if "#" in uri:
                return False
            return True

        return False
