"""MCP request proxying with user context injection for Streamable HTTP transport."""

from typing import Dict, Optional

import httpx
from fastapi import Request, Response

from ..auth.models import UserInfo
from ..config.config import McpServiceConfig


class McpProxy:
    """Proxy MCP requests with user context injection for Streamable HTTP transport."""

    def __init__(self):
        self.client: Optional[httpx.AsyncClient] = None

    async def start(self):
        """Start the proxy client."""
        if not self.client:
            self.client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0), follow_redirects=False
            )

    async def stop(self):
        """Stop the proxy client."""
        if self.client:
            await self.client.aclose()
            self.client = None

    async def forward_request(
        self,
        service_config: McpServiceConfig,
        request: Request,
        user_info: Optional[UserInfo] = None,
    ) -> Response:
        """Forward MCP request to backend service with user context."""
        if not self.client:
            await self.start()

        # Extract request details
        method = request.method

        # For MCP Streamable HTTP transport, we proxy directly to the configured MCP endpoint
        # The service URL should already include the /mcp path
        target_url = service_config.url

        # Prepare headers for MCP Streamable HTTP transport
        headers = dict(request.headers)

        # Remove problematic headers
        headers_to_remove = [
            "host",
            "content-length",
            "connection",
            "upgrade",
            "proxy-connection",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "authorization",
        ]

        for header in headers_to_remove:
            headers.pop(header.lower(), None)
            headers.pop(header.title(), None)

        # Add MCP-specific headers
        headers["Accept"] = "application/json, text/event-stream"
        headers["Content-Type"] = "application/json"

        # Add protocol version header as per MCP spec
        headers["MCP-Protocol-Version"] = "2025-06-18"

        # Add user context headers
        if user_info:
            user_headers = self._build_user_context_headers(user_info)
            headers.update(user_headers)

        # Get request body
        body = await request.body()

        # Get query parameters
        query_params = dict(request.query_params)

        try:
            # Set service-specific timeout
            timeout = httpx.Timeout(
                service_config.timeout / 1000.0
            )  # Convert to seconds

            # Make request to backend
            if not self.client:
                raise RuntimeError("HTTP client not initialized")

            response = await self.client.request(
                method=method,
                url=target_url,
                headers=headers,
                content=body,
                params=query_params,
                timeout=timeout,
            )

            # Prepare response headers
            response_headers = dict(response.headers)

            # Remove problematic response headers
            response_headers_to_remove = [
                "content-length",
                "connection",
                "upgrade",
                "proxy-connection",
                "transfer-encoding",
            ]

            for header in response_headers_to_remove:
                response_headers.pop(header.lower(), None)
                response_headers.pop(header.title(), None)

            # Return response
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=response_headers,
                media_type=response_headers.get("content-type"),
            )

        except httpx.TimeoutException:
            return Response(
                content=f"Request to {service_config.name} timed out",
                status_code=504,
                media_type="text/plain",
            )
        except httpx.ConnectError:
            return Response(
                content=f"Cannot connect to {service_config.name} at {service_config.url}",
                status_code=502,
                media_type="text/plain",
            )
        except Exception as e:
            return Response(
                content=f"Proxy error: {str(e)}",
                status_code=500,
                media_type="text/plain",
            )

    async def check_service_health(self, service_config: McpServiceConfig) -> bool:
        """Check if service is healthy."""
        if not self.client:
            await self.start()

        try:
            if not self.client:
                return False
            await self.client.get(service_config.url, timeout=httpx.Timeout(5.0))
            return True
        except Exception:
            return False

    def _extract_service_id_from_path(self, path: str) -> str:
        """Extract service ID from request path."""
        parts = path.strip("/").split("/")
        return parts[0] if parts else ""

    def _build_target_url(self, base_url: str, path: str) -> str:
        """Build target URL for backend service."""
        # Ensure base_url doesn't end with slash and path starts with slash
        base_url = base_url.rstrip("/")
        if not path.startswith("/"):
            path = "/" + path

        return base_url + path

    def _build_user_context_headers(self, user_info: UserInfo) -> Dict[str, str]:
        """Build user context headers for backend service."""
        headers = {}

        if user_info.id:
            headers["x-user-id"] = user_info.id

        if user_info.email:
            headers["x-user-email"] = user_info.email

        if user_info.name:
            headers["x-user-name"] = user_info.name

        if user_info.provider:
            headers["x-user-provider"] = user_info.provider

        if user_info.avatar_url:
            headers["x-user-avatar"] = user_info.avatar_url

        return headers
