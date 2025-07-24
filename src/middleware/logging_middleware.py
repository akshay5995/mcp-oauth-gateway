"""Custom logging middleware for MCP OAuth Gateway."""

import logging
import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class CustomLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for logging requests with sensitive data filtering.

    This middleware:
    - Skips logging for health check endpoints
    - Protects sensitive OAuth data in production mode
    - Shows full OAuth URLs in debug mode for development
    - Logs MCP proxy requests with service identification
    - Tracks request duration for all endpoints
    """

    def __init__(self, app, debug: bool = False):
        """Initialize the logging middleware.

        Args:
            app: The FastAPI/Starlette application
            debug: Whether to run in debug mode (shows sensitive data)
        """
        super().__init__(app)
        self.debug = debug

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process and log the request.

        Args:
            request: The incoming HTTP request
            call_next: The next middleware or endpoint handler

        Returns:
            The HTTP response
        """
        start_time = time.time()

        # Skip logging for health checks
        if request.url.path == "/health":
            return await call_next(request)

        # Capture request info
        method = request.method
        path = request.url.path

        # Process the request
        response = await call_next(request)

        # Calculate duration
        duration = time.time() - start_time

        # Determine if this is an OAuth-related endpoint
        is_oauth = path.startswith("/oauth/") or path.startswith("/.well-known/oauth")

        # Log based on endpoint type and debug mode
        if is_oauth:
            if self.debug:
                # Debug mode - include query string for OAuth endpoints
                full_path = str(request.url).replace(
                    str(request.base_url).rstrip("/"), ""
                )
                logger.debug(
                    f"{method} {full_path} - {response.status_code} ({duration:.3f}s)"
                )
            else:
                # Production - log without sensitive query params or body data
                logger.info(
                    f"{method} {path} - {response.status_code} ({duration:.3f}s)"
                )
        elif path.endswith("/mcp"):
            # MCP proxy request - include service ID
            service_id = path.split("/")[1] if len(path.split("/")) > 1 else "unknown"
            logger.info(
                f"{method} /{service_id}/mcp - {response.status_code} ({duration:.3f}s)"
            )
        else:
            # Other endpoints - log normally
            logger.info(f"{method} {path} - {response.status_code} ({duration:.3f}s)")

        return response
