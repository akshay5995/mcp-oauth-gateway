"""Main MCP OAuth Gateway application."""

import logging
from contextlib import asynccontextmanager
from typing import Optional
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .api.metadata import MetadataProvider
from .auth.models import AuthorizeRequest, ClientRegistrationRequest, TokenRequest
from .auth.oauth_server import OAuthServer
from .auth.provider_manager import ProviderManager
from .config.config import ConfigManager
from .proxy.mcp_proxy import McpProxy

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security scheme
security = HTTPBearer(auto_error=False)


class McpGateway:
    """MCP OAuth Gateway - Transparent OAuth proxy for MCP services."""

    def __init__(self, config_path: Optional[str] = None):
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.load_config()

        # Validate configuration before initializing components
        self._validate_configuration()

        # Initialize core components
        self.oauth_server = OAuthServer(
            secret_key=self.config.session_secret, issuer=self.config.issuer
        )

        self.provider_manager = ProviderManager(self.config.oauth_providers)
        self.metadata_provider = MetadataProvider(self.config)
        self.mcp_proxy = McpProxy()

        # Create FastAPI app
        @asynccontextmanager
        async def lifespan(app: FastAPI):
            # Startup
            await self.mcp_proxy.start()
            logger.info(
                f"MCP OAuth Gateway started on {self.config.host}:{self.config.port}"
            )
            yield
            # Shutdown
            await self.mcp_proxy.stop()
            logger.info("MCP OAuth Gateway stopped")

        self.app = FastAPI(
            title="MCP OAuth Gateway",
            description="OAuth 2.1 Authorization Server for Model Context Protocol services",
            version="1.0.0",
            openapi_url="/openapi.json",
            docs_url="/docs" if self.config.debug else None,
            redoc_url="/redoc" if self.config.debug else None,
            lifespan=lifespan,
        )

        self._setup_middleware()
        self._setup_routes()

    def _validate_configuration(self):
        """Validate gateway configuration and log warnings for potential issues."""
        validation_issues = []
        warnings = []

        # Check if OAuth providers are needed
        auth_required_services = [
            service_id for service_id, service in self.config.mcp_services.items()
            if service.auth_required
        ]
        
        if not self.config.oauth_providers and auth_required_services:
            validation_issues.append(
                f"Services {auth_required_services} require authentication but no OAuth providers are configured"
            )
        elif not self.config.oauth_providers:
            logger.info("No OAuth providers configured - gateway will only serve public services")

        # Check service-provider mapping for authenticated services
        available_providers = set(self.config.oauth_providers.keys())
        for service_id, service in self.config.mcp_services.items():
            if service.auth_required and service.oauth_provider:
                if service.oauth_provider not in available_providers:
                    validation_issues.append(
                        f"Service '{service_id}' references non-existent provider '{service.oauth_provider}'"
                    )

        # Log validation results
        if validation_issues:
            for issue in validation_issues:
                logger.error(f"Configuration error: {issue}")
            raise ValueError(f"Invalid configuration: {'; '.join(validation_issues)}")

        if warnings:
            for warning in warnings:
                logger.warning(f"Configuration warning: {warning}")
            logger.info(f"Available providers: {list(available_providers)}")
        else:
            logger.info(
                f"Configuration validation passed - {len(available_providers)} providers, {len(self.config.mcp_services)} services"
            )

    def _setup_middleware(self):
        """Setup FastAPI middleware."""
        # CORS middleware - configured from config
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=self.config.cors.allow_origins,
            allow_credentials=self.config.cors.allow_credentials,
            allow_methods=self.config.cors.allow_methods,
            allow_headers=self.config.cors.allow_headers,
        )

    def _setup_routes(self):
        """Setup application routes."""

        # Root endpoint
        @self.app.get("/")
        async def root():
            """Gateway information."""
            return {
                "name": "MCP OAuth Gateway",
                "version": "1.0.0",
                "issuer": self.config.issuer,
                "services": len(self.config.mcp_services),
            }

        # Health check
        @self.app.get("/health")
        async def health():
            """Health check endpoint."""
            return {"status": "healthy"}

        # OAuth 2.1 Metadata endpoints
        @self.app.get("/.well-known/oauth-authorization-server")
        async def authorization_server_metadata():
            """OAuth 2.0 Authorization Server Metadata (RFC 8414)."""
            return self.metadata_provider.get_authorization_server_metadata()

        @self.app.get("/.well-known/oauth-protected-resource")
        async def protected_resource_metadata():
            """OAuth 2.0 Protected Resource Metadata (RFC 9728)."""
            return self.metadata_provider.get_protected_resource_metadata()

        # OAuth 2.1 Endpoints
        @self.app.get("/oauth/authorize")
        async def authorize(
            response_type: str = Query(...),
            client_id: str = Query(...),
            redirect_uri: str = Query(...),
            scope: str = Query(None),
            state: str = Query(None),
            code_challenge: str = Query(None),
            code_challenge_method: str = Query(None),
            resource: str = Query(None),
        ):
            """OAuth 2.1 authorization endpoint."""
            request = AuthorizeRequest(
                response_type=response_type,
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                state=state,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                resource=resource,
            )

            # Handle authorization request
            logger.info("Processing authorization request")
            oauth_state, error = await self.oauth_server.handle_authorize(request)

            if error:
                # Redirect to client with error
                error_params = {
                    "error": error.error,
                    "error_description": error.error_description,
                    "state": state,
                }
                return RedirectResponse(
                    url=f"{redirect_uri}?{urlencode(error_params)}", status_code=302
                )

            # Determine which OAuth provider to use (with resilient fallback)
            try:
                provider_id = self._determine_provider_for_resource(resource)
            except ValueError as e:
                # No providers configured at all
                error_params = {
                    "error": "server_error",
                    "error_description": str(e),
                    "state": state,
                }
                return RedirectResponse(
                    url=f"{redirect_uri}?{urlencode(error_params)}", status_code=302
                )

            # Get provider (should always exist now due to resilient logic)
            provider = self.provider_manager.get_provider(provider_id)
            if not provider:
                # This should not happen with resilient logic, but just in case
                logger.error(
                    f"Resilient provider determination returned non-existent provider: {provider_id}"
                )
                available_providers = list(self.config.oauth_providers.keys())
                if available_providers:
                    provider_id = available_providers[0]
                    provider = self.provider_manager.get_provider(provider_id)
                    logger.warning(f"Emergency fallback to provider: {provider_id}")

                if not provider:
                    error_params = {
                        "error": "server_error",
                        "error_description": "No OAuth providers available",
                        "state": state,
                    }
                    return RedirectResponse(
                        url=f"{redirect_uri}?{urlencode(error_params)}", status_code=302
                    )

            # Store OAuth state with provider info
            oauth_state_obj = self.oauth_server.get_oauth_state(oauth_state)
            if oauth_state_obj:
                oauth_state_obj.provider = provider_id

            # Generate callback state
            callback_state = self.provider_manager.generate_callback_state(
                provider_id, oauth_state
            )

            # Build provider callback URI
            callback_uri = f"{self.config.issuer}/oauth/callback"

            # Get provider authorization URL
            provider_auth_url = provider.get_authorization_url(
                callback_state, callback_uri
            )

            return RedirectResponse(url=provider_auth_url, status_code=302)

        @self.app.get("/oauth/callback")
        async def oauth_callback(
            code: str = Query(None), state: str = Query(None), error: str = Query(None)
        ):
            """OAuth provider callback handler."""
            if error:
                return HTTPException(
                    status_code=400, detail=f"OAuth provider error: {error}"
                )

            if not code or not state:
                raise HTTPException(
                    status_code=400, detail="Missing code or state parameter"
                )

            try:
                # Parse callback state
                provider_id, oauth_state = self.provider_manager.parse_callback_state(
                    state
                )

                # Get OAuth state
                oauth_state_obj = self.oauth_server.get_oauth_state(oauth_state)
                if not oauth_state_obj:
                    logger.warning(
                        f"OAuth state mismatch for state '{oauth_state}' - possible CSRF attack"
                    )
                    raise HTTPException(
                        status_code=400,
                        detail="OAuth state mismatch - possible CSRF attack",
                    )

                # Handle provider callback
                callback_uri = f"{self.config.issuer}/oauth/callback"
                user_info = await self.provider_manager.handle_provider_callback(
                    provider_id, code, callback_uri
                )

                # Store user session
                user_id = f"{provider_id}:{user_info.id}"
                self.oauth_server.store_user_session(user_id, user_info)

                # Create authorization code
                resource_value = (
                    oauth_state_obj.resource
                    if hasattr(oauth_state_obj, "resource")
                    else "None"
                )
                logger.info(
                    f"Creating authorization code for user '{user_id}' with resource '{resource_value}'"
                )
                auth_code = self.oauth_server.create_authorization_code(
                    user_id, oauth_state_obj
                )

                # Redirect back to client
                callback_params = {
                    "code": auth_code,
                    "state": (
                        oauth_state_obj.client_state
                        if hasattr(oauth_state_obj, "client_state")
                        and oauth_state_obj.client_state
                        else None
                    ),
                }

                # Filter out None values
                callback_params = {
                    k: v for k, v in callback_params.items() if v is not None
                }

                return RedirectResponse(
                    url=f"{oauth_state_obj.redirect_uri}?{urlencode(callback_params)}",
                    status_code=302,
                )

            except Exception as e:
                logger.error(f"OAuth callback error: {str(e)}")
                raise HTTPException(
                    status_code=400, detail=f"OAuth callback failed: {str(e)}"
                ) from e

        @self.app.post("/oauth/token")
        async def token(
            grant_type: str = Form(...),
            client_id: str = Form(...),
            client_secret: str = Form(None),
            code: str = Form(None),
            redirect_uri: str = Form(None),
            code_verifier: str = Form(None),
            resource: str = Form(None),
            scope: str = Form(None),
            refresh_token: str = Form(None),
        ):
            """OAuth 2.1 token endpoint."""
            request = TokenRequest(
                grant_type=grant_type,
                client_id=client_id,
                client_secret=client_secret,
                code=code,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
                resource=resource,
                scope=scope,
                refresh_token=refresh_token,
            )

            logger.info(f"Token request: grant_type='{grant_type}'")
            token_response, error = await self.oauth_server.handle_token(request)

            if error:
                logger.error(
                    f"Token request failed: {error.error} - {error.error_description}"
                )
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": error.error,
                        "error_description": error.error_description,
                    },
                )

            logger.info("Token request successful")
            return token_response

        @self.app.post("/oauth/register")
        async def register_client(request: Request):
            """Dynamic Client Registration (RFC 7591)."""
            try:
                # Parse JSON body for DCR
                body = await request.json()

                registration_request = ClientRegistrationRequest(
                    client_name=body.get("client_name"),
                    redirect_uris=body.get("redirect_uris", []),
                    grant_types=body.get("grant_types", ["authorization_code"]),
                    response_types=body.get("response_types", ["code"]),
                    token_endpoint_auth_method=body.get(
                        "token_endpoint_auth_method", "client_secret_basic"
                    ),
                    scope=body.get("scope", ""),
                )

                client_info, error = await self.oauth_server.handle_client_registration(
                    registration_request
                )

                if error:
                    logger.error(
                        f"Client registration failed: {error.error} - {error.error_description}"
                    )
                    raise HTTPException(
                        status_code=400,
                        detail={
                            "error": error.error,
                            "error_description": error.error_description,
                        },
                    )

                logger.info("Client registered successfully")
                return client_info

            except Exception as e:
                logger.error(f"Client registration error: {str(e)}")
                raise HTTPException(
                    status_code=400,
                    detail={"error": "invalid_request", "error_description": str(e)},
                ) from e

        # Service discovery
        @self.app.get("/services")
        async def list_services():
            """List available MCP services."""
            services = {}
            for service_id, service in self.config.mcp_services.items():
                services[service_id] = {
                    "name": service.name,
                    "url": f"{self.config.issuer}/{service_id}/mcp",
                    "auth_required": service.auth_required,
                    "scopes": service.scopes,
                }
            return {"services": services}

        @self.app.get("/services/{service_id}")
        async def get_service_info(service_id: str):
            """Get specific service information."""
            service = self.config.mcp_services.get(service_id)
            if not service:
                raise HTTPException(status_code=404, detail="Service not found")

            return {
                "id": service_id,
                "name": service.name,
                "url": f"{self.config.issuer}/{service_id}/mcp",
                "auth_required": service.auth_required,
                "scopes": service.scopes,
                "oauth_provider": service.oauth_provider,
            }

        # MCP service proxy routes
        @self.app.api_route(
            "/{service_id}/mcp",
            methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        )
        @self.app.api_route(
            "/{service_id}/mcp/{path:path}",
            methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        )
        async def proxy_mcp_request(
            service_id: str,
            request: Request,
            path: str = "",
            credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
        ):
            """Proxy MCP requests to backend services."""
            # Get service configuration
            service = self.config.mcp_services.get(service_id)
            if not service:
                raise HTTPException(
                    status_code=404, detail=f"Service '{service_id}' not found"
                )

            user_info = None

            # Check authentication if required
            if service.auth_required:
                if not credentials or credentials.scheme.lower() != "bearer":
                    # Return 401 with WWW-Authenticate header per MCP spec
                    headers = {
                        "WWW-Authenticate": f'Bearer resource_metadata="{self.config.issuer}/.well-known/oauth-protected-resource"'
                    }
                    raise HTTPException(
                        status_code=401,
                        detail="Authentication required",
                        headers=headers,
                    )

                # Validate token - use gateway root as resource since that's what MCP clients send
                resource_uri = self.config.issuer.rstrip("/")
                logger.info(
                    f"Validating token for service '{service_id}': issuer='{self.config.issuer}', resource_uri='{resource_uri}'"
                )
                token_payload = self.oauth_server.validate_access_token(
                    credentials.credentials, resource=resource_uri
                )

                logger.info(
                    f"Token validation for service '{service_id}': payload={bool(token_payload)}, expected_resource='{resource_uri}'"
                )

                if not token_payload:
                    logger.warning(
                        f"Token validation failed for service '{service_id}' with resource '{resource_uri}'"
                    )
                    headers = {
                        "WWW-Authenticate": f'Bearer resource_metadata="{self.config.issuer}/.well-known/oauth-protected-resource"'
                    }
                    raise HTTPException(
                        status_code=401,
                        detail="Invalid or expired token",
                        headers=headers,
                    )

                # Get user info from token payload
                user_id = token_payload.get("sub")

                # Create UserInfo from token payload
                if user_id:
                    from .auth.models import UserInfo

                    user_info = UserInfo(
                        id=(
                            user_id.split(":")[-1] if ":" in user_id else user_id
                        ),  # Extract actual user ID
                        email=token_payload.get("email", ""),
                        name=token_payload.get("name", ""),
                        avatar_url=token_payload.get("avatar_url", ""),
                        provider=token_payload.get(
                            "provider",
                            user_id.split(":")[0] if ":" in user_id else "unknown",
                        ),
                    )
                else:
                    user_info = None

            # Proxy request to backend service
            return await self.mcp_proxy.forward_request(service, request, user_info)

    def _determine_provider_for_resource(self, resource: Optional[str] = None) -> str:
        """Determine which OAuth provider to use.
        
        Since only one provider is configured, always returns that provider.
        The resource parameter is accepted for OAuth 2.1 compliance but all
        requests use the same configured provider.
        """
        available_providers = list(self.config.oauth_providers.keys())

        if not available_providers:
            # No providers configured - this is a configuration error
            logger.error("No OAuth providers configured in gateway")
            raise ValueError("No OAuth providers configured")
        
        # With single provider constraint, always return the configured provider
        configured_provider = available_providers[0]
        logger.debug(f"Using configured OAuth provider: {configured_provider}")
        return configured_provider

    def get_app(self) -> FastAPI:
        """Get the FastAPI application."""
        return self.app


def create_app(config_path: Optional[str] = None) -> FastAPI:
    """Create and configure the gateway application."""
    gateway = McpGateway(config_path)
    return gateway.get_app()


# Default app instance for uvicorn
# This will be recreated when config changes in reload mode
app = create_app()


if __name__ == "__main__":
    import argparse

    import uvicorn

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="MCP OAuth Gateway")
    parser.add_argument("--config", "-c", type=str, help="Path to configuration file")
    parser.add_argument("--host", type=str, help="Host to bind to")
    parser.add_argument("--port", type=int, help="Port to bind to")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    # Create the application
    app = create_app(args.config)

    # Get config for host/port
    config_manager = ConfigManager(args.config)
    config = config_manager.get_config()

    host = args.host or config.host
    port = args.port or config.port
    debug = args.debug or config.debug

    # Run with uvicorn
    if debug:
        # Use import string for reload mode
        uvicorn.run(
            "src.gateway:app", host=host, port=port, log_level="debug", reload=True
        )
    else:
        # Use app instance for production
        uvicorn.run(app, host=host, port=port, log_level="info")
