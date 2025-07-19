# CLAUDE.md

This file provides guidance to Claude Code when working with the MCP OAuth Gateway codebase.

## Project Overview

The **MCP OAuth Gateway** is a work-in-progress OAuth 2.1 authorization server that provides transparent authentication and authorization for Model Context Protocol (MCP) services. It acts as a secure proxy that handles all OAuth complexity, allowing users to simply access `https://gateway.example.com/<service-id>/mcp` and have authentication handled automatically.

## Codebase Structure

### Directory Layout
```
src/
├── gateway.py               # Main FastAPI application and CLI entry point
├── auth/                    # OAuth 2.1 authentication system
│   ├── models.py           # Pydantic models for OAuth entities
│   ├── oauth_server.py     # Core OAuth 2.1 server implementation
│   ├── provider_manager.py # External OAuth provider integration
│   ├── client_registry.py  # Dynamic Client Registration (RFC 7591)
│   └── token_manager.py    # JWT token creation/validation
├── config/
│   └── config.py           # YAML configuration management
├── proxy/
│   └── mcp_proxy.py        # HTTP proxy with user context injection
└── api/
    └── metadata.py         # OAuth metadata endpoints
```

### Key Dependencies
- **FastAPI** (≥0.104.1) - Web framework and OpenAPI
- **Uvicorn** - ASGI server
- **python-jose** - JWT token handling with cryptography support
- **httpx** (≥0.25.2) - HTTP client for proxying requests
- **Pydantic** (≥2.5.0) - Data validation and serialization
- **PyYAML** - Configuration file parsing
- **Cryptography** (≥45.0.0) - Security primitives
- **pytest** (≥7.0.0) - Testing framework with async support
- **pytest-asyncio** (≥0.23.0) - Async test support
- **pytest-httpx** (≥0.21.0) - HTTP client mocking for tests

## Core Components

### 1. Main Application (`gateway.py`)
- FastAPI app with OAuth 2.1 and MCP service endpoints
- Command-line interface with config file support
- Health checks and service discovery endpoints
- CORS middleware and security headers
- Lifespan management for async resources

**Key functions:**
- `McpGateway` class - Main gateway orchestrator with all OAuth and MCP functionality
- `create_app(config: Config) -> FastAPI` - Application factory
- `main()` - CLI entry point with argument parsing
- `_determine_provider_for_resource()` - Single provider constraint enforcement

### 2. OAuth Authentication System (`auth/`)

#### Models (`models.py`)
Complete Pydantic models for OAuth 2.1 entities:
- `UserInfo` - User profile from OAuth providers
- `ClientInfo` - OAuth client registration data
- `AuthorizationCode` - PKCE-enabled authorization codes
- `AccessToken` - JWT tokens with audience binding
- Request/response models for all OAuth endpoints

#### OAuth Server (`oauth_server.py`)
Core OAuth 2.1 authorization server implementation:
- **Authorization endpoint** with PKCE and resource parameter support
- **Token endpoint** for authorization code exchange
- **State management** for OAuth flows with in-memory storage
- **User session handling** with secure session secrets

**Key methods:**
- `handle_authorize()` - Authorization endpoint with PKCE and resource parameter support
- `handle_token()` - Token endpoint supporting authorization_code and refresh_token grants
- `handle_client_registration()` - Dynamic Client Registration per RFC 7591
- `generate_authorization_code()` - Create PKCE-enabled codes with expiration
- `validate_pkce()` - PKCE code challenge verification

#### Provider Manager (`provider_manager.py`)
Single OAuth provider integration:
- **Domain-wide authentication** using one configured OAuth provider
- **Google OAuth** with OpenID Connect support
- **GitHub OAuth** with user email scope
- **Custom OAuth providers** with configurable endpoints
- **Note**: Due to OAuth 2.1 resource parameter constraints, only one provider can be configured per gateway instance

**Key classes and methods:**
- `OAuthProvider` - Base provider class with common interface
- `GoogleOAuthProvider`, `GitHubOAuthProvider`, `OktaOAuthProvider`, `CustomOAuthProvider` - Provider implementations
- `ProviderManager` - Single provider management with validation
- `authenticate_user(provider: str, code: str)` - Exchange code for user info
- `get_provider_for_service(service_id: str)` - Returns the configured provider

#### Token Manager (`token_manager.py`)
JWT token creation and validation:
- **Service-specific audience claims** per RFC 8707
- **Configurable token expiration** (default 1 hour)
- **Resource binding** to prevent token misuse
- **HS256 signing** with shared secret

**Key methods:**
- `create_access_token(user: UserInfo, client_id: str, resource: str)` - Generate JWT with audience binding
- `create_refresh_token(user: UserInfo, client_id: str)` - Secure refresh token generation
- `validate_access_token(token: str, resource: str)` - Verify and decode JWT with audience validation
- `revoke_tokens()` - Token revocation support for client and token-specific scenarios

#### Client Registry (`client_registry.py`)
Dynamic Client Registration per RFC 7591:
- **Automatic client registration** for MCP clients
- **Client credential generation** with secure random secrets
- **Redirect URI validation** for security
- **Comprehensive validation** - Grant types, auth methods, response types
- **Deduplication support** - Prevents duplicate registrations for same client
- **In-memory client storage** (suitable for development)

### 3. Configuration (`config/config.py`)
YAML-based configuration management:
- **Environment variable substitution** (${VAR_NAME} syntax)
- **OAuth provider configuration** with credentials and scopes
- **MCP service definitions** with auth requirements
- **Gateway settings** (host, port, issuer, session secret)

**Configuration structure:**
```yaml
host: "0.0.0.0"
port: 8080
issuer: "http://localhost:8080"
session_secret: "your-secret-key"

# Single OAuth provider configuration
# Only one provider can be configured per gateway instance
oauth_providers:
  google:  # Configure only one provider
    client_id: "${GOOGLE_CLIENT_ID}"
    client_secret: "${GOOGLE_CLIENT_SECRET}"
    scopes: ["openid", "email", "profile"]

mcp_services:
  calculator:
    name: "Calculator Service"
    url: "http://localhost:3001/mcp/"
    oauth_provider: "google"  # Must match the configured provider
    auth_required: true
    scopes: ["read", "calculate"]
```

### 4. MCP Proxy (`proxy/mcp_proxy.py`)
HTTP request forwarding with user context injection:
- **Transparent proxying** to backend MCP services
- **User context headers** (`x-user-id`, `x-user-email`, etc.)
- **Streamable HTTP support** for MCP protocol
- **Timeout handling** and error propagation

**Key features:**
- Preserves original request method and body
- Adds user context from validated JWT tokens
- Handles both JSON-RPC and streaming responses
- Configurable timeouts per service

### 5. API Endpoints (`api/metadata.py`)
OAuth metadata endpoints per RFCs:
- **Authorization Server Metadata** (RFC 8414) at `/.well-known/oauth-authorization-server`
- **Protected Resource Metadata** (RFC 9728) at `/.well-known/oauth-protected-resource`
- **Service discovery** endpoints for MCP services

## Development Guidelines

### Configuring OAuth Provider

**Important**: Due to OAuth 2.1 resource parameter constraints, only one OAuth provider can be configured per gateway instance.

1. **Configure single provider** in `config.yaml`:
```yaml
oauth_providers:
  # Choose ONE provider only
  google:  # OR github, okta, custom - but only one
    client_id: "${GOOGLE_CLIENT_ID}"
    client_secret: "${GOOGLE_CLIENT_SECRET}"
    scopes: ["openid", "email", "profile"]
  
  # For custom providers:
  # custom:
  #   authorization_url: "https://provider.com/oauth/authorize"
  #   token_url: "https://provider.com/oauth/token"
  #   userinfo_url: "https://provider.com/oauth/userinfo"
  #   client_id: "${CUSTOM_CLIENT_ID}"
  #   client_secret: "${CUSTOM_CLIENT_SECRET}"
  #   scopes: ["read", "profile"]
```

2. **Update all MCP services** to use the same provider:
```yaml
mcp_services:
  service1:
    oauth_provider: "google"  # Must match configured provider
  service2:
    oauth_provider: "google"  # All services use same provider
```

3. **Test the provider** with your MCP services

### Adding New MCP Services

1. **Configure the service** in `config.yaml`:
```yaml
mcp_services:
  new_service:
    name: "New MCP Service"
    url: "http://backend:3001/mcp"
    oauth_provider: "google"  # Must match the configured OAuth provider
    auth_required: true
    scopes: ["read", "write"]
    timeout: 30000
```

2. **The service will be automatically available** at `/{service-id}/mcp`
3. **Backend services receive user context** via headers
4. **All services must use the same OAuth provider** configured in the gateway

### Code Style and Standards

- **Use Pydantic models** for all data validation
- **Follow FastAPI patterns** for dependency injection
- **Use async/await** for all I/O operations
- **Add type hints** to all functions
- **Use structured logging** with context
- **Format code** with Black and Ruff

### Testing

- **Unit test suite** - 15 test files covering individual components with mocking
- **OAuth 2.1 component testing** - PKCE validation, token exchange, metadata endpoints
- **Security boundary testing** - Token validation, redirect URI validation, error paths
- **Configuration validation testing** - Single provider constraints, service configuration
- **Component isolation testing** - Mocked HTTP requests, isolated functionality testing
- **pytest framework** with async support, HTTP client mocking, and component fixtures
- **Test utilities** - PKCE generation helpers and crypto validation tools

### Security Considerations

- **NEVER log sensitive data** (tokens, secrets, user data)
- **Validate all input** using Pydantic models
- **Use secure random generation** for codes and secrets
- **Implement proper CORS** for web clients
- **Enforce HTTPS** in production
- **Validate redirect URIs** strictly

### Production Deployment

- **Use environment variables** for all secrets
- **Configure proper logging** (JSON format recommended)
- **Set up health checks** for monitoring
- **Use HTTPS** with proper certificates
- **Configure reverse proxy** if needed
- **Monitor OAuth flow metrics**

## Common Development Tasks

### Running the Gateway
```bash
# Development with auto-reload
python -m src.gateway --config config.yaml --debug

# Production mode
python -m src.gateway --config config.yaml
```

### Code Quality
```bash
# Format and lint
ruff check src/ --fix
ruff format src/

# Run tests
pytest

# Type checking (if mypy is added)
mypy src/
```

### Docker Development
```bash
# Build image
docker build -t mcp-oauth-gateway .

# Run with config
docker run -p 8080:8080 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  mcp-oauth-gateway
```

## Architecture Notes

### OAuth 2.1 Compliance
- **PKCE required** for all authorization code flows
- **Resource parameter** for audience binding per RFC 8707
- **Dynamic Client Registration** per RFC 7591
- **Proper metadata endpoints** per RFC 8414 and RFC 9728

### MCP Protocol Support
- **Streamable HTTP transport** as specified in MCP
- **User context injection** for backend authorization
- **Transparent proxying** maintains MCP protocol semantics
- **Service-specific token scoping** prevents privilege escalation

### Security Architecture
- **Service isolation** through audience-bound tokens
- **Single provider design** ensures consistent authentication
- **Session management** with secure, signed sessions
- **State validation** prevents CSRF attacks

## Known Limitations

- **Single OAuth provider** per gateway instance due to OAuth 2.1 resource parameter constraints
- **In-memory storage** for sessions and clients (not suitable for multi-instance deployment)
- **Limited refresh token support** - Implemented but not exposed as public endpoint
- **No public token revocation endpoint** - Functionality exists but not exposed
- **Limited to HTTP transport** for MCP (WebSocket not supported)
- **No persistent user storage** (users re-authenticate each session)
- **No token introspection endpoint** - Functionality exists but not exposed

## Future Enhancements

- **Redis/database backend** for session storage
- **Public refresh token endpoint** exposure
- **Public token revocation endpoint** exposure  
- **Token introspection endpoint** exposure
- **WebSocket transport** for MCP services
- **User management interface** for administrators
- **Metrics and observability** integration
- **Rate limiting** for OAuth endpoints
- **Multi-instance deployment** support with shared storage