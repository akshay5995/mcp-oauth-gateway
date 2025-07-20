# CLAUDE.md

This file provides guidance to Claude Code when working with the MCP OAuth Gateway codebase.

📚 **Documentation Navigation**
- 🚀 **[README.md](README.md)** - Quick start guide and basic configuration
- 🏗️ **[ARCHITECTURE.md](ARCHITECTURE.md)** - System architecture and design
- 👩‍💻 **[CLAUDE.md](CLAUDE.md)** - Developer guide and implementation details (this document)

## Project Overview

The **MCP OAuth Gateway** is a work-in-progress OAuth 2.1 authorization server that provides transparent authentication and authorization for Model Context Protocol (MCP) services. It acts as a secure proxy that handles all OAuth complexity, allowing users to simply access `https://gateway.example.com/{service-id}/mcp` and have authentication handled automatically.

**Key Features:**
- **Transparent MCP Access**: Users access MCP services via simple URLs without manual OAuth setup
- **Single OAuth Provider**: Uses one OAuth provider for all services (Google, GitHub, Okta, or custom)
- **Full MCP Compliance**: Implements complete MCP authorization specification with OAuth 2.1
- **Dynamic Client Registration**: Automatic client registration per RFC 7591
- **User Context Injection**: Seamless user context headers for backend MCP services
- **Resource-Specific Tokens**: RFC 8707 audience binding prevents token misuse
- **Configurable Storage**: Memory (dev), Redis (production), Vault (enterprise) backends
- **Production Ready**: Comprehensive testing, Docker support, scalable architecture

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
├── storage/                 # Configurable storage backends
│   ├── __init__.py         # Storage module exports
│   ├── base.py             # Base storage interface and UnifiedStorage
│   ├── manager.py          # Storage factory and lifecycle management
│   ├── memory.py           # In-memory storage (default)
│   ├── redis.py            # Redis storage backend (production)
│   └── vault.py            # HashiCorp Vault storage (enterprise)
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
- Security middleware stack (Origin validation, MCP protocol validation)
- CORS middleware and security headers
- Lifespan management for async resources

**Key classes and functions:**
- `McpGateway` class - Main gateway orchestrator with all OAuth and MCP functionality
- `OriginValidationMiddleware` - DNS rebinding protection with localhost enforcement
- `MCPProtocolVersionMiddleware` - MCP protocol version validation and compatibility
- `create_app(config: Config) -> FastAPI` - Application factory
- `main()` - CLI entry point with argument parsing
- `_determine_provider_for_resource()` - Single provider constraint enforcement

**Security Middleware Stack:**
- **Origin Validation**: Protects against DNS rebinding attacks with configurable localhost enforcement
- **MCP Protocol Validation**: Validates MCP-Protocol-Version headers for protocol compliance
- **CORS Protection**: Standard CORS middleware with configurable policies

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
- **State management** for OAuth flows with configurable storage backends
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
- **Configurable storage backends** (memory, Redis, Vault) with automatic fallback

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

### 4. Storage Backends (`storage/`)
Production-ready configurable storage system with comprehensive backend support:
- **Multiple backend support** - Memory (default), Redis (production), Vault (enterprise)
- **Unified interface** - BaseStorage interface with UnifiedStorage implementation
- **Dependency injection** - Factory pattern with automatic fallback
- **Graceful degradation** - Automatic fallback to memory storage on failures
- **TTL support** - Time-to-live for all storage operations across backends
- **Health monitoring** - Comprehensive health checks and backend statistics
- **Production testing** - 85+ storage tests with behavior-focused validation

#### Base Storage Interface (`base.py`)
Defines the contract for all storage backends:
- **BaseStorage** - Abstract base class defining storage operations
- **UnifiedStorage** - Concrete implementation avoiding multiple inheritance
- **Consistent API** - Standardized methods across all storage backends
- **Type safety** - Full type hints for all storage operations

**Core interface methods:**
- `async start()` - Initialize storage backend and resources
- `async stop()` - Graceful shutdown and resource cleanup
- `async get(key: str) -> Optional[Dict[str, Any]]` - Retrieve data by key
- `async set(key: str, value: Dict[str, Any], ttl: Optional[int] = None)` - Store data with optional TTL
- `async delete(key: str) -> bool` - Remove data and return success status
- `async exists(key: str) -> bool` - Check if key exists
- `async keys(pattern: str = "*") -> List[str]` - List keys matching pattern
- `async clear()` - Remove all stored data
- `async health_check() -> bool` - Backend health validation
- `async get_stats() -> Dict[str, Any]` - Backend-specific statistics

#### Storage Manager (`manager.py`)
Factory pattern for creating and managing storage backends with production reliability:
- **Dependency injection** - Similar to OAuth provider configuration pattern
- **Automatic fallback** - Falls back to memory storage on initialization failures
- **Lifecycle management** - Complete startup/shutdown procedures with error handling
- **Health monitoring** - Continuous health checks and backend-specific statistics
- **Error resilience** - Graceful handling of storage backend failures

**Key methods:**
- `create_storage_backend() -> UnifiedStorage` - Factory method with fallback logic
- `start_storage() -> UnifiedStorage` - Initialize and start storage backend with fallback
- `stop_storage()` - Graceful shutdown of storage resources with error handling
- `health_check() -> bool` - Overall storage system health check
- `get_storage_info() -> dict` - Storage backend information and status

**Error handling and fallback:**
- Falls back to memory storage if Redis/Vault dependencies unavailable
- Falls back to memory storage if backend initialization fails
- Continues operation if backend stops responding after initialization
- Logs detailed error information for debugging

#### Memory Storage (`memory.py`)
High-performance in-memory storage backend using Python dictionaries:
- **Development-friendly** - No external dependencies, immediate startup
- **TTL implementation** - Background cleanup task for expired keys with asyncio
- **Statistics tracking** - Key counts, TTL monitoring, operation metrics
- **Thread-safe** - Async/await compatible with proper synchronization
- **Suitable for** - Development, testing, single-instance deployments

**Features:**
- Dictionary-based storage with O(1) key operations
- Automatic TTL cleanup with configurable cleanup intervals
- Memory usage statistics and key count monitoring
- Compatible with all OAuth data structures (codes, tokens, sessions)

#### Redis Storage (`redis.py`)
Production-ready Redis backend with enterprise features and Python 3.11+ compatibility:
- **Modern Redis library support** - Uses redis-py for Python 3.11+ (fixes TimeoutError conflict) with aioredis fallback
- **Connection resilience** - Automatic reconnection and error handling with dual library support
- **TTL support** - Native Redis expiration with automatic cleanup
- **Health checks** - Connection monitoring and Redis server statistics
- **Performance optimization** - Connection pooling and pipeline support with hiredis acceleration
- **Suitable for** - Production deployments, multi-instance scaling, high availability

**Production features:**
- Connection pooling with configurable limits (default: 20 connections)
- SSL/TLS support for secure connections
- Automatic JSON serialization/deserialization with error handling
- Redis-native TTL handling with SET EX commands
- Comprehensive error handling for network failures
- Redis INFO command integration for server statistics
- Support for Redis Cluster and Sentinel configurations

**Configuration options:**
```yaml
redis:
  host: "redis.example.com"
  port: 6379
  password: "${REDIS_PASSWORD}"
  ssl: true
  ssl_cert_reqs: "required"
  ssl_ca_certs: "/path/to/ca.pem"
  max_connections: 50
  socket_timeout: 5.0
  socket_connect_timeout: 5.0
  retry_on_timeout: true
  health_check_interval: 30
```

#### Vault Storage (`vault.py`)
Enterprise-grade HashiCorp Vault backend with security focus:
- **hvac integration** - Official Vault client library with async support
- **KV v2 engine** - Structured secret storage with versioning support
- **Token management** - Automatic token renewal and authentication
- **Security compliance** - Encrypted storage at rest with audit trails
- **Manual TTL** - Timestamp-based expiration handling for Vault KV store
- **Suitable for** - Enterprise environments, compliance requirements, sensitive data

**Enterprise security features:**
- Token-based authentication with automatic renewal background task
- Encrypted storage at rest with Vault's security model
- Audit logging capabilities through Vault's audit backend
- Path-based secret organization with configurable mount points
- Support for multiple authentication methods (token, AppRole, Kubernetes)
- Integration with Vault policies for fine-grained access control

**Authentication methods:**
```yaml
vault:
  # Token authentication (default)
  auth_method: "token"
  token: "${VAULT_TOKEN}"
  
  # AppRole authentication
  auth_method: "approle"
  role_id: "${VAULT_ROLE_ID}"
  secret_id: "${VAULT_SECRET_ID}"
  
  # Kubernetes authentication
  auth_method: "kubernetes"
  role: "mcp-gateway"
  jwt_path: "/var/run/secrets/kubernetes.io/serviceaccount/token"
```

**Vault configuration:**
```yaml
vault:
  url: "https://vault.example.com:8200"
  token: "${VAULT_TOKEN}"
  mount_point: "kv"  # KV v2 mount point
  path_prefix: "mcp-gateway/prod"  # Secret path prefix
  auth_method: "token"
  verify_ssl: true
  timeout: 10
  namespace: "prod"  # Vault Enterprise namespace
```

#### Storage Configuration
Flexible YAML-based storage configuration with environment variable support:

```yaml
# Storage backend selection
storage:
  type: "memory"  # Options: memory, redis, vault
  
  # Redis configuration (when type: redis)
  redis:
    host: "${REDIS_HOST:-localhost}"
    port: ${REDIS_PORT:-6379}
    password: "${REDIS_PASSWORD}"
    ssl: ${REDIS_SSL:-false}
    ssl_cert_reqs: "required"
    ssl_ca_certs: "${REDIS_CA_CERTS}"
    max_connections: ${REDIS_MAX_CONNECTIONS:-20}
    socket_timeout: 5.0
    socket_connect_timeout: 5.0
    retry_on_timeout: true
    health_check_interval: 30
    
  # Vault configuration (when type: vault)
  vault:
    url: "${VAULT_URL}"
    token: "${VAULT_TOKEN}"
    mount_point: "${VAULT_MOUNT_POINT:-secret}"
    path_prefix: "${VAULT_PATH_PREFIX:-mcp-gateway}"
    auth_method: "${VAULT_AUTH_METHOD:-token}"
    verify_ssl: ${VAULT_VERIFY_SSL:-true}
    timeout: ${VAULT_TIMEOUT:-10}
    namespace: "${VAULT_NAMESPACE}"  # Vault Enterprise
    
    # AppRole authentication
    role_id: "${VAULT_ROLE_ID}"
    secret_id: "${VAULT_SECRET_ID}"
    
    # Kubernetes authentication
    role: "${VAULT_K8S_ROLE}"
    jwt_path: "/var/run/secrets/kubernetes.io/serviceaccount/token"
```

#### Storage Testing
Comprehensive test suite with 85+ tests ensuring production reliability:
- **Behavior-focused testing** - Tests storage contracts rather than implementation details
- **Fake implementations** - Test doubles for Redis and Vault to avoid external dependencies
- **Error scenario testing** - Connection failures, timeout handling, backend unavailability
- **Concurrent operation testing** - Thread safety and async operation validation
- **TTL and expiration testing** - Time-based operations and cleanup validation
- **Configuration testing** - YAML validation and environment variable substitution
- **Integration testing** - End-to-end storage manager lifecycle testing

### 5. MCP Proxy (`proxy/mcp_proxy.py`)
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

### 6. API Endpoints (`api/metadata.py`)
OAuth metadata endpoints per RFCs:
- **Authorization Server Metadata** (RFC 8414) at `/.well-known/oauth-authorization-server`
- **Protected Resource Metadata** (RFC 9728) at `/.well-known/oauth-protected-resource`
- **Service discovery** endpoints for MCP services
- **Service-specific canonical URIs** per RFC 8707 for proper audience binding

**Key methods:**
- `get_service_canonical_uri(service_id: str)` - Generates canonical URI for service-specific tokens
- `get_all_service_canonical_uris()` - Returns mapping of all service canonical URIs
- `get_authorization_server_metadata()` - RFC 8414 compliant metadata
- `get_protected_resource_metadata(service_id)` - RFC 9728 compliant resource metadata

### 6. Security Middleware (`gateway.py`)
Comprehensive security middleware stack protecting against common web attacks:

#### Origin Validation Middleware
Protects against DNS rebinding attacks with environment-aware configuration:

**Features:**
- **DNS Rebinding Protection**: Validates Origin headers against allowed origins
- **Localhost Enforcement**: Development-friendly localhost access with production security
- **Environment Awareness**: Different security levels for debug vs production modes

**Configuration:**
```python
OriginValidationMiddleware(
    allowed_origins=["https://trusted.example.com", "https://app.company.com"],
    enforce_localhost=not config.debug  # True in production, False in development
)
```

**Security Behavior:**
- **Production Mode** (`debug=False`, `enforce_localhost=True`):
  - ✅ Allowed: Origins in explicit allow list
  - ✅ Allowed: Localhost origins (`http://localhost:*`, `https://127.0.0.1:*`)
  - ❌ Blocked: All other origins
- **Development Mode** (`debug=True`, `enforce_localhost=False`):
  - ✅ Allowed: Origins in explicit allow list
  - ✅ Allowed: Localhost origins
  - ✅ Allowed: Any other origin (permissive for development)

#### MCP Protocol Version Middleware
Validates MCP protocol compliance and version compatibility:

**Features:**
- **Protocol Version Validation**: Ensures clients use supported MCP protocol versions
- **Backward Compatibility**: Supports multiple MCP specification versions
- **Path-Specific Validation**: Only validates requests to MCP endpoints (`/mcp` paths)

**Supported Versions:**
- `2025-06-18` (Current MCP specification)
- `2025-03-26` (Backward compatibility)

**Validation Logic:**
- Validates `MCP-Protocol-Version` header on requests to `/{service-id}/mcp` endpoints
- Returns 400 error for unsupported versions with helpful error messages
- Allows requests without version header (backend should handle gracefully)
- Bypasses validation for non-MCP endpoints

## Development Guidelines

### Storage Backend Selection
Choose the appropriate storage backend based on your deployment requirements:

**Memory Storage** (Default)
- ✅ Development and testing
- ✅ Single-instance deployments
- ✅ No external dependencies
- ❌ Data loss on restart
- ❌ Not suitable for multi-instance

**Redis Storage**
- ✅ Production deployments
- ✅ Multi-instance scaling
- ✅ Persistent data storage
- ✅ High performance
- ❌ Requires Redis infrastructure

**Vault Storage**
- ✅ Enterprise security requirements
- ✅ Compliance and audit needs
- ✅ Encrypted storage at rest
- ✅ Fine-grained access control
- ❌ Complex setup and maintenance
- ❌ Higher operational overhead

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

### Security Configuration

Configure the gateway's security middleware for your environment:

**Development Configuration:**
```yaml
host: "localhost"  # Bind to localhost for development security
port: 8080
issuer: "http://localhost:8080"
debug: true  # Enables permissive Origin validation (enforce_localhost=False)

cors:
  allow_origins: ["http://localhost:3000", "https://dev.myapp.com"]
  allow_credentials: true
```

**Production Configuration:**
```yaml
host: "0.0.0.0"  # Can bind to all interfaces with proper origin validation
port: 8080
issuer: "https://gateway.myapp.com"
debug: false  # Enables strict Origin validation (enforce_localhost=True)

cors:
  allow_origins: ["https://myapp.com", "https://admin.myapp.com"]  # Explicit production origins
  allow_credentials: true
  allow_methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  allow_headers: ["Authorization", "Content-Type", "MCP-Protocol-Version"]
```

**Security Behavior by Environment:**
- **Development** (`debug=true`): Permissive origin validation for easy testing
- **Production** (`debug=false`): Strict origin validation with localhost fallback for debugging

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
3. **Service gets canonical URI** for token audience: `{issuer}/{service-id}/mcp`
4. **Backend services receive user context** via headers
5. **All services must use the same OAuth provider** configured in the gateway

### Code Style and Standards

- **Use Pydantic models** for all data validation
- **Follow FastAPI patterns** for dependency injection
- **Use async/await** for all I/O operations
- **Add type hints** to all functions
- **Use structured logging** with context
- **Format code** with Black and Ruff

### Testing

- **Comprehensive test suite** - 16+ test files covering all components with 197+ test cases
- **OAuth 2.1 component testing** - PKCE validation, token exchange, metadata endpoints with canonical URIs
- **Security middleware testing** - Origin validation, MCP protocol version validation, middleware integration
- **Security boundary testing** - Token validation, redirect URI validation, audience binding, error paths
- **Configuration validation testing** - Single provider constraints, service configuration, canonical URI generation
- **Component isolation testing** - Mocked HTTP requests, isolated functionality testing
- **Integration testing** - End-to-end OAuth flows with service-specific token validation
- **pytest framework** with async support, HTTP client mocking, FastAPI TestClient, and component fixtures
- **Test utilities** - PKCE generation helpers, crypto validation tools, middleware test patterns

### Security Considerations

- **NEVER log sensitive data** (tokens, secrets, user data)
- **Validate all input** using Pydantic models
- **Use secure random generation** for codes and secrets
- **Configure Origin validation** appropriately for your environment
- **Enable localhost enforcement** in production (`debug=False`)
- **Validate MCP protocol versions** to ensure client compatibility
- **Implement proper CORS** for web clients with explicit origins
- **Enforce HTTPS** in production
- **Validate redirect URIs** strictly
- **Use service-specific canonical URIs** for proper token audience binding

### Storage Backend Deployment

**Development Setup (Memory)**
```bash
# Use default memory storage - no additional setup required
python -m src.gateway --config config.yaml --debug
```

**Production Setup (Redis)**
```bash
# Install Redis dependencies (modern library for Python 3.11+)
pip install -r requirements-redis.txt

# Alternative: Install directly
pip install 'redis[hiredis]>=4.5.0'  # For Python 3.11+
# pip install aioredis>=2.0.0         # For older Python versions

# Set environment variables
export REDIS_HOST=redis.example.com
export REDIS_PASSWORD=your-secure-password

# Update config.yaml storage section
# storage:
#   type: "redis"
#   redis:
#     ssl: true
#     max_connections: 50

python -m src.gateway --config config.yaml
```

**Enterprise Setup (Vault)**
```bash
# Install Vault dependencies  
pip install -r requirements-vault.txt

# Set environment variables
export VAULT_URL=https://vault.example.com:8200
export VAULT_TOKEN=your-vault-token

# Update config.yaml storage section
# storage:
#   type: "vault"
#   vault:
#     mount_point: "kv"
#     path_prefix: "apps/mcp-gateway/prod"

python -m src.gateway --config config.yaml
```

**Docker with Redis**
```bash
# Start Redis container
docker run -d --name redis \
  -p 6379:6379 \
  redis:alpine redis-server --requirepass mypassword

# Run gateway with Redis
export REDIS_PASSWORD=mypassword
python -m src.gateway --config config.yaml
```

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

# Run tests (all 197+ test cases)
pytest

# Run specific test categories
pytest tests/gateway/test_middleware.py  # Security middleware tests
pytest tests/api/test_metadata.py       # Canonical URI tests
pytest tests/integration/               # Integration tests

# Type checking (if mypy is added)
mypy src/
```

### Troubleshooting

**Origin Validation Issues:**
```bash
# 403 Unauthorized origin errors in production
# Check CORS configuration and debug mode:
debug: false  # Should be false in production
cors:
  allow_origins: ["https://yourapp.com"]  # Add your domain

# For development, enable debug mode:
debug: true  # Allows more permissive origins
```

**MCP Protocol Version Issues:**
```bash
# 400 Unsupported MCP protocol version
# Ensure your client sends supported version header:
curl -H "MCP-Protocol-Version: 2025-06-18" https://gateway.com/service/mcp

# Supported versions: 2025-06-18, 2025-03-26
# Missing header is allowed (backend handles default)
```

**Token Audience Issues:**
```bash
# 401 Invalid token errors
# Verify token audience matches service canonical URI:
# Expected: https://gateway.com/calculator/mcp
# Not:      https://gateway.com/calculator

# Check metadata endpoint for correct canonical URI:
curl https://gateway.com/.well-known/oauth-protected-resource?service_id=calculator
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
- **Service-specific canonical URIs** following format `{issuer}/{service-id}/mcp`
- **Dynamic Client Registration** per RFC 7591
- **Proper metadata endpoints** per RFC 8414 and RFC 9728

### MCP Protocol Support
- **Streamable HTTP transport** as specified in MCP
- **MCP protocol version validation** for specification compliance
- **User context injection** for backend authorization
- **Transparent proxying** maintains MCP protocol semantics
- **Service-specific token scoping** prevents privilege escalation

### Security Architecture
- **Multi-layer security middleware** with DNS rebinding protection
- **Environment-aware security** (development vs production modes)
- **Service isolation** through audience-bound tokens with canonical URIs
- **Single provider design** ensures consistent authentication
- **Session management** with secure, signed sessions
- **State validation** prevents CSRF attacks
- **Origin validation** protects against cross-origin attacks


## Current Implementation Status

### ✅ Implemented Features

#### Complete OAuth 2.1 Implementation
- Authorization code flow with PKCE support (S256 only) ✅
- Refresh token flow with token rotation for public clients ✅
- Dynamic Client Registration (RFC 7591) with comprehensive validation ✅ 
- Authorization Server Metadata (RFC 8414) ✅
- Protected Resource Metadata (RFC 9728) ✅
- JWT token creation and validation with audience binding ✅
- Token revocation functionality (internal) ✅
- Client authentication (basic, post, none methods) ✅

#### Advanced Security Features
- PKCE code challenge validation (S256 required) ✅
- JWT audience validation with service-specific resource binding ✅
- Comprehensive redirect URI validation ✅
- State parameter CSRF protection with expiration ✅
- Bearer token authentication with timeout handling ✅
- Client deduplication and credential security ✅
- Single provider constraint enforcement ✅
- Origin header validation for DNS rebinding protection ✅
- MCP-Protocol-Version validation and enforcement ✅
- Localhost binding warnings for development security ✅

#### Production-Ready MCP Integration
- HTTP proxy to backend MCP services with connection pooling ✅
- User context header injection (`x-user-id`, `x-user-email`, etc.) ✅
- Service-specific authentication requirements ✅
- Configurable timeouts per service with 502/504 error handling ✅
- Service health monitoring capabilities ✅
- MCP protocol compliance with proper headers ✅

#### Unit Testing Infrastructure
- 16 test files covering individual components with mocking ✅
- OAuth 2.1 component testing (PKCE validation, token exchange, metadata) ✅
- Security boundary testing (token validation, redirect URI validation) ✅
- Configuration validation testing (single provider constraints, service config) ✅
- Provider component testing (Google, GitHub, Okta, custom with mocking) ✅
- Configuration testing (YAML loading, environment variables, validation) ✅
- Error handling and edge case testing with mocked scenarios ✅

#### Resource Parameter Support
- Resource parameter accepted and properly implemented per RFC 8707 ✅
- Service-specific canonical URIs used as audience (e.g., `https://gateway.com/calculator/mcp`) ✅
- Proper token audience binding prevents cross-service token reuse ✅
- MCP clients get tokens bound to specific services per specification ✅

### ❌ Current Limitations

#### OAuth 2.1 Resource Parameter Constraints
- **Single OAuth provider**: Due to domain-wide resource parameter requirements, only one OAuth provider can be configured per gateway instance
- **Service provider binding**: All MCP services must use the same OAuth provider

#### Default Deployment Constraints
- **Memory storage default**: Default configuration uses memory storage (suitable for development)
- **Single instance by default**: Requires Redis/Vault configuration for horizontal scaling
- **Basic HTTP in development**: Development configuration uses HTTP (HTTPS recommended for production)

#### Missing Public Endpoints
- **Token revocation**: Functionality implemented but not exposed as public endpoint
- **Token introspection**: Functionality implemented but not exposed as public endpoint
- **Refresh token endpoint**: Basic implementation exists but needs enhancement

#### Storage Backend Limitations
- **Memory storage persistence**: Memory backend loses data on restart (by design)
- **Vault TTL complexity**: Vault storage uses manual timestamp-based TTL (KV engine limitation)
- **Redis dependency**: Redis backend requires aioredis library and Redis server

## Architecture Design Notes

### Streamable HTTP MCP Proxy Focus
- **Purpose-built for MCP**: Specifically designed as an OAuth 2.1 proxy for Streamable HTTP MCP services
- **Transparent authentication**: Handles OAuth complexity while maintaining MCP protocol semantics
- **User context injection**: Adds authentication context via headers for backend MCP services
- **Development-friendly**: In-memory storage and simple configuration for rapid development

### Design Decisions
- **Monolithic structure**: Single `gateway.py` file for simplicity and easier development
- **HTTP proxy approach**: Transparent request/response forwarding maintains MCP protocol integrity
- **OAuth 2.1 focus**: Implements core OAuth flows needed for MCP authorization
- **Single provider design**: All services use the same OAuth provider due to resource parameter constraints

This implementation provides a **development OAuth 2.1 gateway** for MCP services suitable for development, testing, and demonstration scenarios. The in-memory design and single-instance architecture make it ideal for rapid prototyping and proof-of-concept work.

## Future Enhancements

- **Additional storage statistics** and monitoring endpoints
- **Public refresh token endpoint** exposure
- **Public token revocation endpoint** exposure  
- **Token introspection endpoint** exposure
- **WebSocket transport** for MCP services
- **User management interface** for administrators
- **Metrics and observability** integration
- **Rate limiting** for OAuth endpoints