# MCP OAuth Gateway Architecture

This document provides a comprehensive architectural overview of the MCP OAuth Gateway, including current implementation status, design patterns, data flows, and specifications.

## System Overview

The MCP OAuth Gateway is an OAuth 2.1 authorization server that provides transparent authentication and authorization for Model Context Protocol (MCP) services. It acts as a secure proxy that handles OAuth complexity, allowing users to access `https://gateway.example.com/<service-id>/mcp` with authentication handled automatically.

**Current Status**: Work-in-progress implementation with complete OAuth 2.1 functionality, comprehensive testing, and MCP proxying. Suitable for development, testing, and demonstration scenarios.

### Key Features (Currently Implemented)

- **Transparent MCP Access**: Users access MCP services via simple URLs without manual OAuth setup ✅
- **Single OAuth Provider**: One OAuth provider per gateway instance (Google, GitHub, Okta, or custom) ✅
- **OAuth 2.1 Core Flow**: Authorization code flow with PKCE support ✅
- **Dynamic Client Registration**: Automatic client registration per RFC 7591 ✅
- **User Context Injection**: Seamless user context headers for backend MCP services ✅
- **JWT Token Management**: Service-scoped tokens with validation ✅

## System Architecture

### High-Level Architecture

```mermaid
graph TB
    Client[MCP Client] --> Gateway[OAuth Gateway]
    Gateway --> Backend[MCP Services]
    Gateway --> Provider[OAuth Provider<br/>Google/GitHub/Custom]
    
    subgraph "OAuth Gateway"
        AuthServer[OAuth 2.1 Server]
        Proxy[MCP Proxy]
        TokenMgr[Token Manager]
        ClientReg[Client Registry]
    end
    
    subgraph "MCP Services"
        Calculator[Calculator Service]
        Weather[Weather Service]
        Docs[Documentation Service]
    end
    
    subgraph "OAuth Providers"
        Google[Google OAuth]
        GitHub[GitHub OAuth]
        Custom[Custom Provider]
    end
```

### Current Implementation Architecture

```mermaid
graph TB
    subgraph "Main Application (gateway.py)"
        FastAPI[FastAPI Application]
        OAuth[OAuth Endpoints]
        Meta[Metadata Endpoints]
        McpEndpoints[MCP Service Endpoints]
        Health[Health Endpoints]
    end
    
    subgraph "Authentication Layer (auth/)"
        AuthServer[OAuth Server]
        ProviderMgr[Provider Manager]
        TokenMgr[Token Manager]
        ClientReg[Client Registry]
    end
    
    subgraph "Proxy Layer (proxy/)"
        McpProxy[MCP Proxy]
    end
    
    subgraph "Configuration (config/)"
        Config[Config Manager]
    end
    
    subgraph "Data Models (auth/models.py)"
        Models[Pydantic Models]
    end
    
    FastAPI --> OAuth
    FastAPI --> Meta
    FastAPI --> McpEndpoints
    FastAPI --> Health
    
    OAuth --> AuthServer
    AuthServer --> ProviderMgr
    AuthServer --> TokenMgr
    AuthServer --> ClientReg
    
    McpEndpoints --> McpProxy
    
    AuthServer --> Config
    AuthServer --> Models
```

## OAuth 2.1 Flow Architecture

### Authorization Code Flow with PKCE

```mermaid
sequenceDiagram
    participant Client as MCP Client
    participant Gateway as OAuth Gateway
    participant Provider as OAuth Provider
    participant Backend as MCP Service
    
    Note over Client,Backend: 1. Discovery Phase
    Client->>Gateway: GET /{service-id}/mcp
    Gateway->>Client: 401 + WWW-Authenticate header
    
    Note over Client,Backend: 2. Metadata Retrieval
    Client->>Gateway: GET /.well-known/oauth-authorization-server
    Gateway->>Client: OAuth server metadata
    Client->>Gateway: GET /.well-known/oauth-protected-resource
    Gateway->>Client: Resource metadata
    
    Note over Client,Backend: 3. Client Registration
    Client->>Gateway: POST /oauth/register
    Gateway->>Client: client_id + client_secret
    
    Note over Client,Backend: 4. Authorization Flow
    Client->>Gateway: GET /oauth/authorize + PKCE + resource
    Gateway->>Provider: Redirect to provider auth
    Provider->>Gateway: Authorization code callback
    Gateway->>Client: Redirect with authorization code
    
    Note over Client,Backend: 5. Token Exchange
    Client->>Gateway: POST /oauth/token + code_verifier
    Gateway->>Provider: Exchange code for user info
    Provider->>Gateway: User profile data
    Gateway->>Client: JWT access token with audience
    
    Note over Client,Backend: 6. Authenticated Request
    Client->>Gateway: Request with Bearer token
    Gateway->>Gateway: Validate token + extract user
    Gateway->>Backend: Proxied request + user headers
    Backend->>Gateway: Response
    Gateway->>Client: Response
```

### Token Validation Flow

```mermaid
graph TB
    Request[Incoming Request] --> Auth{Has Authorization<br/>Header?}
    Auth -->|No| Reject[401 Unauthorized]
    Auth -->|Yes| Extract[Extract Bearer Token]
    
    Extract --> Validate{Valid JWT?}
    Validate -->|No| Reject
    Validate -->|Yes| Audience{Correct Audience?}
    
    Audience -->|No| Reject
    Audience -->|Yes| Expired{Token Expired?}
    
    Expired -->|Yes| Reject
    Expired -->|No| UserCtx[Extract User Context]
    
    UserCtx --> Headers[Add x-user-* Headers]
    Headers --> Proxy[Forward to Backend]
```

## Data Flow Architecture

### Request Processing Pipeline

```mermaid
graph TB
    subgraph "Ingress"
        Request[HTTP Request]
        CORS[CORS Middleware]
        Route[Route Matching]
    end
    
    subgraph "Authentication"
        AuthCheck{Auth Required?}
        TokenValidation[Token Validation]
        UserExtraction[User Context Extraction]
    end
    
    subgraph "Authorization"
        ScopeCheck[Scope Validation]
        ResourceCheck[Resource Binding Check]
    end
    
    subgraph "Proxying"
        HeaderInjection[User Header Injection]
        BackendRequest[Backend HTTP Request]
        ResponseProxy[Response Proxying]
    end
    
    Request --> CORS
    CORS --> Route
    Route --> AuthCheck
    
    AuthCheck -->|Yes| TokenValidation
    AuthCheck -->|No| HeaderInjection
    
    TokenValidation --> UserExtraction
    UserExtraction --> ScopeCheck
    ScopeCheck --> ResourceCheck
    ResourceCheck --> HeaderInjection
    
    HeaderInjection --> BackendRequest
    BackendRequest --> ResponseProxy
```

### Configuration Data Flow

```mermaid
graph TB
    subgraph "Configuration Sources"
        YAML[config.yaml]
        EnvVars[Environment Variables]
        Defaults[Default Values]
    end
    
    subgraph "Processing"
        Parser[YAML Parser]
        Substitution[Variable Substitution]
        Validation[Schema Validation]
    end
    
    subgraph "Runtime Configuration"
        Gateway[Gateway Config]
        Providers[OAuth Providers]
        Services[MCP Services]
    end
    
    YAML --> Parser
    EnvVars --> Substitution
    Defaults --> Validation
    
    Parser --> Substitution
    Substitution --> Validation
    
    Validation --> Gateway
    Validation --> Providers
    Validation --> Services
```

## Security Architecture

### OAuth 2.1 Security Model

```mermaid
graph TB
    subgraph "Client Security"
        PKCE[PKCE Code Challenge]
        RedirectVal[Redirect URI Validation]
        StateParam[State Parameter CSRF Protection]
    end
    
    subgraph "Token Security"
        JWTAudience[JWT Audience Binding]
        TokenExpiry[Token Expiration]
        ResourceBinding[Resource-Specific Tokens]
    end
    
    subgraph "Provider Security"
        CredStorage[Secure Credential Storage]
        ProviderVal[Provider Validation]
        UserInfoSec[User Info Security]
    end
    
    subgraph "Transport Security"
        HTTPSEnforce[HTTPS Enforcement]
        SecureHeaders[Security Headers]
        CORSPolicy[CORS Policy]
    end
    
    PKCE --> JWTAudience
    RedirectVal --> TokenExpiry
    StateParam --> ResourceBinding
    
    JWTAudience --> CredStorage
    TokenExpiry --> ProviderVal
    ResourceBinding --> UserInfoSec
    
    CredStorage --> HTTPSEnforce
    ProviderVal --> SecureHeaders
    UserInfoSec --> CORSPolicy
```

### Token Lifecycle

```mermaid
stateDiagram-v2
    [*] --> AuthorizationRequest: Client initiates OAuth
    AuthorizationRequest --> CodeGeneration: User authorizes
    CodeGeneration --> CodeExchange: Client exchanges code
    CodeExchange --> TokenCreation: Validation successful
    TokenCreation --> TokenActive: JWT issued
    
    TokenActive --> TokenValidation: Each request
    TokenValidation --> TokenActive: Valid token
    TokenValidation --> TokenExpired: Expired
    TokenValidation --> TokenInvalid: Invalid signature/audience
    
    TokenExpired --> [*]
    TokenInvalid --> [*]
    TokenActive --> TokenRevoked: Manual revocation
    TokenRevoked --> [*]
```

## Deployment Architecture

### Container Architecture

```mermaid
graph TB
    subgraph "Load Balancer"
        LB[Nginx/HAProxy]
    end
    
    subgraph "Gateway Cluster"
        GW1[Gateway Instance 1]
        GW2[Gateway Instance 2]
        GW3[Gateway Instance 3]
    end
    
    subgraph "Session Storage"
        Redis[(Redis Cluster)]
    end
    
    subgraph "Backend Services"
        MCP1[MCP Service 1]
        MCP2[MCP Service 2]
        MCP3[MCP Service 3]
    end
    
    subgraph "External Services"
        Google[Google OAuth]
        GitHub[GitHub OAuth]
        Custom[Custom OAuth]
    end
    
    LB --> GW1
    LB --> GW2
    LB --> GW3
    
    GW1 --> Redis
    GW2 --> Redis
    GW3 --> Redis
    
    GW1 --> MCP1
    GW1 --> MCP2
    GW1 --> MCP3
    
    GW1 --> Google
    GW1 --> GitHub
    GW1 --> Custom
```

### Service Mesh Integration

```mermaid
graph TB
    subgraph "Ingress Layer"
        Ingress[Istio Gateway]
        VirtualService[Virtual Service]
    end
    
    subgraph "OAuth Gateway"
        Gateway[Gateway Pod]
        Sidecar1[Envoy Sidecar]
    end
    
    subgraph "MCP Services"
        Service1[Service 1 Pod]
        Sidecar2[Envoy Sidecar]
        Service2[Service 2 Pod]
        Sidecar3[Envoy Sidecar]
    end
    
    subgraph "Observability"
        Prometheus[Prometheus]
        Jaeger[Jaeger]
        Grafana[Grafana]
    end
    
    Ingress --> VirtualService
    VirtualService --> Sidecar1
    Sidecar1 --> Gateway
    Gateway --> Sidecar2
    Gateway --> Sidecar3
    Sidecar2 --> Service1
    Sidecar3 --> Service2
    
    Sidecar1 --> Prometheus
    Sidecar2 --> Prometheus
    Sidecar3 --> Prometheus
    
    Sidecar1 --> Jaeger
    Sidecar2 --> Jaeger
    Sidecar3 --> Jaeger
```

## API Architecture

### Currently Implemented Endpoints

#### OAuth 2.1 Endpoints (✅ Implemented)
- **`GET /.well-known/oauth-authorization-server`** - OAuth server metadata (RFC 8414)
- **`GET /.well-known/oauth-protected-resource`** - Resource metadata (RFC 9728)
- **`GET /oauth/authorize`** - Authorization endpoint with PKCE support
- **`POST /oauth/token`** - Token endpoint for code exchange
- **`POST /oauth/register`** - Dynamic Client Registration (RFC 7591)
- **`GET /oauth/callback/{provider}`** - OAuth provider callback handling

#### MCP Service Endpoints (✅ Implemented)
- **`GET /{service-id}/mcp`** (unauthorized) - Returns 401 with WWW-Authenticate header
- **`ALL /{service-id}/mcp`** (with Bearer token) - Proxies to backend MCP services
- **`GET /services`** - Lists all available MCP services
- **`GET /services/{service-id}`** - Returns specific service information

#### Health and Utility Endpoints (✅ Implemented)
- **`GET /`** - Gateway information and status
- **`GET /health`** - Basic health check

### Missing Endpoints (❌ Not Implemented)
- **`POST /oauth/introspect`** - Token introspection (RFC 7662)
- **`GET /oauth/userinfo`** - User information endpoint
- **`GET /oauth/jwks`** - JSON Web Key Set
- **`GET /health/providers`** - OAuth provider connectivity
- **`GET /health/services`** - Backend service health

## Implementation Specifications

### Current Configuration Schema

Based on the actual `config.yaml` structure:

```yaml
# Gateway settings
host: "0.0.0.0"                # Bind address
port: 8080                     # Listen port
issuer: "http://localhost:8080" # OAuth issuer URL (used as audience)
session_secret: "your-production-secret-key-change-this"
debug: true                    # Debug mode flag

# CORS configuration
cors:
  allow_origins: ["*"]         # Allowed origins (use specific domains in production)
  allow_credentials: true      # Allow credentials in CORS requests
  allow_methods:               # Allowed HTTP methods
    - "GET"
    - "POST"
    - "PUT"
    - "DELETE"
    - "OPTIONS"
  allow_headers: ["*"]         # Allowed headers (use specific headers in production)

# Single OAuth provider for user authentication
# Only ONE provider can be configured per gateway instance
oauth_providers:
  github:                      # Currently configured provider
    client_id: $CLIENT_ID
    client_secret: $CLIENT_SECRET
    scopes:
      - "user:email"
  
  # Alternative providers (configure only ONE):
  # google:
  #   client_id: $GOOGLE_CLIENT_ID
  #   client_secret: $GOOGLE_CLIENT_SECRET
  #   scopes: ["openid", "email", "profile"]
  # 
  # okta:
  #   client_id: $OKTA_CLIENT_ID
  #   client_secret: $OKTA_CLIENT_SECRET
  #   authorization_url: "https://domain.okta.com/oauth2/default/v1/authorize"
  #   token_url: "https://domain.okta.com/oauth2/default/v1/token"
  #   userinfo_url: "https://domain.okta.com/oauth2/default/v1/userinfo"
  #   scopes: ["openid", "email", "profile"]

# MCP services to proxy
mcp_services:
  calculator:
    name: "Calculator"
    url: "http://localhost:3001/mcp/"
    oauth_provider: "github"    # Must match the configured provider above
    auth_required: true
    scopes:
      - "read"
      - "calculate"
    timeout: 30000
  
  calculator_public:
    name: "Public Calculator" 
    url: "http://localhost:3001/mcp/"
    auth_required: false        # No authentication required
    timeout: 10000
    
  # All authenticated services must use the same OAuth provider:
  # weather:
  #   name: "Weather Service"
  #   url: "http://localhost:3002/mcp/"
  #   oauth_provider: "github"  # Same provider as above
  #   auth_required: true
```

### Request/Response Examples

#### 1. Initial MCP Access (Unauthorized)

**Request:**
```http
GET /calculator/mcp HTTP/1.1
Host: mcp-gateway.example.com
```

**Response:**
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp-gateway.example.com/.well-known/oauth-protected-resource"
Content-Type: application/json

{
  "error": "unauthorized",
  "error_description": "Authentication required for this MCP service"
}
```

#### 2. Authorization Server Metadata

**Request:**
```http
GET /.well-known/oauth-authorization-server HTTP/1.1
Host: mcp-gateway.example.com
```

**Response:**
```json
{
  "issuer": "https://mcp-gateway.example.com",
  "authorization_endpoint": "https://mcp-gateway.example.com/oauth/authorize",
  "token_endpoint": "https://mcp-gateway.example.com/oauth/token",
  "registration_endpoint": "https://mcp-gateway.example.com/oauth/register",
  "scopes_supported": ["read", "write", "calculate"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code"],
  "code_challenge_methods_supported": ["S256"],
  "resource_parameter_supported": true,
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]
}
```

#### 3. Dynamic Client Registration

**Request:**
```http
POST /oauth/register HTTP/1.1
Content-Type: application/json
Host: mcp-gateway.example.com

{
  "client_name": "MCP Desktop Client",
  "redirect_uris": ["http://localhost:8080/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "client_secret_basic"
}
```

**Response:**
```json
{
  "client_id": "mcp_client_123456789",
  "client_secret": "secret_abc123def456",
  "client_name": "MCP Desktop Client",
  "redirect_uris": ["http://localhost:8080/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "client_secret_basic",
  "client_id_issued_at": 1640995200,
  "client_secret_expires_at": 0
}
```

#### 4. Authorization Request with Resource Parameter

**Request:**
```http
GET /oauth/authorize?response_type=code&client_id=mcp_client_123456789&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&scope=read%20calculate&state=xyz123&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&resource=https%3A%2F%2Fmcp-gateway.example.com%2Fcalculator HTTP/1.1
Host: mcp-gateway.example.com
```

**Response:**
```http
HTTP/1.1 302 Found
Location: https://accounts.google.com/oauth/authorize?client_id=google_client_id&redirect_uri=https%3A%2F%2Fmcp-gateway.example.com%2Foauth%2Fcallback%2Fgoogle&scope=openid%20email%20profile&state=internal_state_abc123&response_type=code
```

#### 5. Token Exchange

**Request:**
```http
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Basic bWNwX2NsaWVudF8xMjM0NTY3ODk6c2VjcmV0X2FiYzEyM2RlZjQ1Ng==
Host: mcp-gateway.example.com

grant_type=authorization_code&code=auth_code_xyz789&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&resource=https%3A%2F%2Fmcp-gateway.example.com%2Fcalculator
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read calculate",
  "resource": "https://mcp-gateway.example.com/calculator"
}
```

#### 6. Authenticated MCP Request

**Client Request:**
```http
POST /calculator/mcp HTTP/1.1
Host: mcp-gateway.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "add",
  "params": {"a": 5, "b": 3}
}
```

**Proxied Request to Backend:**
```http
POST /mcp HTTP/1.1
Host: calculator-service:3001
Accept: application/json, text/event-stream
Content-Type: application/json
MCP-Protocol-Version: 2025-06-18
x-user-id: google_user_123456
x-user-email: user@example.com
x-user-name: John Doe
x-user-provider: google

{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "add",
  "params": {"a": 5, "b": 3}
}
```

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
- 15 test files covering individual components with mocking ✅
- OAuth 2.1 component testing (PKCE validation, token exchange, metadata) ✅
- Security boundary testing (token validation, redirect URI validation) ✅
- Configuration validation testing (single provider constraints, service config) ✅
- Provider component testing (Google, GitHub, Okta, custom with mocking) ✅
- Configuration testing (YAML loading, environment variables, validation) ✅
- Error handling and edge case testing with mocked scenarios ✅

### ✅ Full Implementation

#### Resource Parameter Support
- Resource parameter accepted and properly implemented per RFC 8707 ✅
- Service-specific canonical URIs used as audience (e.g., `https://gateway.com/calculator/mcp`) ✅
- Proper token audience binding prevents cross-service token reuse ✅
- MCP clients get tokens bound to specific services per specification ✅

### ❌ Current Limitations

#### OAuth 2.1 Resource Parameter Constraints
- **Single OAuth provider**: Due to domain-wide resource parameter requirements, only one OAuth provider can be configured per gateway instance
- **Service provider binding**: All MCP services must use the same OAuth provider

#### Scalability Constraints
- **In-memory storage**: Sessions, tokens, and clients stored in memory (suitable for development and small-scale production)
- **Single instance deployment**: Not designed for horizontal scaling without shared storage
- **Basic HTTP**: Development configuration uses HTTP (HTTPS recommended for production)

#### Missing Public Endpoints
- **Token revocation**: Functionality implemented but not exposed as public endpoint
- **Token introspection**: Functionality implemented but not exposed as public endpoint
- **Refresh token endpoint**: Basic implementation exists but needs enhancement

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

## Testing Architecture

### Unit Test Coverage

The MCP OAuth Gateway includes a unit testing infrastructure with **15 test files** covering individual components with mocking:

#### **Test Organization by Component**
```
tests/
├── auth/                    # OAuth 2.1 authentication system (6 files)
│   ├── test_oauth_server.py         # Core OAuth server functionality
│   ├── test_token_manager.py        # JWT token creation and validation
│   ├── test_client_registry.py      # Dynamic Client Registration (RFC 7591)
│   ├── test_provider_manager.py     # OAuth provider integration
│   ├── test_single_provider.py      # Single provider constraint enforcement
│   └── test_multi_provider_constraints.py # Single provider constraint validation
├── proxy/
│   └── test_mcp_proxy.py            # HTTP proxy and user context injection
├── config/
│   └── test_config.py               # Configuration management and validation
├── api/
│   └── test_metadata.py             # OAuth metadata endpoints (RFC compliance)
├── gateway/
│   └── test_provider_determination.py # Provider routing logic
├── integration/
│   └── test_resilient_oauth.py      # Single provider constraint validation testing
└── utils/
    └── crypto_helpers.py            # PKCE generation and validation utilities
```

#### **Testing Framework Stack**
- **pytest** (≥7.0.0) - Main testing framework with custom markers (`unit`, `integration`, `slow`)
- **pytest-asyncio** (≥0.23.0) - Async test support with automatic async mode
- **pytest-httpx** (≥0.21.0) - HTTP client mocking for external provider testing
- **unittest.mock** - Comprehensive mocking and patching capabilities

#### **Test Infrastructure Features**

**Advanced Fixtures (`conftest.py`)**:
- Complete gateway configuration for testing
- OAuth server, token manager, and client registry instances
- Provider manager with mock HTTP clients
- Shared test data and provider configurations

**Specialized Test Utilities**:
- PKCE code verifier and challenge generation
- Invalid challenge creation for error testing
- Crypto validation helpers for security testing

**Testing Patterns**:
- **Unit Tests**: Component-level testing with mocked dependencies
- **Configuration Tests**: Single provider constraint validation and service configuration
- **Security Tests**: PKCE validation, token verification, redirect URI security with mocking
- **Error Handling Tests**: Invalid inputs, malformed data, mocked network errors
- **Component Performance Tests**: Provider determination speed with simple benchmarks

#### **Test Quality and Coverage**

**OAuth 2.1 Component Testing**:
- ✅ PKCE code challenge validation (S256 required) with unit tests
- ✅ Resource parameter handling and audience binding with mocked scenarios
- ✅ Authorization Server Metadata (RFC 8414) endpoint testing
- ✅ Protected Resource Metadata (RFC 9728) endpoint testing
- ✅ Dynamic Client Registration (RFC 7591) component validation

**Security Boundary Testing**:
- ✅ Token validation with audience verification using unit tests
- ✅ Redirect URI security and validation with mocked scenarios
- ✅ State parameter CSRF protection testing
- ✅ Client authentication methods testing
- ✅ Single provider constraint enforcement validation

**Provider Component Testing**:
- ✅ Google OAuth component testing with mocked HTTP responses
- ✅ GitHub OAuth component testing with mocked API calls
- ✅ Okta OAuth component testing with mocked endpoints
- ✅ Custom OAuth provider component testing
- ✅ Provider error handling with mocked network failures

**Configuration and Component Testing**:
- ✅ YAML configuration loading and validation
- ✅ Environment variable substitution testing
- ✅ Single provider constraint validation
- ✅ Service-provider mapping validation
- ✅ MCP proxy request forwarding with mocked backends
- ✅ User context header injection testing

#### **Test Execution and Development**

**Running Tests**:
```bash
# All tests
pytest

# Specific test categories
pytest -m unit          # Unit tests only
pytest -m integration   # Integration tests only
pytest -m slow          # Performance/slow tests

# Specific components
pytest tests/auth/       # OAuth authentication tests
pytest tests/proxy/      # MCP proxy tests
pytest tests/config/     # Configuration tests
```

**Test Development Guidelines**:
- Async/await support throughout test suite
- Parametrized tests for different provider types
- Mock HTTP responses for external OAuth provider testing
- Comprehensive error and edge case coverage with mocking
- Mocked scenario testing (network errors, timeouts, malformed data)

The unit testing infrastructure provides **component-level confidence** in the OAuth 2.1 implementation and validates security constraints through mocked scenarios, supporting the gateway's development and demonstration use cases.

## MCP Specification Compliance

### MCP Authorization Specification (2025-06-18)

The gateway implements the MCP authorization specification based on OAuth 2.1 standards:

#### ✅ Currently Compliant Features

**Authorization Server Discovery**
- Implements OAuth 2.0 Protected Resource Metadata endpoint
- Returns proper "authorization_servers" field in metadata
- Uses "WWW-Authenticate" header for 401 Unauthorized responses

**Client Registration**
- Supports Dynamic Client Registration per RFC 7591
- Enables automatic OAuth client ID acquisition
- Provides flexibility for connecting new MCP servers

**Token Handling**
- Uses "Authorization: Bearer <access-token>" header format
- Tokens not included in URI query strings (security best practice)
- Implements JWT token validation with audience checking

**Security Implementation**
- PKCE (Proof Key for Code Exchange) support
- Redirect URI validation
- State parameter for CSRF protection

#### ✅ Full Compliance

**Resource Parameter Implementation**
- Accepts resource parameter in authorization and token requests ✅
- Implements service-specific canonical URIs per RFC 8707 ✅
- Uses canonical URIs like `https://gateway.example.com/{service-id}/mcp` ✅
- **Single Provider Constraint**: Resource parameter binding requires all services to use the same OAuth provider per gateway instance (architectural design choice)

#### 📝 Implementation Notes

**Resource Parameter Handling**
- Implements service-specific canonical URIs per RFC 8707 (e.g., `https://gateway.com/calculator/mcp`)
- Tokens are bound to specific services preventing cross-service reuse
- Full compliance with MCP Authorization specification requirements
- Proper audience validation ensures security isolation between services

### MCP Transport Specification (2025-06-18)

The gateway implements Streamable HTTP transport for MCP services:

#### ✅ Transport Compliance

**Streamable HTTP Transport**
- Single HTTP endpoint supporting POST and GET methods ✅
- Supports Server-Sent Events (SSE) for streaming responses ✅
- Proper HTTP proxy implementation with header forwarding ✅

**Protocol Headers**
- Forwards `MCP-Protocol-Version` header to backend services ✅
- Maintains JSON-RPC message format integrity ✅
- Preserves request/response semantics ✅

**Security Practices**
- Origin header validation through CORS middleware ✅
- Localhost binding in development configuration ✅
- Authentication integration with OAuth 2.1 ✅

#### ✅ Additional Transport Features

**User Context Integration**
- Injects user context headers (`x-user-*`) for backend services ✅
- Maintains session state through OAuth tokens ✅
- Supports service-specific authentication requirements ✅

**Proxy Capabilities**
- Transparent request/response forwarding ✅
- Configurable timeouts per service ✅
- Error handling and HTTP status code preservation ✅

#### 📝 Transport Design Notes

**Proxy Approach**
- Implements transparent HTTP proxy for Streamable HTTP MCP services
- Maintains stateless design with OAuth token-based authentication
- Focuses on single-request/response cycles as per MCP specification

**Connection Handling**
- Each request is independently authenticated and proxied
- Suitable for typical MCP client-server interaction patterns
- Backend services handle their own connection management

### MCP Integration Architecture

```mermaid
sequenceDiagram
    participant Client as MCP Client
    participant Gateway as OAuth Gateway
    participant Backend as MCP Server
    
    Note over Client,Backend: MCP Authorization Flow
    
    Client->>Gateway: GET /{service-id}/mcp
    Gateway->>Client: 401 + WWW-Authenticate header
    
    Note over Client,Gateway: OAuth 2.1 Discovery & Registration
    Client->>Gateway: GET /.well-known/oauth-protected-resource
    Gateway->>Client: Resource metadata with auth server
    
    Client->>Gateway: POST /oauth/register (Dynamic Registration)
    Gateway->>Client: client_id + client_secret
    
    Note over Client,Gateway: OAuth Authorization Flow
    Client->>Gateway: GET /oauth/authorize + PKCE + resource
    Gateway->>Client: Redirect to OAuth provider
    
    Note over Client,Gateway: Token Exchange
    Client->>Gateway: POST /oauth/token + code_verifier
    Gateway->>Client: access_token with audience
    
    Note over Client,Backend: Authenticated MCP Communication
    Client->>Gateway: POST /{service-id}/mcp + Bearer token
    Note over Gateway: Validate token + extract user context
    Gateway->>Backend: POST /mcp + MCP-Protocol-Version + x-user-* headers
    Backend->>Gateway: JSON-RPC response
    Gateway->>Client: Proxied response
```

### MCP Compliance Summary

**Specification Adherence**: The gateway provides a functional implementation of MCP authorization and transport specifications optimized for development use:

- **Authorization**: Core OAuth 2.1 flow works effectively with MCP clients, handling dynamic client registration and PKCE authentication
- **Transport**: Streamable HTTP transport is properly implemented with transparent proxying and user context injection
- **Demo Compatibility**: Successfully works with the included FastMCP calculator demo service

**Design Philosophy**: Built as a development-focused OAuth 2.1 proxy for Streamable HTTP MCP services, prioritizing simplicity and rapid setup for prototyping and demonstration use. The in-memory design and monolithic structure make it ideal for development, testing, and proof-of-concept scenarios.