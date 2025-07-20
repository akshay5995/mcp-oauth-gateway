# MCP OAuth Gateway Architecture

This document provides a comprehensive architectural overview of the MCP OAuth Gateway, including current implementation status, design patterns, data flows, and specifications.

📚 **Documentation Navigation**
- 🚀 **[README.md](README.md)** - Quick start guide and basic configuration
- 🏗️ **[ARCHITECTURE.md](ARCHITECTURE.md)** - System architecture and design (this document)  
- 👩‍💻 **[CLAUDE.md](CLAUDE.md)** - Developer guide and implementation details

## System Overview

The MCP OAuth Gateway is an OAuth 2.1 authorization server that provides transparent authentication and authorization for Model Context Protocol (MCP) services. It acts as a secure proxy that handles OAuth complexity, allowing users to access `https://gateway.example.com/<service-id>/mcp` with authentication handled automatically.

**Current Status**: Work-in-progress implementation with complete OAuth 2.1 functionality, comprehensive testing, and MCP proxying. Suitable for development, testing, and demonstration scenarios.

### Key Features

- **Transparent MCP Access**: Users access MCP services via simple URLs without manual OAuth setup
- **Single OAuth Provider**: Uses one OAuth provider for all services (Google, GitHub, Okta, or custom)
- **Full MCP Compliance**: Implements complete MCP authorization specification with OAuth 2.1
- **Dynamic Client Registration**: Automatic client registration per RFC 7591
- **User Context Injection**: Seamless user context headers for backend MCP services
- **Resource-Specific Tokens**: RFC 8707 audience binding prevents token misuse
- **Configurable Storage**: Memory (dev), Redis (production), Vault (enterprise) backends
- **Production Ready**: Comprehensive testing, Docker support, scalable architecture

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
    
    subgraph "Storage Layer (storage/)"
        StorageMgr[Storage Manager]
        MemoryStorage[Memory Storage]
        RedisStorage[Redis Storage]
        VaultStorage[Vault Storage]
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
    AuthServer --> StorageMgr
    
    StorageMgr --> MemoryStorage
    StorageMgr --> RedisStorage
    StorageMgr --> VaultStorage
    
    McpEndpoints --> McpProxy
    
    AuthServer --> Config
    AuthServer --> Models
    StorageMgr --> Config
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

### Configuration Structure

The gateway uses YAML-based configuration with environment variable substitution to define:

- **Gateway settings**: Host, port, issuer URL, session secrets
- **OAuth provider**: Single provider configuration (Google, GitHub, Okta, or custom)
- **MCP services**: Service definitions with authentication requirements  
- **Storage backend**: Memory, Redis, or Vault storage configuration
- **CORS policies**: Cross-origin access controls

📚 **[Complete Configuration Guide](CLAUDE.md#configuration)** - Detailed configuration options, examples, and best practices

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
Location: https://accounts.google.com/oauth/authorize?client_id=${GOOGLE_CLIENT_ID}&redirect_uri=https%3A%2F%2Fmcp-gateway.example.com%2Foauth%2Fcallback%2Fgoogle&scope=openid%20email%20profile&state=internal_state_abc123&response_type=code
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

## Implementation Overview

The MCP OAuth Gateway provides a complete OAuth 2.1 authorization server with:

- **Full OAuth 2.1 compliance**: Authorization code flow with PKCE, Dynamic Client Registration, metadata endpoints
- **MCP protocol support**: Transparent proxying with user context injection
- **Production-ready features**: Configurable storage backends, comprehensive security middleware
- **Extensive testing**: 197+ test cases covering all components

📚 **[Detailed Implementation Status](CLAUDE.md#current-implementation-status)** - Complete feature list, limitations, and development progress

## Testing Architecture

The MCP OAuth Gateway includes comprehensive test coverage with **197+ test cases** across 16 test files:

- **OAuth 2.1 Component Testing**: PKCE validation, token exchange, metadata endpoints
- **Security Boundary Testing**: Token validation, redirect URI validation, audience binding
- **Provider Integration Testing**: Google, GitHub, Okta, and custom provider support  
- **Configuration Testing**: YAML validation, environment variables, constraint validation
- **Integration Testing**: End-to-end OAuth flows with mocked external dependencies

📚 **[Complete Testing Guide](CLAUDE.md#testing)** - Detailed test organization, framework usage, and development guidelines

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

### Storage Architecture

The MCP OAuth Gateway uses configurable storage backends to support different deployment scenarios:

- **Memory Storage**: Default in-memory storage for development and testing
- **Redis Storage**: Production-ready persistent storage with multi-instance support  
- **Vault Storage**: Enterprise-grade encrypted storage with audit capabilities

Storage backend selection is configured via YAML and automatically falls back to memory storage if external backends are unavailable.

📚 **[Detailed Storage Implementation Guide](CLAUDE.md#storage-backends)** - Complete storage backend documentation, configuration options, and deployment patterns

## MCP Compliance Summary

**Specification Adherence**: The gateway provides a functional implementation of MCP authorization and transport specifications optimized for development use:

- **Authorization**: Core OAuth 2.1 flow works effectively with MCP clients, handling dynamic client registration and PKCE authentication
- **Transport**: Streamable HTTP transport is properly implemented with transparent proxying and user context injection
- **Storage**: Configurable storage backends support development through enterprise deployment scenarios
- **Demo Compatibility**: Successfully works with the included FastMCP calculator demo service

**Design Philosophy**: Built as a development-focused OAuth 2.1 proxy for Streamable HTTP MCP services, prioritizing simplicity and rapid setup for prototyping and demonstration use. The configurable storage architecture enables scaling from development (memory) to production (Redis) to enterprise (Vault) deployments.