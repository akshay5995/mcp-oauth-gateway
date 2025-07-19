# MCP OAuth Gateway

A OAuth 2.1 authorization server that provides transparent authentication and authorization for Model Context Protocol (MCP) services.

## Features

- **Transparent MCP Access**: Users access MCP services via simple URLs without manual OAuth setup
- **Single OAuth Provider**: Uses one OAuth provider for all services (Google, GitHub, Okta, or custom)
- **Full MCP Compliance**: Implements complete MCP authorization specification with OAuth 2.1
- **Dynamic Client Registration**: Automatic client registration per RFC 7591
- **User Context Injection**: Seamless user context headers for backend MCP services
- **Resource-Specific Tokens**: RFC 8707 audience binding prevents token misuse

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure OAuth Provider

**Important**: Configure only ONE OAuth provider per gateway instance.

Set up environment variables for your chosen provider:

```bash
# Option 1: Google OAuth
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"

# Option 2: GitHub OAuth
export GITHUB_CLIENT_ID="your-github-client-id"  
export GITHUB_CLIENT_SECRET="your-github-client-secret"

# Option 3: Okta OAuth
export OKTA_CLIENT_ID="your-okta-client-id"
export OKTA_CLIENT_SECRET="your-okta-client-secret"
export OKTA_DOMAIN="your-domain.okta.com"

# Choose only ONE provider above
```

### 3. Configure Services

Edit `config.yaml` to define your MCP services:

```yaml
# Configure single OAuth provider
oauth_providers:
  google:  # Configure only ONE provider
    client_id: "${GOOGLE_CLIENT_ID}"
    client_secret: "${GOOGLE_CLIENT_SECRET}"
    scopes: ["openid", "email", "profile"]

# All services must use the same provider
mcp_services:
  my_service:
    name: "My MCP Service"
    url: "http://localhost:3001"
    oauth_provider: "google"  # Must match configured provider
    auth_required: true
    scopes: ["read", "write"]
```

### 4. Run the Gateway

```bash
# Development mode
python -m src.gateway --config config.yaml --debug

# Production mode
python -m src.gateway --config config.yaml
```

### 5. Access MCP Services

MCP clients can now access services at:
```
http://localhost:8080/<service-id>/mcp
```

The gateway handles all OAuth complexity automatically!

## MCP Client Integration

### 1. Discovery

MCP clients start by accessing a service endpoint:

```http
GET /calculator/mcp HTTP/1.1
Host: localhost:8080
```

The gateway responds with OAuth metadata:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource"
```

### 2. Metadata Retrieval

Clients fetch OAuth metadata:

```bash
curl http://localhost:8080/.well-known/oauth-authorization-server
curl http://localhost:8080/.well-known/oauth-protected-resource
```

### 3. Dynamic Client Registration

Clients register automatically:

```bash
curl -X POST http://localhost:8080/oauth/register \
  -d "client_name=My MCP Client" \
  -d "redirect_uris=http://localhost:8080/callback"
```

### 4. Authorization Flow

Clients follow standard OAuth 2.1 with PKCE:

1. Authorization request with resource parameter
2. User authentication via configured provider
3. Authorization code exchange for access token
4. Authenticated MCP requests

## Configuration

### Gateway Settings

```yaml
host: "0.0.0.0"
port: 8080
issuer: "https://mcp-gateway.example.com"
session_secret: "production-secret-key"
debug: false
```

### CORS Configuration

Configure Cross-Origin Resource Sharing (CORS) for web clients:

```yaml
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
```

For production deployments, restrict CORS settings:

```yaml
cors:
  allow_origins: 
    - "https://myapp.example.com"
    - "https://dashboard.example.com"
  allow_credentials: true
  allow_methods: ["GET", "POST", "OPTIONS"]
  allow_headers: 
    - "Authorization"
    - "Content-Type"
    - "MCP-Protocol-Version"
```

### OAuth Provider Configuration

**Important**: Configure only ONE OAuth provider per gateway instance due to OAuth 2.1 resource parameter constraints.

```yaml
oauth_providers:
  # Choose ONE of the following providers:
  
  # Option 1: Google OAuth
  google:
    client_id: "${GOOGLE_CLIENT_ID}"
    client_secret: "${GOOGLE_CLIENT_SECRET}"
    scopes: ["openid", "email", "profile"]
  
  # Option 2: GitHub OAuth
  # github:
  #   client_id: "${GITHUB_CLIENT_ID}"
  #   client_secret: "${GITHUB_CLIENT_SECRET}"
  #   scopes: ["user:email"]
  
  # Option 3: Okta OAuth
  # okta:
  #   client_id: "${OKTA_CLIENT_ID}"
  #   client_secret: "${OKTA_CLIENT_SECRET}"
  #   authorization_url: "https://${OKTA_DOMAIN}/oauth2/default/v1/authorize"
  #   token_url: "https://${OKTA_DOMAIN}/oauth2/default/v1/token"
  #   userinfo_url: "https://${OKTA_DOMAIN}/oauth2/default/v1/userinfo"
  #   scopes: ["openid", "email", "profile"]
  
  # Option 4: Custom OAuth Provider
  # custom:
  #   authorization_url: "https://auth.company.com/oauth/authorize"
  #   token_url: "https://auth.company.com/oauth/token"
  #   userinfo_url: "https://auth.company.com/oauth/userinfo"
  #   client_id: "${CUSTOM_CLIENT_ID}"
  #   client_secret: "${CUSTOM_CLIENT_SECRET}"
  #   scopes: ["openid", "email", "profile"]
```

### MCP Services

```yaml
mcp_services:
  calculator:
    name: "Calculator Service"
    url: "http://calculator:3001"
    oauth_provider: "google"  # Must match the configured OAuth provider
    auth_required: true
    scopes: ["read", "calculate"]
    timeout: 30000
  
  # All authenticated services must use the same OAuth provider
  weather:
    name: "Weather Service"
    url: "http://weather:3002"
    oauth_provider: "google"  # Same as above
    auth_required: true
    scopes: ["read"]
```

## Backend Service Integration

Backend MCP services receive requests with user context headers:

```http
GET /mcp HTTP/1.1
Host: calculator:3001
x-user-id: google_user_123456
x-user-email: user@example.com
x-user-name: John Doe
x-user-provider: google
x-user-avatar: https://example.com/avatar.jpg
```

Services can use these headers for:
- User identification and authorization
- Audit logging
- Personalized responses
- User-specific data access

## Docker Deployment

### Build Image

```bash
docker build -t mcp-oauth-gateway .
```

### Run Container

```bash
docker run -p 8080:8080 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -e GOOGLE_CLIENT_ID="your-id" \
  -e GOOGLE_CLIENT_SECRET="your-secret" \
  mcp-oauth-gateway
```

## API Endpoints

### OAuth 2.1 Endpoints

- `GET /.well-known/oauth-authorization-server` - Server metadata
- `GET /.well-known/oauth-protected-resource` - Resource metadata  
- `GET /oauth/authorize` - Authorization endpoint
- `POST /oauth/token` - Token endpoint
- `POST /oauth/register` - Dynamic client registration

### Service Endpoints

- `GET /services` - List available services
- `GET /services/{service-id}` - Get service info
- `ALL /{service-id}/mcp` - MCP service proxy

### Utility Endpoints

- `GET /` - Gateway information
- `GET /health` - Health check

## Security Features

### OAuth 2.1 Compliance

- PKCE required for all authorization code flows
- Resource parameter binding per RFC 8707
- Proper token audience validation
- Secure redirect URI validation

### Token Security

- JWT tokens with service-specific audience claims
- Short-lived access tokens (1 hour)
- Refresh token rotation for public clients
- Token revocation support

### Provider Security

- Single OAuth provider per gateway instance
- Provider-specific user authentication
- Secure credential storage
- State parameter CSRF protection

## Development

### Running Tests

```bash
# Install test dependencies (included in requirements.txt)
pip install pytest pytest-asyncio pytest-httpx

# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=src

# Run specific test file
pytest tests/test_oauth_server.py -v
```

### Code Style

```bash
# Format and lint code
ruff check src/ demo/ --fix
ruff format src/ demo/
```

### Environment Variables

- `MCP_CONFIG_PATH` - Path to config file
- `MCP_GATEWAY_HOST` - Host override
- `MCP_GATEWAY_PORT` - Port override
- `MCP_DEBUG` - Debug mode
- `GOOGLE_CLIENT_ID` - Google OAuth client ID
- `GOOGLE_CLIENT_SECRET` - Google OAuth client secret
- `GITHUB_CLIENT_ID` - GitHub OAuth client ID
- `GITHUB_CLIENT_SECRET` - GitHub OAuth client secret
- `OKTA_CLIENT_ID` - Okta OAuth client ID
- `OKTA_CLIENT_SECRET` - Okta OAuth client secret
- `OKTA_DOMAIN` - Okta domain (e.g., dev-123.okta.com)

## Architecture

The gateway implements a clean separation of concerns:

- **OAuth Server**: Core OAuth 2.1 authorization server
- **Provider Manager**: External OAuth provider integration
- **Client Registry**: Dynamic client registration and management
- **Token Manager**: JWT token creation and validation
- **MCP Proxy**: Request forwarding with user context injection
- **Metadata Provider**: OAuth metadata endpoint implementation

## License

MIT License - see LICENSE file for details.