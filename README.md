# MCP OAuth Gateway

A OAuth 2.1 authorization server that provides transparent authentication and authorization for Model Context Protocol (MCP) services.

## Features

- **Transparent MCP Access**: Users access MCP services via simple URLs without manual OAuth setup
- **Single OAuth Provider**: Uses one OAuth provider for all services (Google, GitHub, Okta, or custom)
- **Full MCP Compliance**: Implements complete MCP authorization specification with OAuth 2.1
- **Dynamic Client Registration**: Automatic client registration per RFC 7591
- **User Context Injection**: Seamless user context headers for backend MCP services
- **Resource-Specific Tokens**: RFC 8707 audience binding prevents token misuse
- **Configurable Storage**: Memory (dev), Redis (production), Vault (enterprise) backends
- **Production Ready**: Comprehensive testing, Docker support, scalable architecture

📖 **[View Detailed Architecture](ARCHITECTURE.md)** | 📚 **[Developer Guide](CLAUDE.md)**

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt

# Optional: For Redis storage backend with modern library
pip install -r requirements-redis.txt
```

### 2. Configure OAuth Provider

**Important**: Configure only ONE OAuth provider per gateway instance.

Set up environment variables for Google OAuth:

```bash
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"
```

📚 **Other providers**: See [Configuration Guide](CLAUDE.md#configuring-oauth-provider) for GitHub, Okta, and custom OAuth providers

### 3. Create Basic Configuration

Create a `config.yaml` file:

```yaml
# Gateway settings
host: "localhost"
port: 8080
issuer: "http://localhost:8080"
session_secret: "your-dev-secret-change-in-production"
debug: true

# OAuth provider
oauth_providers:
  google:
    client_id: "${GOOGLE_CLIENT_ID}"
    client_secret: "${GOOGLE_CLIENT_SECRET}"
    scopes: ["openid", "email", "profile"]

# Example service (replace with your MCP service)
mcp_services:
  calculator:
    name: "Calculator Service"
    url: "http://localhost:3001"
    oauth_provider: "google"
    auth_required: true
    scopes: ["read", "calculate"]
```

### 4. Run the Gateway

```bash
python -m src.gateway --config config.yaml --debug
```

### 5. Test the Setup

Access your service to verify it's working:
```bash
curl http://localhost:8080/calculator/mcp
# Should return 401 with OAuth authentication info
```

### 6. Add Your Services

Replace the example service in `config.yaml` with your actual MCP services. All services must use the same OAuth provider.

📚 **[Complete Configuration Guide](CLAUDE.md#adding-new-mcp-services)** - Detailed service configuration options

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
  google:
    client_id: "${GOOGLE_CLIENT_ID}"
    client_secret: "${GOOGLE_CLIENT_SECRET}"
    scopes: ["openid", "email", "profile"]
```

📚 **Alternative providers**: See [Configuration Guide](CLAUDE.md#configuring-oauth-provider) for GitHub, Okta, and custom OAuth provider examples

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

### Quick Start with Memory Storage

```bash
# Build image
docker build -t mcp-oauth-gateway .

# Run with memory storage (development)
docker run -p 8080:8080 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -e GOOGLE_CLIENT_ID="your-google-client-id" \
  -e GOOGLE_CLIENT_SECRET="your-google-client-secret" \
  mcp-oauth-gateway
```

### Production with Redis Storage

```bash
# Start Redis container
docker run -d --name redis \
  -p 6379:6379 \
  redis:alpine redis-server --requirepass mypassword

# Update config.yaml for Redis
cat >> config.yaml << EOF
storage:
  type: "redis"
  redis:
    host: "host.docker.internal"  # or Redis container IP
    port: 6379
    password: "\${REDIS_PASSWORD}"
EOF

# Run gateway with Redis
docker run -p 8080:8080 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -e GOOGLE_CLIENT_ID="your-google-client-id" \
  -e GOOGLE_CLIENT_SECRET="your-google-client-secret" \
  -e REDIS_PASSWORD="mypassword" \
  mcp-oauth-gateway
```

### Enterprise with Vault Storage

```bash
# Start Vault container (dev mode)
docker run -d --name vault \
  -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID="myroot" \
  vault:latest

# Update config.yaml for Vault
cat >> config.yaml << EOF
storage:
  type: "vault"
  vault:
    url: "http://host.docker.internal:8200"
    token: "\${VAULT_TOKEN}"
    mount_point: "secret"
    path_prefix: "mcp-gateway"
EOF

# Run gateway with Vault
docker run -p 8080:8080 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -e GOOGLE_CLIENT_ID="your-google-client-id" \
  -e GOOGLE_CLIENT_SECRET="your-google-client-secret" \
  -e VAULT_TOKEN="myroot" \
  mcp-oauth-gateway
```

### Docker Compose Example

```yaml
# docker-compose.yml
version: '3.8'
services:
  mcp-gateway:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./config.yaml:/app/config.yaml
    environment:
      - GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}
      - GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}
      - REDIS_PASSWORD=mypassword
    depends_on:
      - redis

  redis:
    image: redis:alpine
    command: redis-server --requirepass mypassword
    ports:
      - "6379:6379"
```

```bash
# Start with Docker Compose
docker-compose up -d
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

#### Gateway Configuration
- `MCP_CONFIG_PATH` - Path to config file
- `MCP_GATEWAY_HOST` - Host override
- `MCP_GATEWAY_PORT` - Port override
- `MCP_DEBUG` - Debug mode

#### OAuth Providers
- `GOOGLE_CLIENT_ID` - Google OAuth client ID
- `GOOGLE_CLIENT_SECRET` - Google OAuth client secret
- `GITHUB_CLIENT_ID` - GitHub OAuth client ID
- `GITHUB_CLIENT_SECRET` - GitHub OAuth client secret
- `OKTA_CLIENT_ID` - Okta OAuth client ID
- `OKTA_CLIENT_SECRET` - Okta OAuth client secret
- `OKTA_DOMAIN` - Okta domain (e.g., dev-123.okta.com)

#### Storage Backends
- `REDIS_HOST` - Redis server host
- `REDIS_PORT` - Redis server port
- `REDIS_PASSWORD` - Redis authentication password
- `REDIS_SSL` - Enable Redis SSL (true/false)
- `VAULT_URL` - Vault server URL
- `VAULT_TOKEN` - Vault authentication token
- `VAULT_MOUNT_POINT` - Vault KV mount point
- `VAULT_PATH_PREFIX` - Vault secret path prefix

## Storage Backends

Choose the appropriate storage backend for your deployment:

### Memory Storage (Default)
```yaml
storage:
  type: "memory"
```
✅ **Best for**: Development, testing, single-instance demos  
❌ **Limitations**: Data lost on restart, single-instance only

### Redis Storage (Production)
```yaml
storage:
  type: "redis"
  redis:
    host: "${REDIS_HOST:-localhost}"
    port: 6379
    password: "${REDIS_PASSWORD}"
    ssl: true
    max_connections: 20
```
✅ **Best for**: Production deployments, horizontal scaling  
✅ **Features**: Persistent storage, multi-instance support, connection pooling  
✅ **Compatibility**: Uses modern redis-py library for Python 3.11+ compatibility

### Vault Storage (Enterprise)
```yaml
storage:
  type: "vault"
  vault:
    url: "${VAULT_URL}"
    token: "${VAULT_TOKEN}"
    mount_point: "secret"
    path_prefix: "mcp-gateway"
    auth_method: "token"  # or "approle", "kubernetes"
```
✅ **Best for**: Enterprise environments, compliance requirements  
✅ **Features**: Encrypted at rest, audit logging, fine-grained access control

## Architecture

The gateway implements a clean separation of concerns:

- **OAuth Server**: Core OAuth 2.1 authorization server
- **Provider Manager**: External OAuth provider integration  
- **Client Registry**: Dynamic client registration and management
- **Token Manager**: JWT token creation and validation
- **Storage Manager**: Configurable storage backends with fallback
- **MCP Proxy**: Request forwarding with user context injection
- **Metadata Provider**: OAuth metadata endpoint implementation

📖 **[View Complete Architecture Documentation](ARCHITECTURE.md)**

## Troubleshooting

Having issues? Check the troubleshooting guide:

📚 **[Troubleshooting Guide](CLAUDE.md#troubleshooting)** - Common issues and solutions including:
- Origin validation errors (403 responses)
- MCP protocol version issues (400 responses) 
- Token audience validation problems (401 responses)
- Configuration and deployment issues

## Quick Links

- 📖 **[Architecture Documentation](ARCHITECTURE.md)** - Comprehensive system design and data flows
- 📚 **[Developer Guide](CLAUDE.md)** - Detailed development instructions and API reference
- 🧪 **[Testing Guide](tests/)** - 197+ test cases covering all components
- 🐳 **[Docker Examples](docker-compose.yml)** - Production deployment patterns

## License

MIT License - see LICENSE file for details.