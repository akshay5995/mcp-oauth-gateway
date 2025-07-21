# Quick Start

Add OAuth 2.1 authentication to your MCP services in 5 minutes.

## What You Need

- Docker
- OAuth provider (Google, GitHub, etc.)  
- Your MCP service

## Step 1: Get OAuth Credentials

**Google**: [Cloud Console](https://console.cloud.google.com/) → Create OAuth client → Add redirect URI: `http://localhost:8080/oauth/callback`

**GitHub**: Settings → OAuth Apps → New App → Callback: `http://localhost:8080/oauth/callback`

## Step 2: Run Gateway

```bash
# Create config.yaml
cat > config.yaml << EOF
host: "localhost"
port: 8080
issuer: "http://localhost:8080"
session_secret: "dev-secret"

oauth_providers:
  google:
    client_id: "\${GOOGLE_CLIENT_ID}"
    client_secret: "\${GOOGLE_CLIENT_SECRET}"
    scopes: ["openid", "email", "profile"]

mcp_services:
  my-service:
    name: "My MCP Service"
    url: "http://my-service:3001"
    oauth_provider: "google"
    auth_required: true
EOF

# Run gateway
docker run -p 8080:8080 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -e GOOGLE_CLIENT_ID="your-client-id" \
  -e GOOGLE_CLIENT_SECRET="your-client-secret" \
  ghcr.io/akshay5995/mcp-oauth-gateway:latest
```

## Step 3: Test

```bash
curl http://localhost:8080/my-service/mcp
# Should return: 401 Unauthorized + OAuth metadata URL
```

## What Your MCP Service Gets

Your service receives user context headers (**no OAuth tokens**):

```http
GET /mcp HTTP/1.1
Host: my-service:3001
MCP-Protocol-Version: 2025-06-18
x-user-id: google_123456789
x-user-email: user@example.com
x-user-name: John Doe
x-user-provider: google
```

- ✅ User context via `x-user-*` headers
- ❌ No `Authorization: Bearer` tokens (gateway removes them)

## Production

**Environment variables**: Use `${VAR}` for secrets in config.yaml  
**Redis storage**: `storage: { type: "redis" }` for production  
**HTTPS**: Set proper `issuer: "https://..."` URL

## Resources

**Development**: [GitHub repo](https://github.com/akshay5995/mcp-oauth-gateway) · [CLAUDE.md guide](https://github.com/akshay5995/mcp-oauth-gateway/blob/main/CLAUDE.md)  
**MCP Specs**: [Authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) · [Streamable HTTP](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#streamable-http-transport)  
**Architecture**: [Design decisions](./architecture) - why HTTP-only, single provider, etc.