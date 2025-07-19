"""Configuration management for MCP OAuth Gateway."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class OAuthProviderConfig:
    """OAuth provider configuration."""

    client_id: str
    client_secret: str
    scopes: List[str] = field(default_factory=list)
    authorization_url: Optional[str] = None
    token_url: Optional[str] = None
    userinfo_url: Optional[str] = None
    extra_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class McpServiceConfig:
    """MCP service configuration."""

    name: str
    url: str
    oauth_provider: Optional[str] = None
    auth_required: bool = True
    scopes: List[str] = field(default_factory=list)
    timeout: int = 30000


@dataclass
class CorsConfig:
    """CORS configuration."""

    allow_origins: List[str] = field(default_factory=lambda: ["*"])
    allow_credentials: bool = True
    allow_methods: List[str] = field(
        default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    )
    allow_headers: List[str] = field(default_factory=lambda: ["*"])


@dataclass
class GatewayConfig:
    """Main gateway configuration."""

    host: str = "0.0.0.0"
    port: int = 8080
    issuer: str = "http://localhost:8080"
    session_secret: str = "change-this-in-production"
    debug: bool = False

    oauth_providers: Dict[str, OAuthProviderConfig] = field(default_factory=dict)
    mcp_services: Dict[str, McpServiceConfig] = field(default_factory=dict)
    cors: CorsConfig = field(default_factory=CorsConfig)


class ConfigManager:
    """Manages gateway configuration."""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._find_config_file()
        self.config: Optional[GatewayConfig] = None

    def _find_config_file(self) -> str:
        """Find configuration file in standard locations."""
        possible_paths = [
            os.getenv("MCP_CONFIG_PATH"),
            "config.yaml",
            "config.yml",
            os.path.expanduser("~/.mcp-gateway/config.yaml"),
            "/etc/mcp-gateway/config.yaml",
        ]

        for path in possible_paths:
            if path and os.path.exists(path):
                return path

        return "config.yaml"  # Default

    def load_config(self) -> GatewayConfig:
        """Load configuration from file."""
        config_file = Path(self.config_path)

        if not config_file.exists():
            # Create default config
            self.config = GatewayConfig()
            self.save_config()
            return self.config

        with open(config_file) as f:
            data = yaml.safe_load(f) or {}

        # Parse OAuth providers with single provider validation
        oauth_providers = {}
        provider_data_dict = data.get("oauth_providers", {})
        
        # Validate single provider constraint
        if len(provider_data_dict) > 1:
            provider_ids = list(provider_data_dict.keys())
            raise ValueError(
                f"Configuration error: Only one OAuth provider can be configured per gateway instance. "
                f"Found {len(provider_data_dict)} providers: {provider_ids}. "
                f"Please configure only one provider due to OAuth 2.1 resource parameter constraints."
            )
        
        for provider_id, provider_data in provider_data_dict.items():
            oauth_providers[provider_id] = OAuthProviderConfig(
                client_id=provider_data["client_id"],
                client_secret=provider_data["client_secret"],
                scopes=provider_data.get("scopes", []),
                authorization_url=provider_data.get("authorization_url"),
                token_url=provider_data.get("token_url"),
                userinfo_url=provider_data.get("userinfo_url"),
                extra_params=provider_data.get("extra_params", {}),
            )

        # Parse MCP services with provider validation
        mcp_services = {}
        configured_provider_id = None
        if oauth_providers:
            configured_provider_id = list(oauth_providers.keys())[0]
        
        for service_id, service_data in data.get("mcp_services", {}).items():
            service_auth_required = service_data.get("auth_required", True)
            service_provider = service_data.get("oauth_provider")
            
            # For authenticated services, ensure provider is specified and matches configured provider
            if service_auth_required:
                if not service_provider:
                    raise ValueError(
                        f"Configuration error: Service '{service_id}' requires authentication "
                        f"but no oauth_provider is specified."
                    )
                
                if configured_provider_id and service_provider != configured_provider_id:
                    raise ValueError(
                        f"Configuration error: Service '{service_id}' specifies OAuth provider '{service_provider}' "
                        f"but only '{configured_provider_id}' is configured. All authenticated services must use "
                        f"the same OAuth provider in a single gateway instance."
                    )
            
            # For public services, oauth_provider is optional
            mcp_services[service_id] = McpServiceConfig(
                name=service_data["name"],
                url=service_data["url"],
                oauth_provider=service_provider,
                auth_required=service_auth_required,
                scopes=service_data.get("scopes", []),
                timeout=service_data.get("timeout", 30000),
            )

        # Parse CORS configuration
        cors_data = data.get("cors", {})
        cors_config = CorsConfig(
            allow_origins=cors_data.get("allow_origins", ["*"]),
            allow_credentials=cors_data.get("allow_credentials", True),
            allow_methods=cors_data.get(
                "allow_methods", ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
            ),
            allow_headers=cors_data.get("allow_headers", ["*"]),
        )

        # Final validation: ensure at least one OAuth provider if any service requires auth
        auth_required_services = [
            service_id for service_id, service in mcp_services.items() 
            if service.auth_required
        ]
        if auth_required_services and not oauth_providers:
            raise ValueError(
                f"Configuration error: Services {auth_required_services} require authentication "
                f"but no OAuth providers are configured. Please add an OAuth provider configuration."
            )
        
        # For authenticated services, ensure all use the same provider (if providers exist)
        if oauth_providers and auth_required_services:
            configured_provider = list(oauth_providers.keys())[0]
            for service_id in auth_required_services:
                service = mcp_services[service_id]
                if service.oauth_provider != configured_provider:
                    raise ValueError(
                        f"Configuration error: All authenticated services must use the same OAuth provider. "
                        f"Service '{service_id}' uses '{service.oauth_provider}' but '{configured_provider}' is configured."
                    )
        
        self.config = GatewayConfig(
            host=os.getenv("MCP_GATEWAY_HOST", data.get("host", "0.0.0.0")),
            port=int(os.getenv("MCP_GATEWAY_PORT", data.get("port", 8080))),
            issuer=os.getenv("MCP_ISSUER", data.get("issuer", "http://localhost:8080")),
            session_secret=os.getenv(
                "MCP_SESSION_SECRET",
                data.get("session_secret", "change-this-in-production"),
            ),
            debug=os.getenv("MCP_DEBUG", str(data.get("debug", False))).lower()
            == "true",
            oauth_providers=oauth_providers,
            mcp_services=mcp_services,
            cors=cors_config,
        )

        return self.config

    def save_config(self) -> None:
        """Save configuration to file."""
        if not self.config:
            return

        data = {
            "host": self.config.host,
            "port": self.config.port,
            "issuer": self.config.issuer,
            "session_secret": self.config.session_secret,
            "debug": self.config.debug,
            "cors": {
                "allow_origins": self.config.cors.allow_origins,
                "allow_credentials": self.config.cors.allow_credentials,
                "allow_methods": self.config.cors.allow_methods,
                "allow_headers": self.config.cors.allow_headers,
            },
            "oauth_providers": {},
            "mcp_services": {},
        }

        # Add OAuth providers
        for provider_id, provider in self.config.oauth_providers.items():
            data["oauth_providers"][provider_id] = {
                "client_id": provider.client_id,
                "client_secret": provider.client_secret,
                "scopes": provider.scopes,
                "authorization_url": provider.authorization_url,
                "token_url": provider.token_url,
                "userinfo_url": provider.userinfo_url,
                "extra_params": provider.extra_params,
            }

        # Add MCP services
        for service_id, service in self.config.mcp_services.items():
            data["mcp_services"][service_id] = {
                "name": service.name,
                "url": service.url,
                "oauth_provider": service.oauth_provider,
                "auth_required": service.auth_required,
                "scopes": service.scopes,
                "timeout": service.timeout,
            }

        with open(self.config_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, indent=2)

    def get_config(self) -> GatewayConfig:
        """Get current configuration."""
        if not self.config:
            self.config = self.load_config()
        return self.config

    def get_service(self, service_id: str) -> Optional[McpServiceConfig]:
        """Get a specific service configuration."""
        config = self.get_config()
        return config.mcp_services.get(service_id)

    def get_provider(self, provider_id: str) -> Optional[OAuthProviderConfig]:
        """Get a specific OAuth provider configuration."""
        config = self.get_config()
        return config.oauth_providers.get(provider_id)
