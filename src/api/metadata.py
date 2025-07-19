"""OAuth 2.1 metadata endpoints implementation."""

from typing import Any, Dict, List, Optional

from ..config.config import GatewayConfig


class MetadataProvider:
    """Provides OAuth 2.1 metadata endpoints."""

    def __init__(self, config: GatewayConfig):
        self.config = config

    def get_authorization_server_metadata(self) -> Dict[str, Any]:
        """Get OAuth 2.0 Authorization Server Metadata per RFC 8414."""
        return {
            "issuer": self.config.issuer,
            "authorization_endpoint": f"{self.config.issuer}/oauth/authorize",
            "token_endpoint": f"{self.config.issuer}/oauth/token",
            "registration_endpoint": f"{self.config.issuer}/oauth/register",
            "userinfo_endpoint": f"{self.config.issuer}/oauth/userinfo",
            "jwks_uri": f"{self.config.issuer}/oauth/jwks",
            "scopes_supported": self._get_supported_scopes(),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            "resource_parameter_supported": True,
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["HS256", "RS256"],
            "token_endpoint_auth_signing_alg_values_supported": ["HS256", "RS256"],
        }

    def get_protected_resource_metadata(
        self, service_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get OAuth 2.0 Protected Resource Metadata per RFC 9728."""
        base_metadata = {
            "resource": self.config.issuer,
            "authorization_servers": [self.config.issuer],
            "scopes_supported": self._get_supported_scopes(),
            "bearer_methods_supported": ["header"],
            "resource_documentation": f"{self.config.issuer}/services",
        }

        if service_id:
            # Service-specific metadata with canonical MCP URI
            service = self.config.mcp_services.get(service_id)
            if service:
                # Generate canonical URI per RFC 8707 and MCP spec
                canonical_uri = self.get_service_canonical_uri(service_id)
                base_metadata["resource"] = canonical_uri
                base_metadata["scopes_supported"] = (
                    service.scopes or self._get_supported_scopes()
                )

        return base_metadata

    def get_service_canonical_uri(self, service_id: str) -> str:
        """Generate canonical URI for a service per RFC 8707 and MCP spec.

        Returns the canonical URI that should be used as the audience
        for tokens intended for this specific MCP service.

        Format: {issuer}/{service_id}/mcp
        Example: https://gateway.example.com/calculator/mcp
        """
        # Normalize issuer by removing trailing slash
        issuer = self.config.issuer.rstrip("/")
        return f"{issuer}/{service_id}/mcp"

    def get_all_service_canonical_uris(self) -> Dict[str, str]:
        """Get canonical URIs for all configured services."""
        return {
            service_id: self.get_service_canonical_uri(service_id)
            for service_id in self.config.mcp_services.keys()
        }

    def _get_supported_scopes(self) -> List[str]:
        """Get all supported scopes from configured services."""
        scopes = {"read", "write"}  # Default scopes

        for service in self.config.mcp_services.values():
            if service.scopes:
                scopes.update(service.scopes)

        return sorted(scopes)
