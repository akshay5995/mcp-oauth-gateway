"""Data models for OAuth authentication."""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class GrantType(str, Enum):
    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    REFRESH_TOKEN = "refresh_token"


class ResponseType(str, Enum):
    CODE = "code"


class TokenType(str, Enum):
    BEARER = "Bearer"


@dataclass
class UserInfo:
    """User information from OAuth provider."""

    id: str
    email: str
    name: str
    provider: str
    avatar_url: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ClientInfo:
    """OAuth client information."""

    client_id: str
    client_secret: str
    client_name: str
    redirect_uris: List[str]
    grant_types: List[str] = field(default_factory=lambda: ["authorization_code"])
    response_types: List[str] = field(default_factory=lambda: ["code"])
    token_endpoint_auth_method: str = "client_secret_basic"
    scope: str = ""
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0  # 0 means no expiration


@dataclass
class AuthorizationCode:
    """Authorization code information."""

    code: str
    client_id: str
    user_id: str
    redirect_uri: str
    scope: str
    resource: Optional[str]
    code_challenge: Optional[str]
    code_challenge_method: Optional[str]
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 600)  # 10 minutes

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


@dataclass
class AccessToken:
    """Access token information."""

    token: str
    client_id: str
    user_id: str
    scope: str
    resource: Optional[str]
    token_type: str = "Bearer"
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 3600)  # 1 hour

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def is_valid_for_resource(self, resource_url: str) -> bool:
        """Check if token is valid for a specific resource."""
        if not self.resource:
            return True  # Backward compatibility
        return self.resource == resource_url


@dataclass
class RefreshToken:
    """Refresh token information."""

    token: str
    client_id: str
    user_id: str
    scope: str
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(
        default_factory=lambda: time.time() + 86400 * 30
    )  # 30 days

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


@dataclass
class OAuthState:
    """OAuth state for authorization flow."""

    state: str  # Internal provider state (for our tracking)
    client_state: str  # Original client state (to return to client)
    client_id: str
    redirect_uri: str
    scope: str
    resource: Optional[str]
    code_challenge: Optional[str]
    code_challenge_method: Optional[str]
    provider: str
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 300)  # 5 minutes

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


# Request/Response models for API endpoints


@dataclass
class AuthorizeRequest:
    """Authorization endpoint request."""

    response_type: str
    client_id: str
    redirect_uri: str
    scope: Optional[str] = None
    state: Optional[str] = None
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None
    resource: Optional[str] = None


@dataclass
class TokenRequest:
    """Token endpoint request."""

    grant_type: str
    client_id: str
    client_secret: Optional[str] = None
    code: Optional[str] = None
    redirect_uri: Optional[str] = None
    code_verifier: Optional[str] = None
    resource: Optional[str] = None
    scope: Optional[str] = None
    refresh_token: Optional[str] = None


@dataclass
class ClientRegistrationRequest:
    """Client registration request."""

    client_name: str
    redirect_uris: List[str]
    grant_types: List[str] = field(default_factory=lambda: ["authorization_code"])
    response_types: List[str] = field(default_factory=lambda: ["code"])
    token_endpoint_auth_method: str = "client_secret_basic"
    scope: str = ""


@dataclass
class TokenResponse:
    """Token endpoint response."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    scope: Optional[str] = None
    resource: Optional[str] = None
    refresh_token: Optional[str] = None


@dataclass
class ErrorResponse:
    """OAuth error response."""

    error: str
    error_description: Optional[str] = None
    error_uri: Optional[str] = None
