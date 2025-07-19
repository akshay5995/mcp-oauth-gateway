"""External OAuth provider integration."""

from typing import Any, Dict, Optional
from urllib.parse import urlencode

import httpx

from ..config.config import OAuthProviderConfig
from .models import UserInfo


class OAuthProvider:
    """Base OAuth provider class."""

    def __init__(self, config: OAuthProviderConfig):
        self.config = config

    def get_authorization_url(self, state: str, redirect_uri: str) -> str:
        """Get authorization URL for provider."""
        raise NotImplementedError

    async def exchange_code_for_token(
        self, code: str, redirect_uri: str
    ) -> Dict[str, Any]:
        """Exchange authorization code for access token."""
        raise NotImplementedError

    async def get_user_info(self, access_token: str) -> UserInfo:
        """Get user information from provider."""
        raise NotImplementedError


class GoogleOAuthProvider(OAuthProvider):
    """Google OAuth provider."""

    def __init__(self, config: OAuthProviderConfig):
        super().__init__(config)

        # Set default URLs if not provided
        if not self.config.authorization_url:
            self.config.authorization_url = (
                "https://accounts.google.com/o/oauth2/v2/auth"
            )
        if not self.config.token_url:
            self.config.token_url = "https://oauth2.googleapis.com/token"
        if not self.config.userinfo_url:
            self.config.userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"

        # Set default scopes if not provided
        if not self.config.scopes:
            self.config.scopes = ["openid", "email", "profile"]

    def get_authorization_url(self, state: str, redirect_uri: str) -> str:
        """Get Google OAuth authorization URL."""
        params = {
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.config.scopes),
            "state": state,
            "access_type": "offline",  # Google-specific
            "prompt": "consent",  # Force consent screen
        }

        params.update(self.config.extra_params)

        return f"{self.config.authorization_url}?{urlencode(params)}"

    async def exchange_code_for_token(
        self, code: str, redirect_uri: str
    ) -> Dict[str, Any]:
        """Exchange authorization code for Google access token."""
        data = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }

        token_url = self.config.token_url
        if not token_url:
            raise ValueError("Token URL not configured for Google provider")

        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=data)
            response.raise_for_status()
            return response.json()

    async def get_user_info(self, access_token: str) -> UserInfo:
        """Get user information from Google."""
        headers = {"Authorization": f"Bearer {access_token}"}

        userinfo_url = self.config.userinfo_url
        if not userinfo_url:
            raise ValueError("Userinfo URL not configured for Google provider")

        async with httpx.AsyncClient() as client:
            response = await client.get(userinfo_url, headers=headers)
            response.raise_for_status()
            data = response.json()

            return UserInfo(
                id=data.get("id", ""),
                email=data.get("email", ""),
                name=data.get("name", ""),
                provider="google",
                avatar_url=data.get("picture"),
                raw_data=data,
            )


class GitHubOAuthProvider(OAuthProvider):
    """GitHub OAuth provider."""

    def __init__(self, config: OAuthProviderConfig):
        super().__init__(config)

        # Set default URLs if not provided
        if not self.config.authorization_url:
            self.config.authorization_url = "https://github.com/login/oauth/authorize"
        if not self.config.token_url:
            self.config.token_url = "https://github.com/login/oauth/access_token"
        if not self.config.userinfo_url:
            self.config.userinfo_url = "https://api.github.com/user"

        # Set default scopes if not provided
        if not self.config.scopes:
            self.config.scopes = ["user:email"]

    def get_authorization_url(self, state: str, redirect_uri: str) -> str:
        """Get GitHub OAuth authorization URL."""
        params = {
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.config.scopes),
            "state": state,
        }

        params.update(self.config.extra_params)

        return f"{self.config.authorization_url}?{urlencode(params)}"

    async def exchange_code_for_token(
        self, code: str, redirect_uri: str
    ) -> Dict[str, Any]:
        """Exchange authorization code for GitHub access token."""
        data = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        }

        headers = {"Accept": "application/json"}

        token_url = self.config.token_url
        if not token_url:
            raise ValueError("Token URL not configured for GitHub provider")

        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=data, headers=headers)
            response.raise_for_status()
            return response.json()

    async def get_user_info(self, access_token: str) -> UserInfo:
        """Get user information from GitHub."""
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github.v3+json",
        }

        userinfo_url = self.config.userinfo_url
        if not userinfo_url:
            raise ValueError("Userinfo URL not configured for GitHub provider")

        async with httpx.AsyncClient() as client:
            # Get user info
            response = await client.get(userinfo_url, headers=headers)
            response.raise_for_status()
            data = response.json()

            # Get email separately if not public
            email = data.get("email", "")
            if not email:
                email_response = await client.get(
                    "https://api.github.com/user/emails", headers=headers
                )
                if email_response.status_code == 200:
                    emails = email_response.json()
                    primary_email = next(
                        (e["email"] for e in emails if e.get("primary")), ""
                    )
                    email = primary_email

            return UserInfo(
                id=str(data.get("id", "")),
                email=email,
                name=data.get("name", "") or data.get("login", ""),
                provider="github",
                avatar_url=data.get("avatar_url"),
                raw_data=data,
            )


class OktaOAuthProvider(OAuthProvider):
    """Okta OAuth provider."""

    def __init__(self, config: OAuthProviderConfig):
        super().__init__(config)

        # Validate Okta domain is provided
        if not self.config.authorization_url:
            raise ValueError(
                "authorization_url is required for Okta provider (e.g., https://your-domain.okta.com/oauth2/default/v1/authorize)"
            )

        # Set default URLs if not provided (assumes default authorization server)
        base_url = self.config.authorization_url.replace(
            "/oauth2/default/v1/authorize", ""
        )
        if not self.config.token_url:
            self.config.token_url = f"{base_url}/oauth2/default/v1/token"
        if not self.config.userinfo_url:
            self.config.userinfo_url = f"{base_url}/oauth2/default/v1/userinfo"

        # Set default scopes if not provided
        if not self.config.scopes:
            self.config.scopes = ["openid", "email", "profile"]

    def get_authorization_url(self, state: str, redirect_uri: str) -> str:
        """Get Okta OAuth authorization URL."""
        params = {
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.config.scopes),
            "state": state,
        }

        params.update(self.config.extra_params)

        return f"{self.config.authorization_url}?{urlencode(params)}"

    async def exchange_code_for_token(
        self, code: str, redirect_uri: str
    ) -> Dict[str, Any]:
        """Exchange authorization code for Okta access token."""
        data = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        token_url = self.config.token_url
        if not token_url:
            raise ValueError("Token URL not configured for Okta provider")

        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=data, headers=headers)
            response.raise_for_status()
            return response.json()

    async def get_user_info(self, access_token: str) -> UserInfo:
        """Get user information from Okta."""
        headers = {"Authorization": f"Bearer {access_token}"}

        userinfo_url = self.config.userinfo_url
        if not userinfo_url:
            raise ValueError("Userinfo URL not configured for Okta provider")

        async with httpx.AsyncClient() as client:
            response = await client.get(userinfo_url, headers=headers)
            response.raise_for_status()
            data = response.json()

            return UserInfo(
                id=data.get("sub", ""),
                email=data.get("email", ""),
                name=data.get("name", "") or data.get("preferred_username", ""),
                provider="okta",
                avatar_url=data.get("picture"),
                raw_data=data,
            )


class CustomOAuthProvider(OAuthProvider):
    """Custom OAuth provider for other services."""

    def get_authorization_url(self, state: str, redirect_uri: str) -> str:
        """Get custom OAuth authorization URL."""
        if not self.config.authorization_url:
            raise ValueError("authorization_url is required for custom provider")

        params = {
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.config.scopes),
            "state": state,
        }

        params.update(self.config.extra_params)

        return f"{self.config.authorization_url}?{urlencode(params)}"

    async def exchange_code_for_token(
        self, code: str, redirect_uri: str
    ) -> Dict[str, Any]:
        """Exchange authorization code for custom provider access token."""
        if not self.config.token_url:
            raise ValueError("token_url is required for custom provider")

        data = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }

        headers = {"Accept": "application/json"}

        token_url = self.config.token_url
        if not token_url:
            raise ValueError("Token URL not configured for custom provider")

        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=data, headers=headers)
            response.raise_for_status()
            return response.json()

    async def get_user_info(self, access_token: str) -> UserInfo:
        """Get user information from custom provider."""
        userinfo_url = self.config.userinfo_url
        if not userinfo_url:
            raise ValueError("userinfo_url is required for custom provider")

        headers = {"Authorization": f"Bearer {access_token}"}

        async with httpx.AsyncClient() as client:
            response = await client.get(userinfo_url, headers=headers)
            response.raise_for_status()
            data = response.json()

            # Try to extract standard fields
            user_id = data.get("id") or data.get("sub") or data.get("user_id", "")
            email = data.get("email", "")
            name = (
                data.get("name") or data.get("display_name") or data.get("username", "")
            )
            avatar_url = (
                data.get("avatar_url")
                or data.get("picture")
                or data.get("profile_image_url")
            )

            return UserInfo(
                id=str(user_id),
                email=email,
                name=name,
                provider="custom",
                avatar_url=avatar_url,
                raw_data=data,
            )


class ProviderManager:
    """Manages a single OAuth provider per gateway instance.
    
    Due to OAuth 2.1 resource parameter constraints, only one OAuth provider
    can be configured per gateway instance to ensure proper domain-wide authentication.
    """

    def __init__(self, provider_configs: Dict[str, OAuthProviderConfig]):
        # Validate single provider constraint
        if len(provider_configs) > 1:
            raise ValueError(
                f"Only one OAuth provider can be configured per gateway instance. "
                f"Found {len(provider_configs)} providers: {list(provider_configs.keys())}. "
                f"Please configure only one provider due to OAuth 2.1 resource parameter constraints."
            )
        
        self.providers: Dict[str, OAuthProvider] = {}
        self.primary_provider_id: str = ""
        
        # Initialize provider if one is configured
        if provider_configs:
            # Initialize the single provider
            for provider_id, config in provider_configs.items():
                self.providers[provider_id] = self._create_provider(provider_id, config)
                self.primary_provider_id = provider_id
                break  # Only process the first (and only) provider

    def _create_provider(
        self, provider_id: str, config: OAuthProviderConfig
    ) -> OAuthProvider:
        """Create provider instance based on type."""
        provider_map = {
            "google": GoogleOAuthProvider,
            "github": GitHubOAuthProvider,
            "okta": OktaOAuthProvider,
            "custom": CustomOAuthProvider,
        }

        provider_class = provider_map.get(provider_id.lower(), CustomOAuthProvider)
        return provider_class(config)

    def get_provider(self, provider_id: str) -> Optional[OAuthProvider]:
        """Get provider by ID."""
        return self.providers.get(provider_id)

    def get_provider_for_service(
        self, service_oauth_provider: Optional[str]
    ) -> Optional[OAuthProvider]:
        """Get provider for a specific service.
        
        Returns None if no provider is configured (for public-only gateways)
        or if the service doesn't specify a provider.
        """
        if not service_oauth_provider:
            return None
            
        if not self.primary_provider_id:
            raise ValueError(
                f"Service requests provider '{service_oauth_provider}' but no "
                f"OAuth providers are configured. This gateway only supports public services."
            )
            
        if service_oauth_provider != self.primary_provider_id:
            raise ValueError(
                f"Service requests provider '{service_oauth_provider}' but only "
                f"'{self.primary_provider_id}' is configured. All services must use "
                f"the same OAuth provider in a single gateway instance."
            )
        return self.get_provider(service_oauth_provider)
    
    def get_primary_provider_id(self) -> str:
        """Get the ID of the configured OAuth provider."""
        return self.primary_provider_id
    
    def get_primary_provider(self) -> Optional[OAuthProvider]:
        """Get the configured OAuth provider."""
        return self.get_provider(self.primary_provider_id)

    def generate_callback_state(self, provider_id: str, oauth_state: str) -> str:
        """Generate state for provider callback.
        
        Validates that the provider_id matches the configured provider.
        """
        if not self.primary_provider_id:
            raise ValueError(
                f"Cannot generate callback state for provider '{provider_id}'. "
                f"No OAuth providers are configured."
            )
            
        if provider_id != self.primary_provider_id:
            raise ValueError(
                f"Cannot generate callback state for provider '{provider_id}'. "
                f"Only '{self.primary_provider_id}' is configured."
            )
        # Combine provider ID with OAuth state for callback routing
        return f"{provider_id}:{oauth_state}"

    def parse_callback_state(self, callback_state: str) -> tuple[str, str]:
        """Parse provider callback state."""
        if ":" in callback_state:
            provider_id, oauth_state = callback_state.split(":", 1)
            return provider_id, oauth_state
        else:
            # Fallback for invalid state
            return "", callback_state

    async def handle_provider_callback(
        self, provider_id: str, code: str, redirect_uri: str
    ) -> UserInfo:
        """Handle OAuth callback from provider.
        
        Validates that the provider_id matches the configured provider.
        """
        if not self.primary_provider_id:
            raise ValueError(
                f"Callback received for provider '{provider_id}' but no "
                f"OAuth providers are configured."
            )
            
        if provider_id != self.primary_provider_id:
            raise ValueError(
                f"Callback received for provider '{provider_id}' but only "
                f"'{self.primary_provider_id}' is configured."
            )
        
        provider = self.get_provider(provider_id)
        if not provider:
            raise ValueError(f"Unknown provider: {provider_id}")

        # Exchange code for token
        token_data = await provider.exchange_code_for_token(code, redirect_uri)
        access_token = token_data.get("access_token")

        if not access_token:
            raise ValueError("No access token received from provider")

        # Get user info
        user_info = await provider.get_user_info(access_token)

        return user_info
