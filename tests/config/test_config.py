"""Tests for configuration management functionality."""

import os
import tempfile
from unittest.mock import patch

import pytest

from src.config.config import (
    ConfigManager,
    CorsConfig,
    GatewayConfig,
    McpServiceConfig,
    OAuthProviderConfig,
)


class TestConfigManager:
    """Test cases for ConfigManager."""

    def test_config_manager_initialization_with_path(self):
        """Test config manager initialization with explicit path."""
        config_manager = ConfigManager("/path/to/config.yaml")
        assert config_manager.config_path == "/path/to/config.yaml"
        assert config_manager.config is None

    def test_config_manager_initialization_without_path(self):
        """Test config manager initialization without explicit path."""
        with patch.object(
            ConfigManager, "_find_config_file", return_value="config.yaml"
        ):
            config_manager = ConfigManager()
            assert config_manager.config_path == "config.yaml"

    @patch.dict(os.environ, {"MCP_CONFIG_PATH": "/env/config.yaml"})
    @patch("os.path.exists")
    def test_find_config_file_from_env(self, mock_exists):
        """Test finding config file from environment variable."""
        mock_exists.side_effect = lambda path: path == "/env/config.yaml"

        config_manager = ConfigManager()
        path = config_manager._find_config_file()

        assert path == "/env/config.yaml"

    @patch("os.path.exists")
    def test_find_config_file_current_directory(self, mock_exists):
        """Test finding config file in current directory."""
        mock_exists.side_effect = lambda path: path == "config.yaml"

        config_manager = ConfigManager()
        path = config_manager._find_config_file()

        assert path == "config.yaml"

    @patch("os.path.exists")
    def test_find_config_file_default(self, mock_exists):
        """Test default config file path when none exist."""
        mock_exists.return_value = False

        config_manager = ConfigManager()
        path = config_manager._find_config_file()

        assert path == "config.yaml"  # Default fallback

    def test_load_config_file_not_exists(self):
        """Test loading config when file doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "nonexistent.yaml")
            config_manager = ConfigManager(config_path)

            config = config_manager.load_config()

            assert isinstance(config, GatewayConfig)
            assert config.host == "0.0.0.0"
            assert config.port == 8080
            assert config.issuer == "http://localhost:8080"
            assert config.session_secret == "change-this-in-production"
            assert config.debug is False

            # Check that file was created
            assert os.path.exists(config_path)

    def test_load_config_from_yaml(self):
        """Test loading config from YAML file."""
        yaml_content = """
host: "127.0.0.1"
port: 9090
issuer: "https://gateway.example.com"
session_secret: "test-secret"
debug: true

cors:
  allow_origins: ["https://example.com"]
  allow_credentials: false
  allow_methods: ["GET", "POST"]
  allow_headers: ["Authorization", "Content-Type"]
  expose_headers: ["MCP-Session-ID", "X-Request-ID"]

oauth_providers:
  github:
    client_id: "github_client_id"
    client_secret: "github_client_secret"
    scopes: ["user:email"]
    extra_params:
      prompt: "consent"

mcp_services:
  calculator:
    name: "Calculator Service"
    url: "http://calc.example.com/mcp"
    oauth_provider: "github"
    auth_required: true
    scopes: ["read", "calculate"]
    timeout: 25000
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            config_path = f.name

        try:
            config_manager = ConfigManager(config_path)
            config = config_manager.load_config()

            # Check main config
            assert config.host == "127.0.0.1"
            assert config.port == 9090
            assert config.issuer == "https://gateway.example.com"
            assert config.session_secret == "test-secret"
            assert config.debug is True

            # Check CORS config
            assert config.cors.allow_origins == ["https://example.com"]
            assert config.cors.allow_credentials is False
            assert config.cors.allow_methods == ["GET", "POST"]
            assert config.cors.allow_headers == ["Authorization", "Content-Type"]
            assert config.cors.expose_headers == ["MCP-Session-ID", "X-Request-ID"]

            # Check OAuth provider
            assert "github" in config.oauth_providers
            github_provider = config.oauth_providers["github"]
            assert github_provider.client_id == "github_client_id"
            assert github_provider.client_secret == "github_client_secret"
            assert github_provider.scopes == ["user:email"]
            assert github_provider.extra_params == {"prompt": "consent"}

            # Check MCP service
            assert "calculator" in config.mcp_services
            calc_service = config.mcp_services["calculator"]
            assert calc_service.name == "Calculator Service"
            assert calc_service.url == "http://calc.example.com/mcp"
            assert calc_service.oauth_provider == "github"
            assert calc_service.auth_required is True
            assert calc_service.scopes == ["read", "calculate"]
            assert calc_service.timeout == 25000

        finally:
            os.unlink(config_path)

    @patch.dict(
        os.environ,
        {
            "MCP_GATEWAY_HOST": "env.example.com",
            "MCP_GATEWAY_PORT": "8081",
            "MCP_ISSUER": "https://env.example.com",
            "MCP_SESSION_SECRET": "env-secret",
            "MCP_DEBUG": "true",
        },
    )
    def test_load_config_with_env_overrides(self):
        """Test loading config with environment variable overrides."""
        yaml_content = """
host: "127.0.0.1"
port: 9090
issuer: "https://gateway.example.com"
session_secret: "file-secret"
debug: false
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            config_path = f.name

        try:
            config_manager = ConfigManager(config_path)
            config = config_manager.load_config()

            # Environment variables should override file values
            assert config.host == "env.example.com"
            assert config.port == 8081
            assert config.issuer == "https://env.example.com"
            assert config.session_secret == "env-secret"
            assert config.debug is True

        finally:
            os.unlink(config_path)

    def test_load_config_empty_yaml(self):
        """Test loading config from empty YAML file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("")  # Empty file
            config_path = f.name

        try:
            config_manager = ConfigManager(config_path)
            config = config_manager.load_config()

            # Should use defaults
            assert config.host == "0.0.0.0"
            assert config.port == 8080
            assert config.issuer == "http://localhost:8080"
            assert len(config.oauth_providers) == 0
            assert len(config.mcp_services) == 0

        finally:
            os.unlink(config_path)

    def test_save_config(self):
        """Test saving config to file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "test_config.yaml")
            config_manager = ConfigManager(config_path)

            # Create a config with some data
            config_manager.config = GatewayConfig(
                host="test.example.com",
                port=8081,
                issuer="https://test.example.com",
                session_secret="test-secret",
                debug=True,
                oauth_providers={
                    "test_provider": OAuthProviderConfig(
                        client_id="test_id",
                        client_secret="test_secret",
                        scopes=["read"],
                        authorization_url="https://auth.example.com",
                        extra_params={"param": "value"},
                    )
                },
                mcp_services={
                    "test_service": McpServiceConfig(
                        name="Test Service",
                        url="http://test.example.com/mcp",
                        oauth_provider="test_provider",
                        auth_required=False,
                        scopes=["read"],
                        timeout=20000,
                    )
                },
                cors=CorsConfig(
                    allow_origins=["https://test.com"], allow_credentials=False
                ),
            )

            config_manager.save_config()

            # Verify file was created and can be loaded
            assert os.path.exists(config_path)

            # Load the saved config
            new_manager = ConfigManager(config_path)
            loaded_config = new_manager.load_config()

            assert loaded_config.host == "test.example.com"
            assert loaded_config.port == 8081
            assert loaded_config.issuer == "https://test.example.com"
            assert loaded_config.session_secret == "test-secret"
            assert loaded_config.debug is True

            # Check provider was saved
            assert "test_provider" in loaded_config.oauth_providers
            provider = loaded_config.oauth_providers["test_provider"]
            assert provider.client_id == "test_id"
            assert provider.authorization_url == "https://auth.example.com"
            assert provider.extra_params == {"param": "value"}

            # Check service was saved
            assert "test_service" in loaded_config.mcp_services
            service = loaded_config.mcp_services["test_service"]
            assert service.name == "Test Service"
            assert service.auth_required is False
            assert service.timeout == 20000

    def test_save_config_no_config(self):
        """Test saving when no config is set."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "test_config.yaml")
            config_manager = ConfigManager(config_path)

            # Don't set any config
            config_manager.save_config()

            # Should not create file
            assert not os.path.exists(config_path)

    def test_get_config_lazy_load(self):
        """Test lazy loading of config via get_config."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("host: '192.168.1.1'\nport: 8082")
            config_path = f.name

        try:
            config_manager = ConfigManager(config_path)

            # Config should be None initially
            assert config_manager.config is None

            # get_config should load it
            config = config_manager.get_config()
            assert config_manager.config is not None
            assert config.host == "192.168.1.1"
            assert config.port == 8082

            # Second call should return same instance
            config2 = config_manager.get_config()
            assert config is config2

        finally:
            os.unlink(config_path)

    def test_get_service_exists(self):
        """Test getting existing service configuration."""
        config_manager = ConfigManager()
        config_manager.config = GatewayConfig(
            mcp_services={
                "test_service": McpServiceConfig(
                    name="Test Service",
                    url="http://test.example.com/mcp",
                    oauth_provider="github",
                )
            }
        )

        service = config_manager.get_service("test_service")
        assert service is not None
        assert service.name == "Test Service"
        assert service.url == "http://test.example.com/mcp"

    def test_get_service_not_exists(self):
        """Test getting non-existent service configuration."""
        config_manager = ConfigManager()
        config_manager.config = GatewayConfig()

        service = config_manager.get_service("nonexistent_service")
        assert service is None

    def test_get_provider_exists(self):
        """Test getting existing OAuth provider configuration."""
        config_manager = ConfigManager()
        config_manager.config = GatewayConfig(
            oauth_providers={
                "test_provider": OAuthProviderConfig(
                    client_id="test_id", client_secret="test_secret"
                )
            }
        )

        provider = config_manager.get_provider("test_provider")
        assert provider is not None
        assert provider.client_id == "test_id"
        assert provider.client_secret == "test_secret"

    def test_get_provider_not_exists(self):
        """Test getting non-existent OAuth provider configuration."""
        config_manager = ConfigManager()
        config_manager.config = GatewayConfig()

        provider = config_manager.get_provider("nonexistent_provider")
        assert provider is None

    @patch.dict(
        os.environ,
        {
            "GITHUB_CLIENT_ID": "github_test_id",
            "GITHUB_CLIENT_SECRET": "github_test_secret",
            "REDIS_HOST": "redis.test.com",
            "REDIS_PORT": "6380",
            "VAULT_TOKEN": "vault_test_token",
        },
    )
    def test_env_var_substitution_required_vars(self):
        """Test environment variable substitution for required variables."""
        yaml_content = """
host: "127.0.0.1"
port: 8080
issuer: "http://localhost:8080"
session_secret: "test-secret"

storage:
  type: "redis"
  redis:
    host: "${REDIS_HOST}"
    port: "${REDIS_PORT}"
  vault:
    token: "${VAULT_TOKEN}"

oauth_providers:
  github:
    client_id: "${GITHUB_CLIENT_ID}"
    client_secret: "${GITHUB_CLIENT_SECRET}"
    scopes: ["user:email"]

mcp_services:
  calculator:
    name: "Calculator Service"
    url: "http://localhost:3001/mcp"
    oauth_provider: "github"
    auth_required: true
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            config_path = f.name

        try:
            config_manager = ConfigManager(config_path)
            config = config_manager.load_config()

            # Check that environment variables were substituted
            github_provider = config.oauth_providers["github"]
            assert github_provider.client_id == "github_test_id"
            assert github_provider.client_secret == "github_test_secret"

            # Check storage config
            assert config.storage.redis.host == "redis.test.com"
            assert config.storage.redis.port == 6380  # Should be converted to int
            assert config.storage.vault.token == "vault_test_token"

        finally:
            os.unlink(config_path)

    @patch.dict(os.environ, {"REDIS_HOST": "redis.prod.com"}, clear=False)
    def test_env_var_substitution_with_defaults(self):
        """Test environment variable substitution with default values."""
        yaml_content = """
host: "127.0.0.1"
port: 8080

storage:
  type: "redis"
  redis:
    host: "${REDIS_HOST:-localhost}"
    port: "${REDIS_PORT:-6379}"
    password: "${REDIS_PASSWORD:-}"
    db: "${REDIS_DB:-0}"

oauth_providers:
  github:
    client_id: "${GITHUB_CLIENT_ID:-default_client_id}"
    client_secret: "${GITHUB_CLIENT_SECRET:-default_secret}"
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            config_path = f.name

        try:
            config_manager = ConfigManager(config_path)
            config = config_manager.load_config()

            # Check that environment variables were used
            assert config.storage.redis.host == "redis.prod.com"  # From env
            assert config.storage.redis.port == 6379  # Default value, converted to int
            assert config.storage.redis.password == ""  # Default empty string
            assert config.storage.redis.db == 0  # Default value

            # Check OAuth provider defaults
            github_provider = config.oauth_providers["github"]
            assert github_provider.client_id == "default_client_id"
            assert github_provider.client_secret == "default_secret"

        finally:
            os.unlink(config_path)

    def test_env_var_substitution_missing_required(self):
        """Test that missing required environment variables raise an error."""
        yaml_content = """
oauth_providers:
  github:
    client_id: "${MISSING_CLIENT_ID}"
    client_secret: "static_secret"
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            config_path = f.name

        try:
            config_manager = ConfigManager(config_path)

            with pytest.raises(
                ValueError,
                match="Environment variable 'MISSING_CLIENT_ID' is required but not set",
            ):
                config_manager.load_config()

        finally:
            os.unlink(config_path)

    def test_env_var_substitution_mixed_formats(self):
        """Test mixed environment variable formats in the same config."""
        yaml_content = """
host: "${HOST:-0.0.0.0}"
port: "${PORT}"
issuer: "${ISSUER:-http://localhost:8080}"
session_secret: "${SESSION_SECRET}"
debug: "${DEBUG:-false}"
"""

        with patch.dict(os.environ, {"PORT": "9000", "SESSION_SECRET": "secret123"}):
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".yaml", delete=False
            ) as f:
                f.write(yaml_content)
                config_path = f.name

            try:
                config_manager = ConfigManager(config_path)
                config = config_manager.load_config()

                # Check mixed substitution results
                assert config.host == "0.0.0.0"  # Default value
                assert config.port == 9000  # From environment
                assert config.issuer == "http://localhost:8080"  # Default value
                assert config.session_secret == "secret123"  # From environment
                assert config.debug is False  # Default value converted to boolean

            finally:
                os.unlink(config_path)

    def test_substitute_env_vars_method_direct(self):
        """Test the _substitute_env_vars method directly."""
        config_manager = ConfigManager()

        # Test required variable
        with patch.dict(os.environ, {"TEST_VAR": "test_value"}):
            result = config_manager._substitute_env_vars("value: ${TEST_VAR}")
            assert result == "value: test_value"

        # Test variable with default
        result = config_manager._substitute_env_vars("value: ${MISSING_VAR:-default}")
        assert result == "value: default"

        # Test missing required variable
        with pytest.raises(
            ValueError,
            match="Environment variable 'MISSING_REQUIRED' is required but not set",
        ):
            config_manager._substitute_env_vars("value: ${MISSING_REQUIRED}")

        # Test multiple variables
        with patch.dict(os.environ, {"VAR1": "value1", "VAR2": "value2"}):
            result = config_manager._substitute_env_vars("${VAR1} and ${VAR2}")
            assert result == "value1 and value2"

        # Test variables with complex defaults
        result = config_manager._substitute_env_vars(
            "${VAR:-default with spaces and : colons}"
        )
        assert result == "default with spaces and : colons"


class TestDataClasses:
    """Test cases for configuration data classes."""

    def test_oauth_provider_config_defaults(self):
        """Test OAuth provider config with defaults."""
        config = OAuthProviderConfig(client_id="test_id", client_secret="test_secret")

        assert config.client_id == "test_id"
        assert config.client_secret == "test_secret"
        assert config.scopes == []
        assert config.authorization_url is None
        assert config.token_url is None
        assert config.userinfo_url is None
        assert config.extra_params == {}

    def test_mcp_service_config_defaults(self):
        """Test MCP service config with defaults."""
        config = McpServiceConfig(
            name="Test Service",
            url="http://test.example.com/mcp",
            oauth_provider="github",
        )

        assert config.name == "Test Service"
        assert config.url == "http://test.example.com/mcp"
        assert config.oauth_provider == "github"
        assert config.auth_required is True
        assert config.scopes == []
        assert config.timeout == 30000

    def test_cors_config_defaults(self):
        """Test CORS config with defaults."""
        config = CorsConfig()

        assert config.allow_origins == ["*"]
        assert config.allow_credentials is True
        assert config.allow_methods == ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
        assert config.allow_headers == ["*"]
        assert config.expose_headers == []

    def test_gateway_config_defaults(self):
        """Test gateway config with defaults."""
        config = GatewayConfig()

        assert config.host == "0.0.0.0"
        assert config.port == 8080
        assert config.issuer == "http://localhost:8080"
        assert config.session_secret == "change-this-in-production"
        assert config.debug is False
        assert config.oauth_providers == {}
        assert config.mcp_services == {}
        assert isinstance(config.cors, CorsConfig)
