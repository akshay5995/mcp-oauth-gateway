"""Tests for storage configuration validation."""

import pytest

from src.config.config import RedisStorageConfig, StorageConfig, VaultStorageConfig


class TestStorageConfigValidation:
    """Test cases for storage configuration validation."""

    def test_valid_memory_config(self):
        """Test valid memory configuration."""
        config = StorageConfig(type="memory")
        # Should not raise any exception
        config.validate()

    def test_valid_redis_config(self):
        """Test valid Redis configuration."""
        redis_config = RedisStorageConfig(
            host="redis.example.com", port=6379, max_connections=20
        )
        config = StorageConfig(type="redis", redis=redis_config)
        # Should not raise any exception
        config.validate()

    def test_valid_vault_config(self):
        """Test valid Vault configuration."""
        vault_config = VaultStorageConfig(
            url="https://vault.example.com:8200",
            token="hvs.test-token",
            mount_point="secret",
            path_prefix="mcp-gateway",
            auth_method="token",
        )
        config = StorageConfig(type="vault", vault=vault_config)
        # Should not raise any exception
        config.validate()

    def test_invalid_storage_type(self):
        """Test invalid storage type."""
        config = StorageConfig(type="invalid_type")
        with pytest.raises(ValueError, match="Invalid storage type 'invalid_type'"):
            config.validate()

    def test_redis_missing_host(self):
        """Test Redis configuration with missing host."""
        redis_config = RedisStorageConfig(host="")
        config = StorageConfig(type="redis", redis=redis_config)
        with pytest.raises(ValueError, match="Redis host is required"):
            config.validate()

    def test_redis_invalid_port(self):
        """Test Redis configuration with invalid port."""
        redis_config = RedisStorageConfig(host="localhost", port=0)
        config = StorageConfig(type="redis", redis=redis_config)
        with pytest.raises(ValueError, match="Invalid Redis port 0"):
            config.validate()

        redis_config = RedisStorageConfig(host="localhost", port=70000)
        config = StorageConfig(type="redis", redis=redis_config)
        with pytest.raises(ValueError, match="Invalid Redis port 70000"):
            config.validate()

    def test_redis_invalid_max_connections(self):
        """Test Redis configuration with invalid max_connections."""
        redis_config = RedisStorageConfig(host="localhost", max_connections=0)
        config = StorageConfig(type="redis", redis=redis_config)
        with pytest.raises(ValueError, match="Invalid Redis max_connections 0"):
            config.validate()

        redis_config = RedisStorageConfig(host="localhost", max_connections=-1)
        config = StorageConfig(type="redis", redis=redis_config)
        with pytest.raises(ValueError, match="Invalid Redis max_connections -1"):
            config.validate()

    def test_vault_missing_url(self):
        """Test Vault configuration with missing URL."""
        vault_config = VaultStorageConfig(url="")
        config = StorageConfig(type="vault", vault=vault_config)
        with pytest.raises(ValueError, match="Vault URL is required"):
            config.validate()

    def test_vault_invalid_url_scheme(self):
        """Test Vault configuration with invalid URL scheme."""
        vault_config = VaultStorageConfig(url="ftp://vault.example.com")
        config = StorageConfig(type="vault", vault=vault_config)
        with pytest.raises(ValueError, match="Invalid Vault URL.*Must start with http"):
            config.validate()

    def test_vault_invalid_auth_method(self):
        """Test Vault configuration with invalid auth method."""
        vault_config = VaultStorageConfig(
            url="https://vault.example.com", auth_method="invalid"
        )
        config = StorageConfig(type="vault", vault=vault_config)
        with pytest.raises(ValueError, match="Invalid Vault auth method 'invalid'"):
            config.validate()

    def test_vault_token_auth_missing_token(self):
        """Test Vault token authentication with missing token."""
        vault_config = VaultStorageConfig(
            url="https://vault.example.com", auth_method="token", token=None
        )
        config = StorageConfig(type="vault", vault=vault_config)
        with pytest.raises(
            ValueError, match="Vault token is required when using token authentication"
        ):
            config.validate()

    def test_vault_missing_mount_point(self):
        """Test Vault configuration with missing mount point."""
        vault_config = VaultStorageConfig(
            url="https://vault.example.com", token="test-token", mount_point=""
        )
        config = StorageConfig(type="vault", vault=vault_config)
        with pytest.raises(ValueError, match="Vault mount_point is required"):
            config.validate()

    def test_vault_missing_path_prefix(self):
        """Test Vault configuration with missing path prefix."""
        vault_config = VaultStorageConfig(
            url="https://vault.example.com", token="test-token", path_prefix=""
        )
        config = StorageConfig(type="vault", vault=vault_config)
        with pytest.raises(ValueError, match="Vault path_prefix is required"):
            config.validate()

    def test_vault_approle_auth(self):
        """Test Vault with AppRole authentication (should be valid even without token)."""
        vault_config = VaultStorageConfig(
            url="https://vault.example.com",
            auth_method="approle",
            token=None,  # No token required for AppRole
        )
        config = StorageConfig(type="vault", vault=vault_config)
        # Should not raise any exception
        config.validate()

    def test_vault_kubernetes_auth(self):
        """Test Vault with Kubernetes authentication (should be valid even without token)."""
        vault_config = VaultStorageConfig(
            url="https://vault.example.com",
            auth_method="kubernetes",
            token=None,  # No token required for Kubernetes auth
        )
        config = StorageConfig(type="vault", vault=vault_config)
        # Should not raise any exception
        config.validate()

    def test_edge_case_valid_ports(self):
        """Test edge cases for valid port numbers."""
        # Test minimum valid port
        redis_config = RedisStorageConfig(host="localhost", port=1)
        config = StorageConfig(type="redis", redis=redis_config)
        config.validate()

        # Test maximum valid port
        redis_config = RedisStorageConfig(host="localhost", port=65535)
        config = StorageConfig(type="redis", redis=redis_config)
        config.validate()

    def test_vault_url_with_port(self):
        """Test Vault URL with custom port."""
        vault_config = VaultStorageConfig(
            url="https://vault.example.com:8200", token="test-token"
        )
        config = StorageConfig(type="vault", vault=vault_config)
        config.validate()

    def test_vault_http_url(self):
        """Test Vault with HTTP URL (should be valid for development)."""
        vault_config = VaultStorageConfig(
            url="http://localhost:8200", token="test-token"
        )
        config = StorageConfig(type="vault", vault=vault_config)
        config.validate()
