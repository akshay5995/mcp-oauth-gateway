"""Tests for MCP proxy functionality."""

from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest
from fastapi import Request
from fastapi.datastructures import Headers

from src.auth.models import UserInfo
from src.config.config import McpServiceConfig
from src.proxy.mcp_proxy import McpProxy


class TestMcpProxy:
    """Test cases for McpProxy."""

    @pytest.fixture
    def mcp_proxy(self):
        """MCP proxy fixture."""
        return McpProxy()

    @pytest.fixture
    def service_config(self):
        """Service configuration fixture."""
        return McpServiceConfig(
            name="Test Calculator",
            url="http://localhost:3001/mcp",
            oauth_provider="github",
            auth_required=True,
            scopes=["read", "calculate"],
            timeout=30000,
        )

    @pytest.fixture
    def user_info(self):
        """User info fixture."""
        return UserInfo(
            id="test_user_123",
            email="test@example.com",
            name="Test User",
            provider="github",
            avatar_url="https://github.com/test.jpg",
        )

    def test_mcp_proxy_initialization(self):
        """Test MCP proxy initializes correctly."""
        proxy = McpProxy()
        assert proxy.client is None

    @pytest.mark.asyncio
    async def test_start_stop_proxy(self):
        """Test proxy start and stop."""
        proxy = McpProxy()

        # Initially no client
        assert proxy.client is None

        # Start proxy
        await proxy.start()
        assert proxy.client is not None
        assert isinstance(proxy.client, httpx.AsyncClient)

        # Stop proxy
        await proxy.stop()
        assert proxy.client is None

    @pytest.mark.asyncio
    async def test_forward_request_success(self, mcp_proxy, service_config, user_info):
        """Test successful request forwarding."""
        # Ensure proxy is started
        await mcp_proxy.start()

        # Mock request
        mock_request = Mock(spec=Request)
        mock_request.method = "POST"
        mock_request.headers = Headers(
            {"content-type": "application/json", "authorization": "Bearer token123"}
        )
        mock_request.body = AsyncMock(
            return_value=b'{"jsonrpc": "2.0", "method": "add", "params": {"a": 1, "b": 2}}'
        )
        mock_request.query_params = {}

        # Mock backend response
        mock_backend_response = Mock()
        mock_backend_response.content = b'{"jsonrpc": "2.0", "result": 3, "id": 1}'
        mock_backend_response.status_code = 200
        mock_backend_response.headers = {"content-type": "application/json"}

        # Mock the httpx client
        with patch.object(
            mcp_proxy.client, "request", return_value=mock_backend_response
        ) as mock_request_call:
            response = await mcp_proxy.forward_request(
                service_config, mock_request, user_info
            )

            assert response.status_code == 200
            assert response.body == b'{"jsonrpc": "2.0", "result": 3, "id": 1}'

            # Verify the call was made with correct parameters
            mock_request_call.assert_called_once()
            call_args = mock_request_call.call_args

            assert call_args.kwargs["method"] == "POST"
            assert call_args.kwargs["url"] == service_config.url
            assert (
                call_args.kwargs["content"]
                == b'{"jsonrpc": "2.0", "method": "add", "params": {"a": 1, "b": 2}}'
            )

            # Check headers
            headers = call_args.kwargs["headers"]
            assert headers["Accept"] == "application/json, text/event-stream"
            assert headers["Content-Type"] == "application/json"
            assert headers["MCP-Protocol-Version"] == "2025-06-18"
            assert headers["x-user-id"] == "test_user_123"
            assert headers["x-user-email"] == "test@example.com"
            assert headers["x-user-name"] == "Test User"
            assert headers["x-user-provider"] == "github"
            assert headers["x-user-avatar"] == "https://github.com/test.jpg"

            # Authorization header should be removed
            assert "authorization" not in headers
            assert "Authorization" not in headers

    @pytest.mark.asyncio
    async def test_forward_request_without_user_info(self, mcp_proxy, service_config):
        """Test request forwarding without user info."""
        # Ensure proxy is started
        await mcp_proxy.start()

        # Mock request
        mock_request = Mock(spec=Request)
        mock_request.method = "GET"
        mock_request.headers = Headers({"content-type": "application/json"})
        mock_request.body = AsyncMock(return_value=b"")
        mock_request.query_params = {}

        # Mock backend response
        mock_backend_response = Mock()
        mock_backend_response.content = b'{"status": "ok"}'
        mock_backend_response.status_code = 200
        mock_backend_response.headers = {"content-type": "application/json"}

        with patch.object(
            mcp_proxy.client, "request", return_value=mock_backend_response
        ) as mock_request_call:
            response = await mcp_proxy.forward_request(
                service_config, mock_request, None
            )

            assert response.status_code == 200

            # Check that no user context headers were added
            headers = mock_request_call.call_args.kwargs["headers"]
            assert "x-user-id" not in headers
            assert "x-user-email" not in headers
            assert "x-user-name" not in headers
            assert "x-user-provider" not in headers
            assert "x-user-avatar" not in headers

    @pytest.mark.asyncio
    async def test_forward_request_timeout(self, mcp_proxy, service_config, user_info):
        """Test request forwarding with timeout."""
        # Ensure proxy is started
        await mcp_proxy.start()

        # Mock request
        mock_request = Mock(spec=Request)
        mock_request.method = "POST"
        mock_request.headers = Headers({"content-type": "application/json"})
        mock_request.body = AsyncMock(return_value=b'{"test": "data"}')
        mock_request.query_params = {}

        # Mock timeout exception
        with patch.object(
            mcp_proxy.client, "request", side_effect=httpx.TimeoutException("Timeout")
        ):
            response = await mcp_proxy.forward_request(
                service_config, mock_request, user_info
            )

            assert response.status_code == 504
            assert "timed out" in response.body.decode()

    @pytest.mark.asyncio
    async def test_forward_request_connection_error(
        self, mcp_proxy, service_config, user_info
    ):
        """Test request forwarding with connection error."""
        # Ensure proxy is started
        await mcp_proxy.start()

        # Mock request
        mock_request = Mock(spec=Request)
        mock_request.method = "POST"
        mock_request.headers = Headers({"content-type": "application/json"})
        mock_request.body = AsyncMock(return_value=b'{"test": "data"}')
        mock_request.query_params = {}

        # Mock connection error
        with patch.object(
            mcp_proxy.client,
            "request",
            side_effect=httpx.ConnectError("Connection failed"),
        ):
            response = await mcp_proxy.forward_request(
                service_config, mock_request, user_info
            )

            assert response.status_code == 502
            assert "Cannot connect" in response.body.decode()

    @pytest.mark.asyncio
    async def test_forward_request_general_error(
        self, mcp_proxy, service_config, user_info
    ):
        """Test request forwarding with general error."""
        # Ensure proxy is started
        await mcp_proxy.start()

        # Mock request
        mock_request = Mock(spec=Request)
        mock_request.method = "POST"
        mock_request.headers = Headers({"content-type": "application/json"})
        mock_request.body = AsyncMock(return_value=b'{"test": "data"}')
        mock_request.query_params = {}

        # Mock general exception
        with patch.object(
            mcp_proxy.client, "request", side_effect=Exception("General error")
        ):
            response = await mcp_proxy.forward_request(
                service_config, mock_request, user_info
            )

            assert response.status_code == 500
            assert "Proxy error" in response.body.decode()

    @pytest.mark.asyncio
    async def test_forward_request_with_query_params(
        self, mcp_proxy, service_config, user_info
    ):
        """Test request forwarding with query parameters."""
        # Ensure proxy is started
        await mcp_proxy.start()

        # Mock request
        mock_request = Mock(spec=Request)
        mock_request.method = "GET"
        mock_request.headers = Headers({"content-type": "application/json"})
        mock_request.body = AsyncMock(return_value=b"")
        mock_request.query_params = {"param1": "value1", "param2": "value2"}

        # Mock backend response
        mock_backend_response = Mock()
        mock_backend_response.content = b'{"result": "success"}'
        mock_backend_response.status_code = 200
        mock_backend_response.headers = {"content-type": "application/json"}

        with patch.object(
            mcp_proxy.client, "request", return_value=mock_backend_response
        ) as mock_request_call:
            response = await mcp_proxy.forward_request(
                service_config, mock_request, user_info
            )

            assert response.status_code == 200

            # Check that query parameters were passed
            params = mock_request_call.call_args.kwargs["params"]
            assert params["param1"] == "value1"
            assert params["param2"] == "value2"

    @pytest.mark.asyncio
    async def test_check_service_health_success(self, mcp_proxy, service_config):
        """Test successful service health check."""
        # Ensure proxy is started
        await mcp_proxy.start()

        mock_response = Mock()
        mock_response.status_code = 200

        with patch.object(mcp_proxy.client, "get", return_value=mock_response):
            healthy = await mcp_proxy.check_service_health(service_config)
            assert healthy is True

    @pytest.mark.asyncio
    async def test_check_service_health_failure(self, mcp_proxy, service_config):
        """Test failed service health check."""
        # Ensure proxy is started
        await mcp_proxy.start()

        with patch.object(
            mcp_proxy.client, "get", side_effect=httpx.ConnectError("Connection failed")
        ):
            healthy = await mcp_proxy.check_service_health(service_config)
            assert healthy is False

    @pytest.mark.asyncio
    async def test_check_service_health_no_client(self):
        """Test health check without initialized client."""
        proxy = McpProxy()
        service_config = McpServiceConfig(
            name="Test Service",
            url="http://localhost:3001/mcp",
            oauth_provider="github",
            auth_required=True,
            timeout=10000,
        )

        with patch.object(proxy, "start") as mock_start:
            mock_start.return_value = None
            proxy.client = None  # Simulate failed start

            healthy = await proxy.check_service_health(service_config)
            assert healthy is False

    def test_extract_service_id_from_path(self, mcp_proxy):
        """Test service ID extraction from path."""
        assert (
            mcp_proxy._extract_service_id_from_path("/calculator/mcp") == "calculator"
        )
        assert mcp_proxy._extract_service_id_from_path("weather/mcp") == "weather"
        assert mcp_proxy._extract_service_id_from_path("/") == ""
        assert mcp_proxy._extract_service_id_from_path("") == ""

    def test_build_target_url(self, mcp_proxy):
        """Test target URL building."""
        assert (
            mcp_proxy._build_target_url("http://localhost:3001", "/mcp")
            == "http://localhost:3001/mcp"
        )
        assert (
            mcp_proxy._build_target_url("http://localhost:3001/", "/mcp")
            == "http://localhost:3001/mcp"
        )
        assert (
            mcp_proxy._build_target_url("http://localhost:3001", "mcp")
            == "http://localhost:3001/mcp"
        )

    def test_build_user_context_headers_complete(self, mcp_proxy, user_info):
        """Test building user context headers with complete user info."""
        headers = mcp_proxy._build_user_context_headers(user_info)

        expected_headers = {
            "x-user-id": "test_user_123",
            "x-user-email": "test@example.com",
            "x-user-name": "Test User",
            "x-user-provider": "github",
            "x-user-avatar": "https://github.com/test.jpg",
        }

        assert headers == expected_headers

    def test_build_user_context_headers_partial(self, mcp_proxy):
        """Test building user context headers with partial user info."""
        partial_user = UserInfo(
            id="test_user_123",
            email="test@example.com",
            name="",  # Empty name
            provider="github",
            avatar_url=None,  # No avatar
        )

        headers = mcp_proxy._build_user_context_headers(partial_user)

        expected_headers = {
            "x-user-id": "test_user_123",
            "x-user-email": "test@example.com",
            "x-user-provider": "github",
        }

        assert headers == expected_headers
        assert "x-user-name" not in headers
        assert "x-user-avatar" not in headers

    def test_build_user_context_headers_empty(self, mcp_proxy):
        """Test building user context headers with empty user info."""
        empty_user = UserInfo(id="", email="", name="", provider="", avatar_url="")

        headers = mcp_proxy._build_user_context_headers(empty_user)

        assert headers == {}

    @pytest.mark.asyncio
    async def test_forward_request_removes_problematic_headers(
        self, mcp_proxy, service_config, user_info
    ):
        """Test that problematic headers are removed from request."""
        # Ensure proxy is started
        await mcp_proxy.start()

        # Mock request with problematic headers
        mock_request = Mock(spec=Request)
        mock_request.method = "POST"
        mock_request.headers = Headers(
            {
                "host": "gateway.example.com",
                "content-length": "100",
                "connection": "keep-alive",
                "authorization": "Bearer token123",
                "custom-header": "keep-this",
            }
        )
        mock_request.body = AsyncMock(return_value=b'{"test": "data"}')
        mock_request.query_params = {}

        # Mock backend response
        mock_backend_response = Mock()
        mock_backend_response.content = b'{"result": "success"}'
        mock_backend_response.status_code = 200
        mock_backend_response.headers = {
            "content-type": "application/json",
            "content-length": "20",
            "transfer-encoding": "chunked",
        }

        with patch.object(
            mcp_proxy.client, "request", return_value=mock_backend_response
        ) as mock_request_call:
            response = await mcp_proxy.forward_request(
                service_config, mock_request, user_info
            )

            # Check that problematic headers were removed from request
            headers = mock_request_call.call_args.kwargs["headers"]
            assert "host" not in headers
            assert "content-length" not in headers
            assert "connection" not in headers
            assert "authorization" not in headers
            assert "custom-header" in headers  # This should be kept

            # Check that response maintains content-type
            assert "content-type" in response.headers
            # Note: content-length is automatically calculated by FastAPI based on response content
