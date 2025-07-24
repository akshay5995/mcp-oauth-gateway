"""Tests for gateway middleware functionality."""

import pytest
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from src.gateway import MCPProtocolVersionMiddleware, OriginValidationMiddleware
from src.middleware.logging_middleware import CustomLoggingMiddleware


class TestOriginValidationMiddleware:
    """Test cases for OriginValidationMiddleware."""

    @pytest.fixture
    def test_app(self):
        """Create a test app with Origin validation middleware."""

        async def homepage(request):
            return PlainTextResponse("Hello World")

        app = Starlette(routes=[Route("/", homepage)])
        app.add_middleware(
            OriginValidationMiddleware,
            allowed_origins=["https://trusted.example.com", "https://app.company.com"],
            enforce_localhost=True,
        )
        return app

    @pytest.fixture
    def test_app_no_localhost_enforcement(self):
        """Create a test app with Origin validation but no localhost enforcement."""

        async def homepage(request):
            return PlainTextResponse("Hello World")

        app = Starlette(routes=[Route("/", homepage)])
        app.add_middleware(
            OriginValidationMiddleware,
            allowed_origins=["https://trusted.example.com"],
            enforce_localhost=False,
        )
        return app

    def test_request_without_origin_header(self, test_app):
        """Test that requests without Origin header are allowed."""
        client = TestClient(test_app)
        response = client.get("/")
        assert response.status_code == 200
        assert response.text == "Hello World"

    def test_request_with_allowed_origin(self, test_app):
        """Test that requests from allowed origins are permitted."""
        client = TestClient(test_app)
        response = client.get("/", headers={"Origin": "https://trusted.example.com"})
        assert response.status_code == 200
        assert response.text == "Hello World"

    def test_request_with_localhost_origin(self, test_app):
        """Test that localhost origins are allowed when enforcement is enabled."""
        client = TestClient(test_app)

        localhost_origins = [
            "http://localhost:8080",
            "http://127.0.0.1:3000",
            "https://localhost",
            "https://127.0.0.1:8443",
        ]

        for origin in localhost_origins:
            response = client.get("/", headers={"Origin": origin})
            assert response.status_code == 200, f"Failed for origin: {origin}"
            assert response.text == "Hello World"

    def test_request_with_unauthorized_origin(self, test_app):
        """Test that requests from unauthorized origins are blocked."""
        client = TestClient(test_app)
        response = client.get("/", headers={"Origin": "https://malicious.example.com"})
        assert response.status_code == 403
        assert response.text == "Unauthorized origin"

    def test_request_with_unauthorized_origin_no_localhost_enforcement(
        self, test_app_no_localhost_enforcement
    ):
        """Test behavior when localhost enforcement is disabled."""
        client = TestClient(test_app_no_localhost_enforcement)

        # When localhost enforcement is disabled, unauthorized non-localhost origins
        # are allowed to pass through (since enforce_localhost=False)
        response = client.get("/", headers={"Origin": "https://malicious.example.com"})
        assert response.status_code == 200  # Should pass through

        # Localhost should still be allowed even without enforcement
        response = client.get("/", headers={"Origin": "http://localhost:8080"})
        assert response.status_code == 200

    def test_origin_validation_case_sensitivity(self, test_app):
        """Test that origin validation is case-sensitive."""
        client = TestClient(test_app)

        # Exact match should work
        response = client.get("/", headers={"Origin": "https://trusted.example.com"})
        assert response.status_code == 200

        # Case mismatch should be blocked
        response = client.get("/", headers={"Origin": "https://TRUSTED.EXAMPLE.COM"})
        assert response.status_code == 403


class TestMCPProtocolVersionMiddleware:
    """Test cases for MCPProtocolVersionMiddleware."""

    @pytest.fixture
    def test_app(self):
        """Create a test app with MCP Protocol Version middleware."""

        async def mcp_endpoint(request):
            version = request.headers.get("mcp-protocol-version", "default")
            return PlainTextResponse(f"MCP Version: {version}")

        async def non_mcp_endpoint(request):
            return PlainTextResponse("Non-MCP endpoint")

        app = Starlette(
            routes=[
                Route("/calculator/mcp", mcp_endpoint),
                Route("/weather/mcp/status", mcp_endpoint),
                Route("/api/health", non_mcp_endpoint),
            ]
        )
        app.add_middleware(MCPProtocolVersionMiddleware)
        return app

    def test_mcp_endpoint_with_supported_version(self, test_app):
        """Test MCP endpoint with supported protocol version."""
        client = TestClient(test_app)

        supported_versions = ["2025-06-18", "2025-03-26"]

        for version in supported_versions:
            response = client.get(
                "/calculator/mcp", headers={"mcp-protocol-version": version}
            )
            assert response.status_code == 200
            assert f"MCP Version: {version}" in response.text

    def test_mcp_endpoint_with_unsupported_version(self, test_app):
        """Test MCP endpoint with unsupported protocol version."""
        client = TestClient(test_app)

        response = client.get(
            "/calculator/mcp", headers={"mcp-protocol-version": "2024-01-01"}
        )
        assert response.status_code == 400
        assert "Unsupported MCP protocol version" in response.text
        assert "2024-01-01" in response.text

    def test_mcp_endpoint_without_version_header(self, test_app):
        """Test MCP endpoint without protocol version header."""
        client = TestClient(test_app)

        # Should be allowed to pass through (backend will handle default)
        response = client.get("/calculator/mcp")
        assert response.status_code == 200
        # The middleware doesn't modify headers, so it should show 'default'
        assert "MCP Version: default" in response.text

    def test_non_mcp_endpoint_bypasses_validation(self, test_app):
        """Test that non-MCP endpoints bypass version validation."""
        client = TestClient(test_app)

        # Non-MCP endpoint should not be affected by protocol version
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.text == "Non-MCP endpoint"

        # Even with invalid version header, non-MCP endpoints should work
        response = client.get(
            "/api/health", headers={"mcp-protocol-version": "invalid-version"}
        )
        assert response.status_code == 200
        assert response.text == "Non-MCP endpoint"

    def test_mcp_endpoint_path_detection(self, test_app):
        """Test that middleware correctly detects MCP endpoints."""
        client = TestClient(test_app)

        # Test various MCP paths
        mcp_paths = [
            "/calculator/mcp",
            "/weather/mcp/status",
        ]

        for path in mcp_paths:
            # Valid version should work
            response = client.get(path, headers={"mcp-protocol-version": "2025-06-18"})
            assert response.status_code == 200

            # Invalid version should be rejected
            response = client.get(path, headers={"mcp-protocol-version": "invalid"})
            assert response.status_code == 400

    def test_version_validation_error_format(self, test_app):
        """Test that version validation errors have proper format."""
        client = TestClient(test_app)

        response = client.get(
            "/calculator/mcp", headers={"mcp-protocol-version": "2023-12-25"}
        )

        assert response.status_code == 400
        assert response.headers["content-type"] == "text/plain"

        error_text = response.text
        assert "Unsupported MCP protocol version: 2023-12-25" in error_text
        assert "Supported versions:" in error_text
        assert "2025-06-18" in error_text
        assert "2025-03-26" in error_text


class TestMiddlewareIntegration:
    """Test middleware working together."""

    @pytest.fixture
    def integrated_app(self):
        """Create an app with both middleware components."""

        async def mcp_endpoint(request):
            origin = request.headers.get("origin", "none")
            version = request.headers.get("mcp-protocol-version", "default")
            return PlainTextResponse(f"Origin: {origin}, Version: {version}")

        app = Starlette(routes=[Route("/service/mcp", mcp_endpoint)])

        # Add middleware in reverse order (FastAPI/Starlette processes them LIFO)
        app.add_middleware(MCPProtocolVersionMiddleware)
        app.add_middleware(
            OriginValidationMiddleware,
            allowed_origins=["https://trusted.example.com"],
            enforce_localhost=True,
        )
        return app

    def test_both_middleware_validations_pass(self, integrated_app):
        """Test that request passes both middleware validations."""
        client = TestClient(integrated_app)

        response = client.get(
            "/service/mcp",
            headers={
                "Origin": "https://trusted.example.com",
                "mcp-protocol-version": "2025-06-18",
            },
        )

        assert response.status_code == 200
        assert "Origin: https://trusted.example.com" in response.text
        assert "Version: 2025-06-18" in response.text

    def test_origin_validation_fails_first(self, integrated_app):
        """Test that origin validation failure blocks request before protocol validation."""
        client = TestClient(integrated_app)

        response = client.get(
            "/service/mcp",
            headers={
                "Origin": "https://malicious.example.com",
                "mcp-protocol-version": "2025-06-18",
            },
        )

        assert response.status_code == 403
        assert response.text == "Unauthorized origin"

    def test_protocol_validation_fails_after_origin_passes(self, integrated_app):
        """Test that protocol validation can fail after origin validation passes."""
        client = TestClient(integrated_app)

        response = client.get(
            "/service/mcp",
            headers={
                "Origin": "https://trusted.example.com",
                "mcp-protocol-version": "invalid-version",
            },
        )

        assert response.status_code == 400
        assert "Unsupported MCP protocol version" in response.text

    def test_no_origin_header_with_valid_protocol(self, integrated_app):
        """Test request with no origin header but valid protocol version."""
        client = TestClient(integrated_app)

        response = client.get(
            "/service/mcp", headers={"mcp-protocol-version": "2025-06-18"}
        )

        assert response.status_code == 200
        assert "Origin: none" in response.text
        assert "Version: 2025-06-18" in response.text


class TestCustomLoggingMiddleware:
    """Test cases for custom logging middleware."""

    @pytest.fixture
    def captured_logs(self, caplog):
        """Fixture to capture log messages."""
        import logging

        caplog.set_level(logging.DEBUG)
        return caplog

    def test_health_check_not_logged(self, captured_logs):
        """Test that health check endpoints are not logged."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()

        @app.get("/health")
        async def health():
            return {"status": "ok"}

        @app.get("/api/test")
        async def test_endpoint():
            return {"test": "data"}

        # Apply the real middleware
        app.add_middleware(CustomLoggingMiddleware, debug=False)

        client = TestClient(app)

        # Health check should not be logged
        response = client.get("/health")
        assert response.status_code == 200

        # Other endpoint should be logged
        response = client.get("/api/test")
        assert response.status_code == 200

        # Check that only the non-health endpoint was logged by our middleware
        # Filter to only our middleware logs (ignore httpx logs)
        middleware_logs = [
            record.message
            for record in captured_logs.records
            if record.name == "src.middleware.logging_middleware"
        ]
        assert not any("/health" in msg for msg in middleware_logs)
        assert any("/api/test" in msg for msg in middleware_logs)

    def test_oauth_endpoints_production_mode(self, captured_logs):
        """Test OAuth endpoints hide sensitive data in production mode."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()

        @app.get("/oauth/authorize")
        async def authorize():
            return {"status": "redirect"}

        @app.get("/oauth/callback")
        async def callback():
            return {"status": "callback"}

        @app.post("/oauth/token")
        async def token():
            return {"access_token": "secret"}

        # Apply the real middleware in production mode
        app.add_middleware(CustomLoggingMiddleware, debug=False)

        client = TestClient(app)

        # Test OAuth endpoints with sensitive query params
        response = client.get(
            "/oauth/authorize?client_id=secret&redirect_uri=http://example.com"
        )
        assert response.status_code == 200

        # Check logs - should NOT contain query parameters
        # Filter to only our middleware logs
        oauth_logs = [
            r
            for r in captured_logs.records
            if r.name == "src.middleware.logging_middleware"
            and "/oauth/authorize" in r.message
        ]
        assert len(oauth_logs) > 0
        assert "client_id=secret" not in oauth_logs[0].message
        assert "redirect_uri" not in oauth_logs[0].message
        assert "GET /oauth/authorize - 200" in oauth_logs[0].message

    def test_oauth_endpoints_debug_mode(self, captured_logs):
        """Test OAuth endpoints show full URLs in debug mode."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()

        @app.get("/oauth/authorize")
        async def authorize():
            return {"status": "redirect"}

        # Apply the real middleware in debug mode
        app.add_middleware(CustomLoggingMiddleware, debug=True)

        client = TestClient(app)

        # Test OAuth endpoint with sensitive query params
        response = client.get(
            "/oauth/authorize?client_id=secret&redirect_uri=http://example.com"
        )
        assert response.status_code == 200

        # In debug mode, logs SHOULD contain query parameters
        oauth_logs = [
            r
            for r in captured_logs.records
            if r.name == "src.middleware.logging_middleware"
            and "oauth/authorize" in r.message
            and r.levelname == "DEBUG"
        ]
        assert len(oauth_logs) > 0
        assert "client_id=secret" in oauth_logs[0].message

    def test_mcp_proxy_logging(self, captured_logs):
        """Test MCP proxy endpoints include service ID in logs."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()

        @app.post("/calculator/mcp")
        async def mcp_endpoint():
            return {"result": "success"}

        # Apply the real middleware
        app.add_middleware(CustomLoggingMiddleware, debug=False)

        client = TestClient(app)
        response = client.post("/calculator/mcp")
        assert response.status_code == 200

        # Check logs include service ID
        mcp_logs = [
            r
            for r in captured_logs.records
            if r.name == "src.middleware.logging_middleware" and "/mcp" in r.message
        ]
        assert len(mcp_logs) > 0
        assert "POST /calculator/mcp - 200" in mcp_logs[0].message

    def test_wellknown_oauth_endpoints(self, captured_logs):
        """Test .well-known OAuth endpoints are treated as OAuth endpoints."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()

        @app.get("/.well-known/oauth-authorization-server")
        async def oauth_metadata():
            return {"issuer": "http://example.com"}

        # Apply the real middleware
        app.add_middleware(CustomLoggingMiddleware, debug=False)

        client = TestClient(app)
        response = client.get("/.well-known/oauth-authorization-server?service_id=test")
        assert response.status_code == 200

        # Check logs don't include query params
        wellknown_logs = [
            r
            for r in captured_logs.records
            if r.name == "src.middleware.logging_middleware"
            and ".well-known/oauth" in r.message
        ]
        assert len(wellknown_logs) > 0
        assert "service_id=test" not in wellknown_logs[0].message

    def test_regular_endpoints_logged_normally(self, captured_logs):
        """Test non-OAuth, non-MCP endpoints are logged normally."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()

        @app.get("/services")
        async def list_services():
            return {"services": []}

        # Apply the real middleware
        app.add_middleware(CustomLoggingMiddleware, debug=False)

        client = TestClient(app)
        response = client.get("/services")
        assert response.status_code == 200

        # Check normal endpoint logging
        service_logs = [
            r
            for r in captured_logs.records
            if r.name == "src.middleware.logging_middleware"
            and "/services" in r.message
        ]
        assert len(service_logs) > 0
        assert "GET /services - 200" in service_logs[0].message
