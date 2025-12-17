from unittest.mock import MagicMock

import pytest
from sanic_testing.testing import SanicASGITestClient

from mcp_oauth_server.config import AppSettings
from mcp_oauth_server.http_server import create_app


@pytest.fixture
def mock_app():
    settings = AppSettings(auth_secret="test")
    mcp = MagicMock()
    mcp.session_manager = MagicMock()
    mcp.streamable_http_app = MagicMock()
    app = create_app(settings, mcp)
    return app


@pytest.mark.asyncio
async def test_options_endpoint(mock_app):
    async with SanicASGITestClient(mock_app) as client:
        request, response = await client.options("/mcp")
        assert response.status == 204
        assert "GET,POST,DELETE,OPTIONS" in response.headers["Allow"]
        assert response.headers["Access-Control-Allow-Origin"] == "*"


@pytest.mark.asyncio
async def test_health_probes(mock_app):
    async with SanicASGITestClient(mock_app) as client:
        # Test default
        request, response = await client.get("/health")
        assert response.status == 200
        assert response.json["status"] == "ok"
        assert response.json["probe"] == "unspecified"

        # Test probe arg
        request, response = await client.get("/health?probe=liveness")
        assert response.status == 200
        assert response.json["probe"] == "liveness"

        # Test type arg
        request, response = await client.get("/health?type=readiness")
        assert response.status == 200
        assert response.json["probe"] == "readiness"


@pytest.mark.asyncio
async def test_handle_not_found_exception(mock_app):
    async with SanicASGITestClient(mock_app) as client:
        # Manually trigger exception handler logic or route to 404
        request, response = await client.get("/non-existent-path-123")
        assert response.status == 404
        assert response.json["error"] == "not_found"


@pytest.mark.asyncio
async def test_handle_method_not_supported(mock_app):
    async with SanicASGITestClient(mock_app) as client:
        # /health allows GET. Try POST.
        request, response = await client.post("/health")
        assert response.status == 405
        assert response.json["error"] == "invalid_request"
        assert "not allowed" in response.json["error_description"]


@pytest.mark.asyncio
async def test_oauth_token_with_code_passthrough(mock_app):
    async with SanicASGITestClient(mock_app) as client:
        # The endpoint supports exchanging "code" directly if it's acting as a mock
        # passing code="test_code"
        params = {"code": "my_auth_code", "resource": "res1"}
        request, response = await client.post("/oauth/token", params=params)
        assert response.status == 200
        data = response.json
        assert data["access_token"] == "my_auth_code"
        assert data["status"] == "authorized"
        assert data["resource"] == "res1"


@pytest.mark.asyncio
async def test_oauth_token_authorization_header_missing(mock_app):
    async with SanicASGITestClient(mock_app) as client:
        # If no code and no Authorization header, should redirect to login
        # mock_app uses default settings which might not have login_url set,
        # but let's check the redirect or 401 behavior
        mock_app.ctx.settings.login_url = None
        request, response = await client.post("/oauth/token", params={})
        # Expect 401 if login_url is not set
        assert response.status == 401
        assert response.json["error"] == "unauthorized"

        # With login_url
        mock_app.ctx.settings.login_url = "http://login.com"
        request, response = await client.post("/oauth/token", params={})
        # ASGI Client might follow redirects automatically or returns 302?
        # Default behavior usually is NOT follow redirects unless configured.
        assert response.headers["Location"] == "http://login.com"
