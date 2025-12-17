import json

import pytest

from mcp_oauth_server.config import AppSettings
from mcp_oauth_server.http_server import create_app
from mcp_oauth_server.mcp_server import build_mcp_server


@pytest.mark.asyncio
async def test_mcp_server_instructions_and_path():
    # If the user did not implement 'call_operation' in standard tools (we removed it), it won't be there.
    # But let's check basic healthcheck tool presence.
    settings = AppSettings(mcp_path="/custom")
    server = build_mcp_server(settings)

    tools = await server.list_tools()
    tool_names = [t.name for t in tools]
    assert "healthcheck" in tool_names
    assert server.settings.streamable_http_path == "/custom"


def test_create_app_initializes_session_manager():
    settings = AppSettings()
    server = build_mcp_server(settings)
    app = create_app(settings, server)

    assert app.ctx.session_manager is not None
    assert app.ctx.mcp_server.settings.streamable_http_path == settings.mcp_path


def test_transport_security_allows_custom_host():
    settings = AppSettings(mcp_host="dev.example.com", allowed_hosts=["dev.example.com:443"])
    server = build_mcp_server(settings)

    assert "dev.example.com:443" in server.settings.transport_security.allowed_hosts
    # mcp_host without port gets :* automatically added
    assert "dev.example.com:*" in server.settings.transport_security.allowed_hosts


def test_transport_security_can_be_disabled():
    settings = AppSettings(dns_rebinding_protection=False)
    server = build_mcp_server(settings)

    assert server.settings.transport_security.enable_dns_rebinding_protection is False


@pytest.mark.asyncio
async def test_config_resource_exposes_base():
    settings = AppSettings(public_base_url="https://dev.example.com/mcp")
    server = build_mcp_server(settings)

    resources = await server.list_resources()
    uris = {str(res.uri) for res in resources}
    assert "config://app" in uris

    contents = await server.read_resource("config://app")
    payload = json.loads(contents[0].content)
    assert payload["public_base_url"] == "https://dev.example.com/mcp"
