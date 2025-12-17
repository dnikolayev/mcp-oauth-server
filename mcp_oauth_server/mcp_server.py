from __future__ import annotations

import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from mcp_oauth_server.config import AppSettings

logger = logging.getLogger(__name__)


def build_mcp_server(settings: AppSettings) -> FastMCP:
    server = FastMCP(
        name="mcp-oauth-server",
        instructions=(
            "You are a helpful assistant. "
            "Use the provided tools to assist the user. "
        ),
        json_response=settings.json_response,
        stateless_http=settings.stateless_http,
    )
    server.settings.streamable_http_path = settings.mcp_path
    _configure_transport_security(server, settings)

    @server.tool(description="Health check for MCP server")
    async def healthcheck() -> dict[str, Any]:
        return {"status": "ok"}

    @server.tool(description="Echo back the input message")
    async def echo(message: str) -> str:
        return f"Echo: {message}"

    @server.tool(description="Add two numbers")
    async def add(a: int, b: int) -> int:
        return a + b

    @server.resource("config://app")
    async def config_resource() -> str:
        """Expose non-sensitive config."""
        import json
        data = {
            "public_base_url": str(settings.public_base_url) if settings.public_base_url else None,
            "mcp_host": settings.mcp_host,
        }
        return json.dumps(data)

    return server


def _configure_transport_security(server: FastMCP, settings: AppSettings) -> None:
    """Augment transport security allow-lists with deployment hostnames."""
    ts = server.settings.transport_security
    ts.enable_dns_rebinding_protection = settings.dns_rebinding_protection
    default_hosts = set(ts.allowed_hosts or [])
    default_origins = set(ts.allowed_origins or [])

    def _ensure_host(host: str) -> None:
        if not host:
            return
        candidate = host if ":" in host else f"{host}:*"
        if candidate not in ts.allowed_hosts:
            ts.allowed_hosts.append(candidate)

    def _ensure_origin(origin_host: str) -> None:
        if not origin_host:
            return
        candidate = origin_host if "://" in origin_host else f"http://{origin_host}"
        if candidate.endswith(":"):
            candidate = candidate[:-1]
        if candidate not in ts.allowed_origins:
            ts.allowed_origins.append(candidate)

    # Preserve defaults, then extend with configured lists
    ts.allowed_hosts = list(default_hosts)
    ts.allowed_origins = list(default_origins)

    for host in settings.allowed_hosts:
        _ensure_host(host)
    for origin in settings.allowed_origins:
        _ensure_origin(origin)
    _ensure_host(settings.mcp_host)
    _ensure_origin(settings.mcp_host)
