from __future__ import annotations

import logging
from functools import partial
from typing import Any

import click
from dotenv import load_dotenv
from sanic import Sanic
from sanic.worker.loader import AppLoader

from mcp_oauth_server.config import AppSettings
from mcp_oauth_server.http_server import create_app
from mcp_oauth_server.mcp_server import build_mcp_server


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=level.upper(),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def _install_uvloop() -> None:
    try:
        import uvloop

        uvloop.install()
    except Exception:  # pragma: no cover - best effort
        pass


def _build_app(settings: AppSettings, debug_enabled: bool, app_name: str) -> Sanic:
    """Factory used by the Sanic worker/reloader to build fresh app instances."""
    _configure_logging(settings.log_level)
    _install_uvloop()
    mcp_server = build_mcp_server(settings)
    app = create_app(settings, mcp_server, app_name=app_name)
    app.config.DEBUG = debug_enabled
    return app


@click.group()
def cli() -> None:
    """MCP OAuth Server utility CLI."""


@cli.command(name="serve", help="Start the MCP HTTP server")
@click.option("--host", "--mcp-host", help="Host to bind the Sanic server (default: 127.0.0.1)")
@click.option("--port", "--mcp-port", type=int, help="Port to bind the Sanic server (default: 8042)")
@click.option("--mcp-path", help="Path to expose MCP streamable HTTP endpoint (default: /mcp)")
@click.option(
    "--json-response/--sse-response",
    default=None,
    help="Return MCP responses as JSON (default) or SSE.",
)
@click.option(
    "--stateless/--stateful",
    default=None,
    help="Use stateless streamable HTTP transport (default: stateless).",
)
@click.option("--log-level", help="Log level (default: INFO)")
@click.option(
    "--debug/--no-debug",
    default=None,
    help="Enable Sanic debug mode; also sets log level to DEBUG when enabled.",
)
# pylint: disable=too-many-branches
def serve(
    host: str | None,
    port: int | None,
    mcp_path: str | None,
    json_response: bool | None,
    stateless: bool | None,
    log_level: str | None,
    debug: bool | None,
) -> None:
    load_dotenv()
    base_settings = AppSettings()
    overrides: dict[str, Any] = {}

    if host:
        overrides["mcp_host"] = host
    if port is not None:
        overrides["mcp_port"] = port
    if mcp_path:
        overrides["mcp_path"] = mcp_path
    if json_response is not None:
        overrides["json_response"] = json_response
    if stateless is not None:
        overrides["stateless_http"] = stateless
    if log_level:
        overrides["log_level"] = log_level
    if debug is True:
        overrides["log_level"] = "DEBUG"

    settings = base_settings.model_copy(update=overrides)
    debug_enabled = debug if debug is not None else settings.log_level.upper() == "DEBUG"
    _configure_logging(settings.log_level)
    _install_uvloop()

    click.echo(f"MCP endpoint http://{settings.mcp_host}:{settings.mcp_port}{settings.mcp_path}")
    if settings.public_base_url:
        click.echo(f"Public MCP base {settings.public_base_url}")

    app_name = "mcp-oauth"

    app_factory = partial(_build_app, settings, debug_enabled, app_name)
    app = app_factory()

    # Prefer single-process to avoid worker/reloader forking, but allow dev/auto-reload when debugging.
    single_process = not debug_enabled
    app.prepare(
        host=settings.mcp_host,
        port=settings.mcp_port,
        access_log=True,
        motd=False,
        single_process=single_process,
        workers=1,
        debug=debug_enabled,
        dev=debug_enabled,
        auto_reload=debug_enabled,
    )

    if single_process:
        Sanic.serve_single(primary=app)
    else:
        app_loader = AppLoader(factory=app_factory)
        Sanic.serve(primary=app, app_loader=app_loader)


@cli.command(name="config", help="Print effective configuration from environment")
def show_settings() -> None:
    settings = AppSettings()
    for field, value in settings.model_dump().items():
        click.echo(f"{field}: {value}")


if __name__ == "__main__":
    cli()
