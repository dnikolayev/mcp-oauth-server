from __future__ import annotations

import asyncio
import base64
import html
import logging
import secrets
import time
import uuid
from contextlib import suppress
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from mcp.server.fastmcp import FastMCP
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from sanic import Sanic, response
from sanic.exceptions import InvalidUsage, MethodNotSupported, NotFound, SanicException, ServiceUnavailable
from sanic.request import Request
from sanic.response import HTTPResponse, ResponseStream

from mcp_oauth_server.config import AppSettings
from mcp_oauth_server.cookie_auth import default_token_extractor
from mcp_oauth_server.db import Database
from mcp_oauth_server.session_store import AppStateStore, RegistrationStore, SessionStore
from mcp_oauth_server.storage import MemoryStorageBackend, PostgresStorageBackend, RedisStorageBackend, StorageBackend

logger = logging.getLogger(__name__)
_DEFAULT_LOGO_DATA_URI: str | None = None


# pylint: disable=too-many-statements
def create_app(
    settings: AppSettings,
    mcp_server: FastMCP,
    *,
    app_name: str | None = None,
    cookie_token_extractor: Callable[[str], str | None] | None = None,
) -> Sanic:
    """Create the Sanic HTTP app that fronts the MCP server."""
    resolved_app_name = app_name or f"mcp-oauth-server-{uuid.uuid4().hex}"
    app = Sanic(resolved_app_name)
    mcp_prefix = settings.mcp_path.rstrip("/") or "/mcp"
    _configure_uvloop(app)

    app.ctx.settings = settings
    app.ctx.mcp_server = mcp_server
    app.ctx.cookie_token_extractor = cookie_token_extractor or default_token_extractor
    backend: StorageBackend
    if settings.database_url:
        app.ctx.db = Database(settings.database_url)
        backend = PostgresStorageBackend(app.ctx.db)
    elif settings.redis_dsn:
        backend = RedisStorageBackend(settings.redis_dsn)
    else:
        backend = MemoryStorageBackend()

    app.ctx.session_store = SessionStore(backend)
    app.ctx.registration_store = RegistrationStore(backend)
    app.ctx.state_store = AppStateStore(backend)

    # Ensure the MCP session manager exists even though we are not using the Starlette wrapper.
    mcp_server.streamable_http_app()
    app.ctx.session_manager = mcp_server.session_manager

    _register_lifecycle_noops(app)

    @app.listener("before_server_start")
    async def init_db(app: Sanic, _) -> None:
        if getattr(app.ctx, "db", None):
            logger.info("Initializing Database")
            await app.ctx.db.init_db()

    @app.listener("before_server_start")
    async def start_session_manager(app: Sanic, _) -> None:
        logger.info("Starting MCP session manager")
        app.ctx.session_manager_cm = app.ctx.session_manager.run()
        await app.ctx.session_manager_cm.__aenter__()

    @app.listener("after_server_stop")
    async def stop_session_manager(app: Sanic, _) -> None:
        logger.info("Stopping MCP session manager")
        if getattr(app.ctx, "session_manager_cm", None):
            # Reloader shutdown may fire from a different task; suppress cancel scope errors on teardown.
            with suppress(RuntimeError):
                await app.ctx.session_manager_cm.__aexit__(None, None, None)

    @app.listener("after_server_stop")
    async def close_db(app: Sanic, _) -> None:
        if getattr(app.ctx, "db", None):
            logger.info("Closing Database")
            await app.ctx.db.close()

    @app.get(settings.health_path)
    async def health(request: Request) -> HTTPResponse:
        probe = request.args.get("probe") or request.args.get("type")
        payload: dict[str, Any] = {"status": "ok", "mcp_path": settings.mcp_path, "probe": probe or "unspecified"}
        return response.json(payload)

    @app.options(settings.mcp_path)
    async def options(_: Request) -> HTTPResponse:

        headers = {
            "Allow": "GET,POST,DELETE,OPTIONS",
            "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Origin": "*",
        }
        return response.empty(status=204, headers=headers)

    @app.route(settings.mcp_path, methods=["GET", "POST", "DELETE"])
    async def mcp_entrypoint(request: Request) -> HTTPResponse:
        session_manager: StreamableHTTPSessionManager = app.ctx.session_manager
        if not getattr(app.ctx, "session_manager_cm", None):
            raise ServiceUnavailable("Session manager not started")

        return await _proxy_to_asgi(request, session_manager)

    async def oauth_validate(request: Request) -> HTTPResponse:
        token = _extract_auth_token(request, settings)
        if not token:
            return _redirect_to_login(settings)
        valid, refreshed = await _is_token_valid(token, app, None)
        if not valid:
            return _redirect_to_login(settings)
        token_to_use = refreshed or token
        payload = {
            "access_token": token_to_use,
            "token_type": "JWT",
            "expires_in": int(settings.access_token_ttl_seconds),
        }
        return response.json(payload)

    async def oauth_token(request: Request) -> HTTPResponse:
        # Support exchanging an incoming "code" (from authorize redirect) as a token passthrough.
        code = request.args.get("code")
        if not code and request.form:
            code = request.form.get("code")
        if code:
            resource = request.args.get("resource") or (request.form.get("resource") if request.form else None)
            return response.json(
                {
                    "access_token": code,
                    "token_type": "JWT",
                    "expires_in": int(settings.access_token_ttl_seconds),
                    "status": "authorized",
                    **({"resource": resource} if resource else {}),
                }
            )

        token = _extract_auth_token(request, settings)
        if not token:
            return _redirect_to_login(settings)
        client_id = request.args.get("client_id")
        valid, refreshed = await _is_token_valid(token, app, client_id)
        if not valid:
            return _redirect_to_login(settings)
        token = refreshed or token
        resource = request.args.get("resource")
        payload = {
            "access_token": token,
            "token_type": "JWT",
            "expires_in": int(settings.access_token_ttl_seconds),
            **({"resource": resource} if resource else {}),
        }
        return response.json(payload)

    async def oauth_authorize(request: Request) -> HTTPResponse:
        token = _extract_auth_token(request, settings)
        if not token:
            return _redirect_to_login(settings)
        client_id = request.args.get("client_id")
        valid, refreshed = await _is_token_valid(token, app, client_id)
        if not valid:
            return _redirect_to_login(settings)
        if request.args.get("cancel") == "1":
            return response.json(
                {
                    "error": "access_denied",
                    "error_description": "The user cancelled the authorization request.",
                },
                status=400,
            )

        consent_given = request.args.get("consent") in {"1", "true", "yes", "on"}
        if not consent_given:
            user_hint = request.args.get("user") or request.args.get("email") or request.args.get("login_hint")
            return _render_consent_page(settings, request, user_hint)

        token = refreshed or token
        redirect_uri = request.args.get("redirect_uri")
        state = request.args.get("state")
        resource = request.args.get("resource")
        if redirect_uri:
            return _redirect_with_token(redirect_uri, token, state, settings, resource=resource)
        return response.json(
            {
                "access_token": token,
                "token_type": "JWT",
                "expires_in": int(settings.access_token_ttl_seconds),
                "status": "authorized",
                **({"resource": resource} if resource else {}),
            }
        )

    async def oauth_register(request: Request) -> HTTPResponse:
        if request.method != "POST":
            return response.json(
                {
                    "error": "invalid_request",
                    "error_description": "dynamic client registration must use POST",
                },
                status=405,
                headers={"Allow": "POST", "Cache-Control": "no-store", "Pragma": "no-cache"},
            )
        content_type = (request.headers.get("content-type") or "").split(";", 1)[0].lower()
        if content_type not in ("application/json", ""):
            return response.json(
                {"error": "invalid_request", "error_description": "content-type must be application/json"},
                status=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )
        try:
            body = request.json or {}
        except Exception:  # pragma: no cover - defensive guard for malformed bodies
            body = {}

        try:
            payload, status = _build_registration_payload(body, settings)
            await app.ctx.registration_store.set(payload["client_id"], payload)
            headers = {
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "Access-Control-Allow-Origin": "*",
            }
            if payload.get("registration_client_uri"):
                headers["Location"] = payload["registration_client_uri"]
            return response.json(payload, status=status, headers=headers)
        except Exception as exc:  # pragma: no cover - defensive guard to avoid HTML error pages
            logger.exception("registration error")
            return response.json(
                {"error": "server_error", "error_description": str(exc)},
                status=500,
                headers={
                    "Cache-Control": "no-store",
                    "Pragma": "no-cache",
                    "Access-Control-Allow-Origin": "*",
                },
            )

    async def oauth_registration_get(request: Request, client_id: str) -> HTTPResponse:
        try:
            record = await app.ctx.registration_store.get(client_id)
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("registration read error")
            return response.json(
                {"error": "server_error", "error_description": str(exc)},
                status=500,
                headers={
                    "Cache-Control": "no-store",
                    "Pragma": "no-cache",
                    "Access-Control-Allow-Origin": "*",
                },
            )
        if not record:
            return response.json({"error": "not_found"}, status=404)

        token = request.headers.get("authorization") or ""
        if token.lower().startswith("bearer "):
            token = token.split(" ", 1)[1]
        expected = record.get("registration_access_token")
        if expected and token != expected:
            return response.json(
                {"error": "invalid_token"},
                status=401,
                headers={
                    "Cache-Control": "no-store",
                    "Pragma": "no-cache",
                    "Access-Control-Allow-Origin": "*",
                },
            )

        if request.method == "GET":
            return response.json(
                record,
                headers={
                    "Cache-Control": "no-store",
                    "Pragma": "no-cache",
                    "Access-Control-Allow-Origin": "*",
                },
            )

        if request.method == "PUT":
            content_type = (request.headers.get("content-type") or "").split(";", 1)[0].lower()
            if content_type not in ("application/json", ""):
                return response.json(
                    {"error": "invalid_request", "error_description": "content-type must be application/json"},
                    status=400,
                    headers={"Cache-Control": "no-store", "Pragma": "no-cache", "Access-Control-Allow-Origin": "*"},
                )
            try:
                body = request.json or {}
            except Exception:
                body = {}
            try:
                payload, status = _build_registration_payload(body, settings, existing=record)
                await app.ctx.registration_store.set(payload["client_id"], payload)
            except Exception as exc:  # pragma: no cover - defensive
                logger.exception("registration update error")
                return response.json(
                    {"error": "server_error", "error_description": str(exc)},
                    status=500,
                    headers={
                        "Cache-Control": "no-store",
                        "Pragma": "no-cache",
                        "Access-Control-Allow-Origin": "*",
                    },
                )
            headers = {
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "Location": payload.get("registration_client_uri", ""),
                "Access-Control-Allow-Origin": "*",
            }
            return response.json(payload, status=status, headers=headers)

        if request.method == "DELETE":
            try:
                await app.ctx.registration_store.delete(client_id)
            except Exception as exc:  # pragma: no cover - defensive
                logger.exception("registration delete error")
                return response.json(
                    {"error": "server_error", "error_description": str(exc)},
                    status=500,
                    headers={
                        "Cache-Control": "no-store",
                        "Pragma": "no-cache",
                        "Access-Control-Allow-Origin": "*",
                    },
                )
            return response.empty(
                status=204,
                headers={
                    "Cache-Control": "no-store",
                    "Pragma": "no-cache",
                    "Access-Control-Allow-Origin": "*",
                },
            )

        return response.json(
            {
                "error": "invalid_request",
                "error_description": "client read/update requires GET or PUT; delete requires DELETE",
            },
            status=405,
            headers={
                "Allow": "GET,PUT,DELETE",
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "Access-Control-Allow-Origin": "*",
            },
        )

    state_path = "/app/state"

    async def app_state(request: Request) -> HTTPResponse:
        if request.method == "OPTIONS":
            return response.empty(
                status=204,
                headers={
                    "Allow": "GET,PUT,DELETE,OPTIONS",
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET,PUT,DELETE,OPTIONS",
                    "Access-Control-Allow-Headers": "content-type",
                },
            )

        state_id = request.args.get("state_id")
        if not state_id:
            try:
                body = request.json or {}
            except Exception:
                body = {}
            if isinstance(body, dict):
                state_id = body.get("state_id")
        if not state_id:
            return response.json(
                {"error": "invalid_request", "error_description": "state_id is required"},
                status=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache", "Access-Control-Allow-Origin": "*"},
            )

        if request.method == "GET":
            state = await app.ctx.state_store.get(state_id)
            if state is None:
                return response.json(
                    {"error": "not_found"},
                    status=404,
                    headers={"Cache-Control": "no-store", "Pragma": "no-cache", "Access-Control-Allow-Origin": "*"},
                )
            return response.json(
                {"state": state},
                headers={"Cache-Control": "no-store", "Pragma": "no-cache", "Access-Control-Allow-Origin": "*"},
            )

        if request.method == "PUT":
            content_type = (request.headers.get("content-type") or "").split(";", 1)[0].lower()
            if content_type not in ("application/json", ""):
                return response.json(
                    {"error": "invalid_request", "error_description": "content-type must be application/json"},
                    status=400,
                    headers={"Cache-Control": "no-store", "Pragma": "no-cache", "Access-Control-Allow-Origin": "*"},
                )
            try:
                body = request.json or {}
            except Exception:
                body = {}
            if not isinstance(body, dict):
                return response.json(
                    {"error": "invalid_request", "error_description": "state body must be JSON"},
                    status=400,
                    headers={"Cache-Control": "no-store", "Pragma": "no-cache", "Access-Control-Allow-Origin": "*"},
                )
            state = body.get("state", body)
            if not isinstance(state, dict):
                return response.json(
                    {"error": "invalid_request", "error_description": "state must be an object"},
                    status=400,
                    headers={"Cache-Control": "no-store", "Pragma": "no-cache", "Access-Control-Allow-Origin": "*"},
                )
            await app.ctx.state_store.set(state_id, state)
            return response.json(
                {"state": state},
                headers={"Cache-Control": "no-store", "Pragma": "no-cache", "Access-Control-Allow-Origin": "*"},
            )

        if request.method == "DELETE":
            await app.ctx.state_store.delete(state_id)
            return response.empty(
                status=204,
                headers={
                    "Cache-Control": "no-store",
                    "Pragma": "no-cache",
                    "Access-Control-Allow-Origin": "*",
                },
            )

        return response.json(
            {
                "error": "invalid_request",
                "error_description": "state endpoint supports GET, PUT, DELETE",
            },
            status=405,
            headers={
                "Allow": "GET,PUT,DELETE,OPTIONS",
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET,PUT,DELETE,OPTIONS",
            },
        )

    # Register OAuth routes at both root and MCP path with unique names.
    app.add_route(oauth_validate, "/oauth/validate", methods=["GET"], name="oauth_validate_root")
    app.add_route(
        oauth_validate,
        f"{mcp_prefix}/oauth/validate",
        methods=["GET"],
        name="oauth_validate_mcp",
    )
    app.add_route(oauth_token, "/oauth/token", methods=["POST"], name="oauth_token_root")
    app.add_route(
        oauth_token,
        f"{mcp_prefix}/oauth/token",
        methods=["POST"],
        name="oauth_token_mcp",
    )
    app.add_route(
        oauth_authorize,
        "/oauth/authorize",
        methods=["GET"],
        name="oauth_authorize_root",
    )
    app.add_route(
        oauth_authorize,
        f"{mcp_prefix}/oauth/authorize",
        methods=["GET"],
        name="oauth_authorize_mcp",
    )
    app.add_route(
        oauth_register,
        "/oauth/register",
        methods=["POST", "GET", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
        name="oauth_register_root",
        strict_slashes=False,
    )
    app.add_route(
        oauth_register,
        f"{mcp_prefix}/oauth/register",
        methods=["POST", "GET", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
        name="oauth_register_mcp",
        strict_slashes=False,
    )
    app.add_route(
        oauth_registration_get,
        "/oauth/register/<client_id>",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
        name="oauth_register_get_root",
        strict_slashes=False,
    )
    app.add_route(
        oauth_registration_get,
        f"{mcp_prefix}/oauth/register/<client_id>",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
        name="oauth_register_get_mcp",
        strict_slashes=False,
    )

    app.add_route(
        app_state, state_path, methods=["GET", "PUT", "DELETE", "OPTIONS"], name="app_state_root", strict_slashes=False
    )
    app.add_route(
        app_state,
        f"{mcp_prefix}{state_path}",
        methods=["GET", "PUT", "DELETE", "OPTIONS"],
        name="app_state_mcp",
        strict_slashes=False,
    )

    well_known_path = "/.well-known/oauth-authorization-server"
    mcp_prefix = settings.mcp_path.rstrip("/") or "/mcp"

    async def oauth_metadata(_: Request) -> HTTPResponse:
        payload = _build_oauth_metadata(settings)
        if not payload:
            return response.json({"error": "oauth not configured"}, status=404)
        return response.json(payload)

    # Handle both /.well-known/oauth-authorization-server and /mcp/.well-known/oauth-authorization-server
    # plus the reversed order some clients may probe: /.well-known/oauth-authorization-server/mcp.
    well_known_paths = (well_known_path, f"{mcp_prefix}{well_known_path}", f"{well_known_path}{mcp_prefix}")
    for idx, path in enumerate(well_known_paths):
        app.add_route(oauth_metadata, path, methods=["GET"], name=f"oauth_metadata_{idx}")

    resource_well_known = "/.well-known/oauth-protected-resource"

    async def resource_metadata(_: Request) -> HTTPResponse:
        payload = _build_resource_metadata(settings)
        return response.json(
            payload,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
            },
        )

    resource_paths = (resource_well_known, f"{mcp_prefix}{resource_well_known}", f"{resource_well_known}{mcp_prefix}")
    for idx, path in enumerate(resource_paths):
        app.add_route(resource_metadata, path, methods=["GET"], name=f"oauth_resource_metadata_{idx}")

    @app.exception(NotFound)
    async def handle_not_found(_: Request, exc: NotFound) -> HTTPResponse:  # pragma: no cover - integration safety
        return response.json(
            {"error": "not_found", "detail": getattr(exc, "message", "") or "resource not found"},
            status=404,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    @app.exception(MethodNotSupported)
    async def handle_method_not_supported(
        request: Request, exc: MethodNotSupported
    ) -> HTTPResponse:  # pragma: no cover - integration safety
        allow = ",".join(exc.allowed_methods) if getattr(exc, "allowed_methods", None) else None
        headers = {"Cache-Control": "no-store", "Pragma": "no-cache"}
        if allow:
            headers["Allow"] = allow
        return response.json(
            {
                "error": "invalid_request",
                "error_description": f"method {request.method} not allowed for {request.path}",
            },
            status=exc.status_code,
            headers=headers,
        )

    @app.exception(InvalidUsage)
    async def handle_invalid_usage(
        _: Request, exc: InvalidUsage
    ) -> HTTPResponse:  # pragma: no cover - integration safety
        return response.json(
            {
                "error": "invalid_request",
                "error_description": getattr(exc, "args", ["invalid request"])[0],
            },
            status=getattr(exc, "status_code", 400),
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    @app.exception(SanicException)
    async def handle_sanic_exc(
        _: Request, exc: SanicException
    ) -> HTTPResponse:  # pragma: no cover - integration safety
        return response.json(
            {
                "error": "server_error",
                "error_description": getattr(exc, "args", ["unexpected server error"])[0],
            },
            status=getattr(exc, "status_code", 500),
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    return app


def _redirect_to_login(settings: AppSettings) -> HTTPResponse:
    if settings.login_url:
        login_url = str(settings.login_url)
        redirect_target = str(settings.post_login_redirect_url) if settings.post_login_redirect_url else None

        if redirect_target:
            parsed = urlparse(login_url)
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            query["redirect_url"] = redirect_target
            login_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))

        return response.redirect(login_url)
    return response.json({"error": "unauthorized"}, status=401)


def _redirect_with_token(
    redirect_uri: str, token: str, state: str | None, settings: AppSettings, *, resource: str | None = None
) -> HTTPResponse:
    """Redirect back to client with token embedded as 'code' and optional state."""
    parsed = urlparse(redirect_uri)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query.update(
        {
            "code": token,
            "token_type": "JWT",
            "expires_in": int(settings.access_token_ttl_seconds),
        }
    )
    if state:
        query["state"] = state
    if resource:
        query["resource"] = resource
    redirect_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
    return response.redirect(redirect_url)


def _get_logo_data_uri() -> str | None:
    # Generic implementation: look for a logo.png in static
    global _DEFAULT_LOGO_DATA_URI  # pylint: disable=global-statement
    if _DEFAULT_LOGO_DATA_URI is not None:
        return _DEFAULT_LOGO_DATA_URI

    logo_path = Path(__file__).resolve().parent / "static" / "logo.png"
    if not logo_path.exists():
        _DEFAULT_LOGO_DATA_URI = None
        return None
    try:
        encoded = base64.b64encode(logo_path.read_bytes()).decode("ascii")
        _DEFAULT_LOGO_DATA_URI = f"data:image/png;base64,{encoded}"
    except Exception as exc:  # pragma: no cover - defensive fallback
        logger.warning("Failed to load logo for consent screen: %s", exc)
        _DEFAULT_LOGO_DATA_URI = None
    return _DEFAULT_LOGO_DATA_URI


def _render_consent_page(settings: AppSettings, request: Request, user_hint: str | None) -> HTTPResponse:
    params = {
        key: request.args.get(key)
        for key in (
            "redirect_uri",
            "state",
            "client_id",
            "scope",
        )
        if request.args.get(key)
    }
    html_page = _build_consent_html(settings, params, user_hint, request.path)
    return response.html(html_page)


def _build_consent_html(
    settings: AppSettings,
    params: dict[str, str],
    user_hint: str | None,
    action_path: str,
) -> str:
    logo_src = None  # _get_logo_data_uri() # Generic version has no logo by default
    app_name = "MCP OAuth Server"
    user_display = user_hint or "Your account"
    brand_letter = app_name[:1].upper()
    brand_mark = (
        f'<div class="brand-mark image"><img src="{logo_src}" alt="App logo" /></div>'
        if logo_src
        else f'<div class="brand-mark">{brand_letter}</div>'
    )
    hidden_inputs = "\n".join(
        f'<input type="hidden" name="{html.escape(key)}" value="{html.escape(value)}" />'
        for key, value in params.items()
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Authorize {app_name}</title>
  <style>
    :root {{
      --bg: #f7f7fb;
      --card: #ffffff;
      --border: #e6e7ec;
      --text: #0f1115;
      --muted: #4f5668;
      --accent: #0f1115;
      --shadow: 0 15px 60px rgba(15, 17, 21, 0.08);
      --radius: 24px;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: "Manrope", "Helvetica Neue", Arial, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 20px;
    }}
    .card {{
      width: min(520px, 100%);
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 42px 44px;
      text-align: center;
    }}
    .brand-mark {{
      width: 68px;
      height: 68px;
      border-radius: 20px;
      background: #0f1115;
      color: #ffffff;
      display: grid;
      place-items: center;
      font-size: 26px;
      font-weight: 700;
      margin: 0 auto 22px;
    }}
    .brand-mark.image {{
      background: #ffffff;
      border: 1px solid var(--border);
      padding: 10px;
    }}
    .brand-mark.image img {{
      max-width: 100%;
      max-height: 100%;
      object-fit: contain;
      border-radius: 16px;
    }}
    h1 {{
      margin: 0 0 14px;
      font-size: 28px;
      line-height: 1.2;
      letter-spacing: -0.3px;
    }}
    h1 .brand {{ font-weight: 700; }}
    .identity-pill {{
      display: inline-flex;
      align-items: center;
      gap: 10px;
      padding: 10px 14px;
      background: #f8f9fb;
      border: 1px solid var(--border);
      border-radius: 999px;
      margin: 12px auto 18px;
      color: var(--text);
      font-weight: 600;
    }}
    .identity-pill .avatar {{
      width: 32px;
      height: 32px;
      border-radius: 50%;
      background: #0f1115;
      color: #ffffff;
      display: grid;
      place-items: center;
      font-weight: 700;
      font-size: 14px;
    }}
    .blurb {{
      margin: 10px 0 6px;
      font-size: 15px;
      color: var(--text);
    }}
    .muted {{
      margin: 0 0 12px;
      font-size: 14px;
      color: var(--muted);
    }}
    form.actions {{
      display: flex;
      gap: 14px;
      justify-content: center;
      margin: 26px 0 18px;
      flex-wrap: wrap;
    }}
    .btn {{
      padding: 14px 26px;
      border-radius: 999px;
      font-weight: 700;
      font-size: 15px;
      border: 1px solid transparent;
      cursor: pointer;
      min-width: 140px;
      transition: transform 0.1s ease, box-shadow 0.15s ease, background 0.2s ease, color 0.2s ease;
    }}
    .btn:focus {{ outline: none; box-shadow: 0 0 0 3px rgba(15, 17, 21, 0.2); }}
    .btn:hover {{ transform: translateY(-1px); }}
    .btn.ghost {{
      background: #ffffff;
      border-color: #d3d6de;
      color: var(--text);
    }}
    .btn.primary {{
      background: #0f1115;
      color: #ffffff;
      border-color: #0f1115;
    }}
    .links {{
      margin-top: 10px;
      display: flex;
      gap: 12px;
      justify-content: center;
      align-items: center;
      font-size: 14px;
      color: var(--muted);
    }}
    .links a {{
      color: var(--muted);
      text-decoration: none;
      font-weight: 600;
    }}
    .links a:hover {{ color: var(--text); }}
    @media (max-width: 520px) {{
      .card {{ padding: 32px 28px; }}
      .btn {{ width: 100%; }}
      form.actions {{ flex-direction: column; }}
    }}
  </style>
</head>
<body>
  <div class="card">
    {brand_mark}
    <h1>Sign in to <span class="brand">{html.escape(app_name)}</span> with OAuth</h1>
    <div class="identity-pill">
      <span class="avatar">{brand_letter}</span>
      <span class="identity">{html.escape(user_display)}</span>
    </div>
    <p class="blurb">By continuing, ChatGPT will share your name, email, and profile picture with
    {html.escape(app_name)} to link your account.</p>
    <p class="muted">{html.escape(app_name)} will not receive your chat history.</p>
    <form class="actions" method="get" action="{html.escape(action_path)}">
      {hidden_inputs}
      <input type="hidden" name="consent" value="1" />
      <button class="btn ghost" type="submit" name="cancel" value="1">Cancel</button>
      <button class="btn primary" type="submit">Continue</button>
    </form>
    <div class="links">
      <a href="#" target="_blank" rel="noreferrer noopener">Terms of Use</a>
      <span class="divider">|</span>
      <a href="#" target="_blank" rel="noreferrer noopener">Privacy Policy</a>
    </div>
  </div>
</body>
</html>
"""


def _extract_auth_token(request: Request, settings: AppSettings) -> str | None:
    auth_header = request.headers.get("authorization")
    if auth_header:
        return auth_header.split(" ", 1)[1] if " " in auth_header else auth_header
    if settings.cookie_name:
        raw_cookie = request.cookies.get(settings.cookie_name) or settings.cookie_value
        if raw_cookie:
            # delegated extractor
            extractor = getattr(request.app.ctx, "cookie_token_extractor", default_token_extractor)
            token = extractor(raw_cookie)
            if token:
                return token

    return None


async def _is_token_valid(token: str, app: Sanic, client_id: str | None) -> tuple[bool, str | None]:
    """
    Validate the token against the upstream API or local logic.
    Returns (is_valid, refreshed_token_if_any).
    """
    # TODO: Implement actual upstream validation here if needed.
    # For the template, we assume if we have a token, it's valid until proven otherwise
    # or validated by middleware/upstream usage.
    if token:
        return True, None
    return False, None


def _oauth_base_paths(settings: AppSettings) -> tuple[str, str]:
    """Return (issuer, base_path) used for OAuth metadata/registration."""
    if settings.public_base_url:
        issuer = str(settings.public_base_url).rstrip("/")
        return issuer, issuer
    issuer = f"http://{settings.mcp_host}:{settings.mcp_port}"
    mcp_prefix = settings.mcp_path.rstrip("/") or "/mcp"
    return issuer, f"{issuer}{mcp_prefix}"


def _is_valid_redirect_uri(uri: str) -> bool:
    parsed = urlparse(uri)
    return bool(parsed.scheme) and bool(parsed.netloc)


def _build_registration_payload(
    body: Any,
    settings: AppSettings,
    existing: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], int]:
    if not isinstance(body, dict):
        return (
            {
                "error": "invalid_client_metadata",
                "error_description": "registration payload must be a JSON object",
            },
            400,
        )

    grant_types = body.get("grant_types") or (existing.get("grant_types") if existing else ["authorization_code"])
    if not isinstance(grant_types, list) or not all(isinstance(gt, str) for gt in grant_types):
        return (
            {
                "error": "invalid_client_metadata",
                "error_description": "grant_types must be a list of strings",
            },
            400,
        )

    response_types = body.get("response_types")
    if not response_types:
        response_types = (
            existing.get("response_types")
            if existing and existing.get("response_types") is not None
            else (["code"] if any(gt in {"authorization_code", "implicit"} for gt in grant_types) else [])
        )
    if not isinstance(response_types, list) or not all(isinstance(rt, str) for rt in response_types):
        return (
            {
                "error": "invalid_client_metadata",
                "error_description": "response_types must be a list of strings",
            },
            400,
        )
    redirect_uris = body.get("redirect_uris")
    redirect_uris = redirect_uris if redirect_uris is not None else (existing.get("redirect_uris") if existing else [])

    if not isinstance(redirect_uris, list) or not all(isinstance(uri, str) for uri in redirect_uris):
        return (
            {
                "error": "invalid_redirect_uri",
                "error_description": "redirect_uris must be a list of strings",
            },
            400,
        )

    redirect_required = any(gt in {"authorization_code", "implicit"} for gt in grant_types) or any(
        rt in {"code", "token"} for rt in response_types
    )
    if redirect_required and not redirect_uris:
        return (
            {
                "error": "invalid_redirect_uri",
                "error_description": "redirect_uris are required for authorization_code/implicit flows",
            },
            400,
        )

    if redirect_uris and not all(_is_valid_redirect_uri(uri) for uri in redirect_uris):
        return (
            {
                "error": "invalid_redirect_uri",
                "error_description": "redirect_uris must be absolute URLs",
            },
            400,
        )

    _, base_path = _oauth_base_paths(settings)
    token_endpoint_auth_method = (
        body.get("token_endpoint_auth_method")
        or (existing.get("token_endpoint_auth_method") if existing else None)
        or "none"
    )
    client_id = existing.get("client_id") if existing else body.get("client_id") or uuid.uuid4().hex
    try:
        uuid.UUID(str(client_id))
    except Exception:
        client_id = uuid.uuid4().hex

    client_secret = body.get("client_secret") or (existing.get("client_secret") if existing else None)
    if token_endpoint_auth_method != "none" and not client_secret:
        client_secret = secrets.token_urlsafe(32)
    issued_at = existing.get("client_id_issued_at") if existing else int(time.time())
    registration_access_token = existing.get("registration_access_token") if existing else uuid.uuid4().hex
    registration_client_uri = (
        existing.get("registration_client_uri")
        if existing
        else f"{base_path}/oauth/register/{client_id}"
    )
    status = 200 if existing else 201
    payload: dict[str, Any] = {
        "client_id": client_id,
        "client_id_issued_at": issued_at,
        "client_secret_expires_at": 0 if client_secret else 0,
        "token_type": "Bearer",
        "registration_access_token": registration_access_token,
        "registration_client_uri": registration_client_uri,
        "token_endpoint_auth_method": token_endpoint_auth_method,
        "grant_types": grant_types,
        "response_types": response_types,
        "redirect_uris": redirect_uris,
    }
    if client_secret:
        payload["client_secret"] = client_secret
    client_name = body.get("client_name")
    if client_name:
        payload["client_name"] = client_name
    elif existing and existing.get("client_name"):
        payload["client_name"] = existing["client_name"]

    if isinstance(body.get("scope"), str):
        payload["scope"] = body["scope"]
    elif existing and existing.get("scope"):
        payload["scope"] = existing["scope"]

    if isinstance(body.get("jwks"), dict):
        payload["jwks"] = body["jwks"]
    elif existing and existing.get("jwks"):
        payload["jwks"] = existing["jwks"]

    if isinstance(body.get("jwks_uri"), str):
        payload["jwks_uri"] = body["jwks_uri"]
    elif existing and existing.get("jwks_uri"):
        payload["jwks_uri"] = existing["jwks_uri"]

    if isinstance(body.get("software_statement"), str):
        payload["software_statement"] = body["software_statement"]
    elif existing and existing.get("software_statement"):
        payload["software_statement"] = existing["software_statement"]

    if isinstance(body.get("software_id"), str):
        payload["software_id"] = body["software_id"]
    elif existing and existing.get("software_id"):
        payload["software_id"] = existing["software_id"]

    if isinstance(body.get("software_version"), str):
        payload["software_version"] = body["software_version"]
    elif existing and existing.get("software_version"):
        payload["software_version"] = existing["software_version"]

    return payload, status


def _build_oauth_metadata(settings: AppSettings) -> dict[str, Any] | None:
    issuer, base_path = _oauth_base_paths(settings)

    authorization_endpoint = (
        str(settings.oauth_authorize_url)
        if settings.oauth_authorize_url
        else f"{base_path}/oauth/authorize"
    )
    token_endpoint = (
        str(settings.oauth_token_url)
        if settings.oauth_token_url
        else f"{base_path}/oauth/token"
    )
    registration_endpoint = (
        str(settings.oauth_registration_url)
        if settings.oauth_registration_url
        else f"{base_path}/oauth/register"
    )
    if not authorization_endpoint or not token_endpoint:
        return None
    data: dict[str, Any] = {
        "issuer": issuer,
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
        "registration_endpoint": registration_endpoint,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
    }
    scopes = settings.scope_list
    if scopes:
        data["scopes_supported"] = scopes
    if settings.oauth_redirect_url:
        data["redirect_uris"] = [str(settings.oauth_redirect_url)]
    return data


def _build_resource_metadata(settings: AppSettings) -> dict[str, Any]:
    issuer, base_path = _oauth_base_paths(settings)
    token_endpoint = (
        str(settings.oauth_token_url)
        if settings.oauth_token_url
        else f"{base_path}/oauth/token"
    )
    authorization_servers = [issuer, token_endpoint]
    metadata: dict[str, Any] = {
        "resource": base_path,
        "authorization_servers": authorization_servers,
    }
    scopes = settings.scope_list
    if scopes:
        metadata["scopes_supported"] = scopes
    return metadata


def _decode_headers(raw_headers: list[tuple[bytes, bytes]]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key, value in raw_headers:
        decoded_key = key.decode("latin-1")
        decoded_value = value.decode("latin-1")
        if decoded_key in headers:
            headers[decoded_key] = f"{headers[decoded_key]}, {decoded_value}"
        else:
            headers[decoded_key] = decoded_value
    return headers


def _build_scope(request: Request) -> dict[str, Any]:
    query_string = request.query_string.encode()
    raw_path = request.path.encode()
    if query_string:
        raw_path = raw_path + b"?" + query_string

    host_header = request.headers.get("host", "localhost")
    if ":" in host_header:
        server_name, server_port = host_header.rsplit(":", 1)
        try:
            server_port_int = int(server_port)
        except ValueError:
            server_port_int = request.app.ctx.settings.mcp_port
    else:
        server_name = host_header
        server_port_int = request.app.ctx.settings.mcp_port

    conn_info = getattr(request, "conn_info", None)
    client = getattr(conn_info, "client", (request.remote_addr, None))
    server_port_int = getattr(conn_info, "server_port", server_port_int)
    server_name = getattr(conn_info, "server", server_name)
    server = (server_name, server_port_int)

    headers = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in request.headers.items()]

    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": request.version,
        "method": request.method,
        "scheme": request.scheme,
        "path": request.path,
        "raw_path": raw_path,
        "query_string": query_string,
        "headers": headers,
        "client": client,
        "server": server,
        "root_path": "",
    }


def _configure_uvloop(app: Sanic) -> None:
    try:
        import uvloop  # type: ignore

        uvloop.install()
        app.config.USE_UVLOOP = True
    except Exception as exc:  # pragma: no cover - fallback when unsupported
        logger.warning("uvloop unavailable or unsupported; falling back to asyncio: %s", exc)
        app.config.USE_UVLOOP = False


def _register_lifecycle_noops(app: Sanic) -> None:
    @app.signal("http.lifecycle.begin")
    async def _on_http_begin(**_: Any) -> None:  # pragma: no cover - trivial handler
        return None

    @app.signal("http.lifecycle.send")
    async def _on_http_send(**_: Any) -> None:  # pragma: no cover - trivial handler
        return None

    @app.signal("http.lifecycle.complete")
    async def _on_http_complete(**_: Any) -> None:  # pragma: no cover - trivial handler
        return None


# pylint: disable=too-many-statements
async def _proxy_to_asgi(request: Request, session_manager: StreamableHTTPSessionManager) -> HTTPResponse:
    scope = _build_scope(request)
    body = request.body or b""
    body_sent = False

    status_holder = {"status": 200}
    header_holder: list[tuple[bytes, bytes]] = []
    start_event = asyncio.Event()
    finish_event = asyncio.Event()
    chunk_queue: asyncio.Queue[bytes | None] = asyncio.Queue()

    async def receive() -> dict[str, Any]:
        nonlocal body_sent
        if not body_sent:
            body_sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            status_holder["status"] = message["status"]
            header_holder[:] = message.get("headers", [])
            start_event.set()
        elif message["type"] == "http.response.body":
            await chunk_queue.put(message.get("body", b""))
            if not message.get("more_body", False):
                await chunk_queue.put(None)
                finish_event.set()

    async def run_transport() -> None:
        try:
            await session_manager.handle_request(scope, receive, send)
        finally:
            if not start_event.is_set():
                start_event.set()
            if not finish_event.is_set():
                await chunk_queue.put(None)
                finish_event.set()

    request.app.add_task(run_transport())
    await start_event.wait()

    headers = _decode_headers(header_holder)
    status = status_holder["status"]
    content_type = headers.pop("content-type", None)

    async def streaming(resp) -> None:
        while True:
            chunk = await chunk_queue.get()
            if chunk is None:
                break
            await resp.write(chunk)

    return ResponseStream(
        streaming,
        status=status,
        headers=headers,
        content_type=content_type,
    )
