import json
import time
import uuid

import pytest

from mcp_oauth_server.config import AppSettings
from mcp_oauth_server.http_server import (
    _build_consent_html,
    _build_oauth_metadata,
    _build_registration_payload,
    _build_resource_metadata,
    _decode_headers,
    _extract_auth_token,
    _redirect_to_login,
    _redirect_with_token,
    create_app,
)
from mcp_oauth_server.mcp_server import build_mcp_server
from mcp_oauth_server.session_store import AppStateStore


def test_decode_headers_combines_duplicates():
    raw = [
        (b"content-type", b"application/json"),
        (b"content-type", b"text/event-stream"),
    ]
    headers = _decode_headers(raw)
    assert headers["content-type"] == "application/json, text/event-stream"


def test_redirect_to_login_with_redirect_url():
    settings = AppSettings(
        login_url="https://login.example.com/login/",
        post_login_redirect_url="https://dev.example.com/mcp",
    )
    resp = _redirect_to_login(settings)
    assert resp.status == 302
    expected_url = (
        "https://login.example.com/login/?redirect_url=https%3A%2F%2Fdev.example.com%2Fmcp"
    )
    assert resp.headers["Location"] == expected_url


def test_redirect_to_login_without_login_url():
    settings = AppSettings(login_url=None)
    resp = _redirect_to_login(settings)
    assert resp.status == 401
    payload = json.loads(resp.body)
    assert payload.get("error") == "unauthorized"


def test_extracts_fallback_cookie():
    settings = AppSettings(cookie_name="auth_cookie")

    class DummyReq:
        headers = {}
        cookies = {"auth_cookie": '{"auth":{"token":"jwt-token"}}'}

        class App:
            class Ctx:
                pass
            ctx = Ctx()
        app = App()

    token = _extract_auth_token(DummyReq(), settings)
    assert token == "jwt-token"


@pytest.mark.asyncio
async def test_http_lifecycle_signals_registered():
    settings = AppSettings()
    server = build_mcp_server(settings)
    app = create_app(settings, server)
    app.signal_router.finalize()

    for event in ("http.lifecycle.begin", "http.lifecycle.send", "http.lifecycle.complete"):
        await app.dispatch(event, inline=True)


@pytest.mark.asyncio
async def test_well_known_oauth_metadata():
    settings = AppSettings(
        oauth_authorize_url="https://login.example.com/auth",
        oauth_token_url="https://login.example.com/token",
        oauth_redirect_url="https://dev.example.com/mcp",
        oauth_scope="read write",
    )
    data = _build_oauth_metadata(settings)
    assert data is not None
    assert data["authorization_endpoint"] == "https://login.example.com/auth"
    assert data["token_endpoint"] == "https://login.example.com/token"
    assert data["redirect_uris"] == ["https://dev.example.com/mcp"]
    assert data["registration_endpoint"] == "http://127.0.0.1:8042/mcp/oauth/register"
    assert "refresh_token" in data["grant_types_supported"]
    assert set(data["token_endpoint_auth_methods_supported"]) == {"none", "client_secret_basic", "client_secret_post"}
    assert data["scopes_supported"] == ["read", "write"]


def test_well_known_oauth_metadata_defaults():
    settings = AppSettings()
    data = _build_oauth_metadata(settings)
    assert data["authorization_endpoint"] == "http://127.0.0.1:8042/mcp/oauth/authorize"
    assert data["token_endpoint"] == "http://127.0.0.1:8042/mcp/oauth/token"
    assert data["registration_endpoint"] == "http://127.0.0.1:8042/mcp/oauth/register"


def test_well_known_oauth_metadata_public_url():
    settings = AppSettings(public_base_url="https://dev.example.com/mcp")
    data = _build_oauth_metadata(settings)
    assert data["authorization_endpoint"] == "https://dev.example.com/mcp/oauth/authorize"
    assert data["token_endpoint"] == "https://dev.example.com/mcp/oauth/token"
    assert data["registration_endpoint"] == "https://dev.example.com/mcp/oauth/register"


def test_well_known_oauth_metadata_registration_override():
    settings = AppSettings(
        public_base_url="https://dev.example.com/mcp",
        oauth_registration_url="https://accounts.example.com/register",
    )
    data = _build_oauth_metadata(settings)
    assert data["registration_endpoint"] == "https://accounts.example.com/register"


def test_resource_metadata_defaults_and_public_url():
    settings = AppSettings()
    data = _build_resource_metadata(settings)
    assert data["resource"] == "http://127.0.0.1:8042/mcp"
    assert "authorization_servers" in data and data["authorization_servers"]
    assert "http://127.0.0.1:8042" in data["authorization_servers"]
    assert any(item.endswith("/oauth/token") for item in data["authorization_servers"])

    pub_settings = AppSettings(public_base_url="https://dev.example.com/mcp", oauth_scope="read write")
    data = _build_resource_metadata(pub_settings)
    assert data["resource"] == "https://dev.example.com/mcp"
    assert data["scopes_supported"] == ["read", "write"]


def test_consent_page_includes_links():
    settings = AppSettings()
    html_page = _build_consent_html(
        settings,
        {"redirect_uri": "https://app.example.com/callback", "state": "abc", "client_id": "cid-123"},
        "user@example.com",
        "/oauth/authorize",
    )
    assert 'name="redirect_uri"' in html_page and "https://app.example.com/callback" in html_page
    assert 'name="state"' in html_page and "abc" in html_page
    assert 'name="client_id"' in html_page and "cid-123" in html_page
    assert 'name="consent" value="1"' in html_page


@pytest.mark.asyncio
async def test_app_state_store_round_trip():
    from mcp_oauth_server.storage import MemoryStorageBackend
    store = AppStateStore(MemoryStorageBackend())
    state_id = "s1"
    data = {"foo": "bar"}
    await store.set(state_id, data)
    fetched = await store.get(state_id)
    assert fetched == data
    await store.delete(state_id)
    assert await store.get(state_id) is None


def test_oauth_register_requires_redirect_uri_for_auth_code():
    settings = AppSettings()
    payload, status = _build_registration_payload({}, settings)
    assert status == 400
    assert payload["error"] == "invalid_redirect_uri"


def test_oauth_register_validates_redirect_uri_format():
    settings = AppSettings()
    payload, status = _build_registration_payload({"redirect_uris": ["/relative"]}, settings)
    assert status == 400
    assert payload["error"] == "invalid_redirect_uri"


def test_oauth_register_validates_metadata_lists():
    settings = AppSettings()
    payload, status = _build_registration_payload({"grant_types": "authorization_code"}, settings)
    assert status == 400
    assert payload["error"] == "invalid_client_metadata"


def test_oauth_register_allows_non_redirect_grant():
    settings = AppSettings()
    payload, status = _build_registration_payload({"grant_types": ["client_credentials"]}, settings)
    assert status == 201
    assert payload["grant_types"] == ["client_credentials"]
    assert payload["response_types"] == []
    assert payload["redirect_uris"] == []


def test_oauth_register_returns_rfc7591_fields():
    settings = AppSettings()
    redirect_uris = ["https://app.example.com/callback"]
    payload, status = _build_registration_payload(
        {"redirect_uris": redirect_uris, "client_name": "Demo"},
        settings,
    )
    assert status == 201
    assert payload["client_name"] == "Demo"
    assert payload["redirect_uris"] == redirect_uris
    assert payload["grant_types"] == ["authorization_code"]
    assert payload["response_types"] == ["code"]
    assert payload["token_endpoint_auth_method"] == "none"
    assert payload["client_secret_expires_at"] == 0
    assert payload["registration_access_token"]
    assert payload["token_type"] == "Bearer"
    assert payload["registration_client_uri"].startswith("http://127.0.0.1:8042/mcp/oauth/register/")
    assert payload["registration_client_uri"].endswith(payload["client_id"])
    assert payload["client_id"] and isinstance(payload["client_id"], str)
    assert payload["client_id_issued_at"] <= int(time.time())


def test_oauth_register_respects_uuid_client_id_and_secret_generation():
    settings = AppSettings()
    requested_id = str(uuid.uuid4())
    payload, status = _build_registration_payload(
        {
            "redirect_uris": ["https://app.example.com/cb"],
            "client_id": requested_id,
            "token_endpoint_auth_method": "client_secret_basic",
        },
        settings,
    )
    assert status == 201
    assert payload["client_id"] == requested_id
    assert payload["token_endpoint_auth_method"] == "client_secret_basic"
    assert payload["client_secret"]


def test_oauth_register_put_updates_metadata_and_keeps_registration_token():
    settings = AppSettings()
    created, status = _build_registration_payload(
        {"redirect_uris": ["https://app.example.com/cb"], "client_name": "Old", "scope": "read"},
        settings,
    )
    assert status == 201
    reg_token = created["registration_access_token"]
    client_id = created["client_id"]

    updated_body = {
        "client_name": "New",
        "scope": "read write",
        "jwks_uri": "https://app.example.com/jwks.json",
        "software_id": "soft-1",
        "software_version": "1.0.0",
    }
    updated, status = _build_registration_payload(updated_body, settings, existing=created)
    assert status == 200
    assert updated["client_name"] == "New"
    assert updated["scope"] == "read write"
    assert updated["jwks_uri"] == "https://app.example.com/jwks.json"
    assert updated["registration_access_token"] == reg_token
    assert updated["client_id"] == client_id


def test_oauth_authorize_redirects_with_token_and_state():
    settings = AppSettings()

    resp = _redirect_with_token("http://127.0.0.1/callback", "tok", "abc", settings)
    assert resp.status == 302
    assert "code=tok" in resp.headers["Location"]
    assert "state=abc" in resp.headers["Location"]


@pytest.mark.asyncio
async def test_is_token_valid_checks_validity_without_refresh():
    # If no refresh/external validation logic is configured, it just returns generic validity
    return False, None
