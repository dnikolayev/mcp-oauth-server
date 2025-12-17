import asyncio

import pytest
from pydantic import SecretStr

from mcp_oauth_server.auth import OAuthTokenManager


class FakeResponse:
    def __init__(self, status: int, payload: dict):
        self.status = status
        self._payload = payload

    async def json(self):
        return self._payload

    async def text(self):
        return str(self._payload)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeSession:
    def __init__(self):
        self.calls = []
        self.responses = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)

    async def close(self):
        return None


@pytest.mark.asyncio
async def test_oauth_token_manager_refreshes_and_caches():
    session = FakeSession()
    session.responses = [
        FakeResponse(200, {"access_token": "t1", "token_type": "Bearer", "expires_in": 1}),
        FakeResponse(200, {"access_token": "t2", "token_type": "Bearer", "expires_in": 3600}),
    ]
    manager = OAuthTokenManager(
        token_url="https://auth.example.com/token",
        client_id="id",
        client_secret=SecretStr("secret"),
        scope=["read"],
        session=session,  # no real HTTP
    )

    first = await manager.get_token()
    assert first == "t1"
    # Force expiry and ensure a second call triggers refresh
    await asyncio.sleep(1.1)
    second = await manager.get_token()
    assert second == "t2"
    assert len(session.calls) == 2
    await manager.close()


@pytest.mark.asyncio
async def test_oauth_token_manager_errors():
    session = FakeSession()
    session.responses = [FakeResponse(500, {"error": "bad"})]
    manager = OAuthTokenManager(
        token_url="https://auth.example.com/token",
        client_id="id",
        client_secret=SecretStr("secret"),
        session=session,
    )
    with pytest.raises(RuntimeError):
        await manager.get_token()
    await manager.close()


@pytest.mark.asyncio
async def test_oauth_token_manager_missing_access_token():
    session = FakeSession()
    session.responses = [FakeResponse(200, {"expires_in": 10})]
    manager = OAuthTokenManager(
        token_url="https://auth.example.com/token",
        client_id="id",
        client_secret=SecretStr("secret"),
        session=session,
    )
    with pytest.raises(RuntimeError):
        await manager.get_token()
    await manager.close()


@pytest.mark.asyncio
async def test_oauth_token_manager_owned_session_closes():
    manager = OAuthTokenManager(
        token_url="https://auth.example.com/token",
        client_id="id",
        client_secret=SecretStr("secret"),
        session=None,
    )
    await manager.close()


@pytest.mark.asyncio
async def test_oauth_token_manager_handles_non_numeric_expiry_and_audience_and_header():
    session = FakeSession()
    session.responses = [
        FakeResponse(200, {"access_token": "abc", "expires_in": "not-a-number", "token_type": "JWT"}),
    ]
    manager = OAuthTokenManager(
        token_url="https://auth.example.com/token",
        client_id="id",
        client_secret=SecretStr("secret"),
        scope=["s1"],
        audience="aud",
        session=session,
    )
    header = await manager.authorization_header()
    assert header["Authorization"].startswith("JWT abc")
    # Cached token should return without another call
    header2 = await manager.authorization_header()
    assert header2 == header


def test_oauth_token_manager_is_expired_without_expiry():
    manager = OAuthTokenManager(
        token_url="https://auth.example.com/token",
        client_id="id",
        client_secret=SecretStr("secret"),
        session=FakeSession(),
    )
    assert manager._is_expired() is True  # pylint: disable=protected-access
