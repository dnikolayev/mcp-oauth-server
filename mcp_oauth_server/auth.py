from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import aiohttp
import jwt
from pydantic import AnyHttpUrl, SecretStr

logger = logging.getLogger(__name__)


def create_access_token(data: dict[str, Any], secret_key: str, expires_delta: timedelta | None = None) -> str:
    """Create a new JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm="HS256")
    return encoded_jwt


class OAuthTokenManager:
    """Fetches and caches OAuth tokens."""

    def __init__(
        self,
        token_url: AnyHttpUrl,
        client_id: str,
        client_secret: SecretStr,
        *,
        scope: list[str] | None = None,
        audience: str | None = None,
        timeout: float = 20.0,
        session: aiohttp.ClientSession | None = None,
    ) -> None:
        self._token_url = str(token_url)
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope or []
        self._audience = audience
        self._timeout = timeout
        self._session = session or aiohttp.ClientSession()
        self._owns_session = session is None
        self._token: str | None = None
        self._token_type: str = "Bearer"
        self._expires_at: datetime | None = None
        self._lock = asyncio.Lock()

    async def close(self) -> None:
        if self._session and self._owns_session:
            await self._session.close()

    async def get_token(self) -> str:
        async with self._lock:
            if self._token and not self._is_expired():
                return self._token
            await self._refresh_token()
            assert self._token  # nosec - handled by refresh
            return self._token

    def _is_expired(self) -> bool:
        if not self._expires_at:
            return True
        return datetime.now(timezone.utc) >= self._expires_at - timedelta(seconds=60)

    async def _refresh_token(self) -> None:
        data: dict[str, Any] = {"grant_type": "client_credentials"}
        if self._scope:
            data["scope"] = " ".join(self._scope)
        if self._audience:
            data["audience"] = self._audience

        logger.debug("Requesting OAuth token from %s", self._token_url)
        async with self._session.post(
            self._token_url,
            data=data,
            auth=aiohttp.BasicAuth(self._client_id, self._client_secret.get_secret_value()),
            timeout=self._timeout,
        ) as response:
            if response.status >= 400:
                text = await response.text()
                raise RuntimeError(f"OAuth token request failed: {response.status} {text}")
            payload = await response.json()
        token = payload.get("access_token")
        if not token:
            raise RuntimeError("OAuth server did not return access_token")

        expires_in = payload.get("expires_in", 3600)
        try:
            expires_in = float(expires_in)
        except (TypeError, ValueError):
            expires_in = 3600

        self._token = token
        self._token_type = payload.get("token_type", "Bearer")
        self._expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        logger.debug("Received OAuth token; expires in %.1fs", expires_in)

    async def authorization_header(self) -> dict[str, str]:
        token = await self.get_token()
        return {"Authorization": f"{self._token_type} {token}"}
