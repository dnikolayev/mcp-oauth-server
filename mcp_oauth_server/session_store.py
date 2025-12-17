from __future__ import annotations

import logging
from typing import Any

from mcp_oauth_server.storage import StorageBackend

logger = logging.getLogger(__name__)


class SessionStore:
    """Session/token storage using a pluggable backend."""

    def __init__(self, backend: StorageBackend) -> None:
        self.backend = backend

    async def set_token(self, client_id: str, token: dict[str, Any]) -> None:
        await self.backend.set(self._token_key(client_id), token)

    async def get_token(self, client_id: str) -> dict[str, Any] | None:
        return await self.backend.get(self._token_key(client_id))

    async def delete_token(self, client_id: str) -> None:
        await self.backend.delete(self._token_key(client_id))

    async def set_auth_state(self, state: str, data: dict[str, Any]) -> None:
        await self.backend.set(self._state_key(state), data, ttl=600)

    async def pop_auth_state(self, state: str) -> dict[str, Any] | None:
        return await self.backend.pop(self._state_key(state))

    def _token_key(self, client_id: str) -> str:
        return f"mcp_oauth_server:token:{client_id}"

    def _state_key(self, state: str) -> str:
        return f"mcp_oauth_server:state:{state}"


class RegistrationStore:
    """OAuth client registration storage using a pluggable backend."""

    def __init__(self, backend: StorageBackend) -> None:
        self.backend = backend

    async def set(self, client_id: str, data: dict[str, Any]) -> None:
        await self.backend.set(self._client_key(client_id), data)

    async def get(self, client_id: str) -> dict[str, Any] | None:
        return await self.backend.get(self._client_key(client_id))

    async def delete(self, client_id: str) -> None:
        await self.backend.delete(self._client_key(client_id))

    def _client_key(self, client_id: str) -> str:
        return f"mcp_oauth_server:oauth_client:{client_id}"


class AppStateStore:
    """App state storage using a pluggable backend."""

    def __init__(self, backend: StorageBackend) -> None:
        self.backend = backend

    async def set(self, state_id: str, data: dict[str, Any]) -> None:
        await self.backend.set(self._state_key(state_id), data)

    async def get(self, state_id: str) -> dict[str, Any] | None:
        return await self.backend.get(self._state_key(state_id))

    async def delete(self, state_id: str) -> None:
        await self.backend.delete(self._state_key(state_id))

    def _state_key(self, state_id: str) -> str:
        return f"mcp_oauth_server:app_state:{state_id}"
