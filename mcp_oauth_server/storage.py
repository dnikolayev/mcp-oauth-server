from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

import redis.asyncio as aioredis
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert

from mcp_oauth_server.db import Database, StoreItem


class StorageBackend(ABC):
    """Abstract base class for storage backends."""

    @abstractmethod
    async def get(self, key: str) -> Any | None:
        pass

    @abstractmethod
    async def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        pass

    @abstractmethod
    async def delete(self, key: str) -> None:
        pass

    @abstractmethod
    async def pop(self, key: str) -> Any | None:
        pass


class MemoryStorageBackend(StorageBackend):
    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    async def get(self, key: str) -> Any | None:
        data = self._store.get(key)
        return json.loads(data) if data else None

    async def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        # Memory backend ignores TTL for simplicity in this implementation
        self._store[key] = json.dumps(value)

    async def delete(self, key: str) -> None:
        self._store.pop(key, None)

    async def pop(self, key: str) -> Any | None:
        data = self._store.pop(key, None)
        return json.loads(data) if data else None


class RedisStorageBackend(StorageBackend):
    def __init__(self, redis_url: str) -> None:
        self._redis = aioredis.from_url(redis_url, encoding="utf-8", decode_responses=True)

    async def get(self, key: str) -> Any | None:
        data = await self._redis.get(key)
        return json.loads(data) if data else None

    async def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        payload = json.dumps(value)
        if ttl:
            await self._redis.set(key, payload, ex=ttl)
        else:
            await self._redis.set(key, payload)

    async def delete(self, key: str) -> None:
        await self._redis.delete(key)

    async def pop(self, key: str) -> Any | None:
        async with self._redis.pipeline() as pipe:
            pipe.get(key)
            pipe.delete(key)
            result = await pipe.execute()
        data = result[0]
        return json.loads(data) if data else None


class PostgresStorageBackend(StorageBackend):
    def __init__(self, db: Database) -> None:
        self.db = db

    async def get(self, key: str) -> Any | None:
        async with self.db.session_maker() as session:
            stmt = select(StoreItem).where(StoreItem.key == key)
            result = await session.execute(stmt)
            item = result.scalar_one_or_none()
            return json.loads(item.value) if item else None

    async def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        # Postgres backend ignores TTL in this simple KV implementation
        # A proper implementation would add an expires_at column and background cleanup
        payload = json.dumps(value)
        async with self.db.session_maker() as session:
            # Upsert
            stmt = insert(StoreItem).values(key=key, value=payload)
            stmt = stmt.on_conflict_do_update(
                index_elements=[StoreItem.key],
                set_={"value": stmt.excluded.value},
            )
            await session.execute(stmt)
            await session.commit()

    async def delete(self, key: str) -> None:
        async with self.db.session_maker() as session:
            stmt = delete(StoreItem).where(StoreItem.key == key)
            await session.execute(stmt)
            await session.commit()

    async def pop(self, key: str) -> Any | None:
        # Not atomic, but sufficient for this use case
        val = await self.get(key)
        if val is not None:
            await self.delete(key)
        return val
