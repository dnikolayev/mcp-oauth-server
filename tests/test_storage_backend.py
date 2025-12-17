
from unittest.mock import AsyncMock, MagicMock

import pytest

from mcp_oauth_server.storage import MemoryStorageBackend, RedisStorageBackend


@pytest.mark.asyncio
async def test_memory_storage_backend():
    storage = MemoryStorageBackend()

    # Set
    await storage.set("key1", "value1")

    # Get
    val = await storage.get("key1")
    assert val == "value1"

    # Get non-existent
    assert await storage.get("missing") is None

    # Delete
    await storage.delete("key1")
    assert await storage.get("key1") is None

    # Delete non-existent (should not raise)
    await storage.delete("missing")

    # Pop
    await storage.set("key2", "value2")
    popped = await storage.pop("key2")
    assert popped == "value2"
    assert await storage.get("key2") is None

    # Pop missing
    assert await storage.pop("missing") is None


@pytest.mark.asyncio
async def test_redis_storage_backend(monkeypatch):
    # Mock Redis client
    mock_redis_client = MagicMock()
    mock_redis_client.get = AsyncMock(return_value=b'"mock_val"')  # json encoded
    mock_redis_client.set = AsyncMock()
    mock_redis_client.delete = AsyncMock(return_value=1)

    # Mock pipeline for pop
    mock_pipeline = MagicMock()
    mock_pipeline.__aenter__ = AsyncMock(return_value=mock_pipeline)
    mock_pipeline.__aexit__ = AsyncMock(return_value=None)
    mock_pipeline.execute = AsyncMock(return_value=[b'"mock_val"', 1])

    # Configure pipeline methods to return the pipeline itself (simulating chaining)
    mock_pipeline.get.return_value = mock_pipeline
    mock_pipeline.delete.return_value = mock_pipeline

    mock_redis_client.pipeline.return_value = mock_pipeline

    mock_from_url = MagicMock(return_value=mock_redis_client)
    monkeypatch.setattr("redis.asyncio.from_url", mock_from_url)

    storage = RedisStorageBackend("redis://localhost")

    # Get
    val = await storage.get("foo")
    assert val == "mock_val"
    mock_redis_client.get.assert_called_with("foo")

    # Set
    await storage.set("foo", "bar", ttl=60)
    mock_redis_client.set.assert_called_with("foo", '"bar"', ex=60)

    # Delete
    await storage.delete("foo")
    mock_redis_client.delete.assert_called_with("foo")

    # Pop
    val = await storage.pop("foo")
    assert val == "mock_val"
    mock_pipeline.get.assert_called_with("foo")
    mock_pipeline.delete.assert_called_with("foo")
