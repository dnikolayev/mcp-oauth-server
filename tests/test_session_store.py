import pytest

from mcp_oauth_server.session_store import AppStateStore, RegistrationStore, SessionStore
from mcp_oauth_server.storage import MemoryStorageBackend, RedisStorageBackend


@pytest.fixture
def memory_backend():
    return MemoryStorageBackend()


@pytest.fixture
def session_store(memory_backend):
    return SessionStore(memory_backend)


@pytest.fixture
def reg_store(memory_backend):
    return RegistrationStore(memory_backend)


@pytest.fixture
def app_state_store(memory_backend):
    return AppStateStore(memory_backend)


@pytest.mark.asyncio
async def test_session_store_redis(monkeypatch):
    # Mock aioredis
    full_store = {}

    class MockRedis:
        def __init__(self, url, **kwargs):
            pass

        async def get(self, key):
            return full_store.get(key)

        async def set(self, key, val, ex=None):
            full_store[key] = val

        async def delete(self, key):
            full_store.pop(key, None)

        def pipeline(self):
            return self

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

        async def execute(self):
            # For this test we only use pop which does get+delete in pipeline
            # Simulating pop behavior manually is tricky with just 'execute returning list'
            # But our RedisStorageBackend.pop implementation expects [value]
            # Since we can't easily mock the pipeline state here without more code,
            # let's just assume set/get works for this basic test of the wrapper.
            return [None]  # Dummy for pipeline
    monkeypatch.setattr("redis.asyncio.from_url", MockRedis)

    # We test the backend logic via SessionStore
    backend = RedisStorageBackend("redis://localhost")
    store = SessionStore(backend)

    await store.set_token("client1", {"foo": "bar"})
    assert "mcp_oauth_server:token:client1" in full_store
    assert await store.get_token("client1") == {"foo": "bar"}

    await store.delete_token("client1")
    assert await store.get_token("client1") is None
    assert "mcp_oauth_server:token:client1" not in full_store


@pytest.mark.asyncio
async def test_session_store_in_memory(session_store):
    store = session_store
    await store.set_token("c1", {"a": 1})
    assert await store.get_token("c1") == {"a": 1}
    await store.delete_token("c1")
    assert await store.get_token("c1") is None

    await store.set_auth_state("s1", {"x": 1})
    assert await store.pop_auth_state("s1") == {"x": 1}
    assert await store.pop_auth_state("s1") is None
