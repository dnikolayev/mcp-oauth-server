
import pytest

from mcp_oauth_server.config import AppSettings


@pytest.mark.parametrize(
    "env_vars, expected_values",
    [
        # 1. OAuth Settings
        (
            {
                "MCP_SERVER_OAUTH_TOKEN_URL": "https://auth.example.com/token",
                "MCP_SERVER_OAUTH_CLIENT_ID": "client-123",
                "MCP_SERVER_OAUTH_CLIENT_SECRET": "secret-123",
            },
            {
                "oauth_token_url": "https://auth.example.com/token",
                "oauth_client_id": "client-123",
                "oauth_client_secret": "secret-123",
            }
        ),
        # 2. Auth Flow & Aliases
        (
            {
                "MCP_LOGIN_URL": "https://app.example.com/login",
                "OAUTH_VALIDATE_REDIRECT": "https://mcp.example.com/cb",
            },
            {
                "login_url": "https://app.example.com/login",
                "post_login_redirect_url": "https://mcp.example.com/cb",
            }
        ),
        # 3. Numeric & Boolean
        (
            {
                "MCP_SERVER_ACCESS_TOKEN_TTL_SECONDS": "7200",
                "ENABLE_DNS_REBINDING_PROTECTION": "0",
                "MCP_SERVER_JSON_RESPONSE": "0",
            },
            {
                "access_token_ttl_seconds": 7200.0,
                "dns_rebinding_protection": False,
                "json_response": False,
            }
        ),
        # 4. Storage Aliases
        (
            {
                "REDIS_URL": "redis://localhost:6379/1",
                "DATABASE_URL": "postgresql://user:pass@localhost:5432/db",
            },
            {
                "redis_url": "redis://localhost:6379/1",
                "database_url": "postgresql://user:pass@localhost:5432/db",
            }
        ),
        # 5. Lists via comma-separated string
        (
            {
                "MCP_SERVER_ALLOWED_HOSTS": "foo.com, bar.com",
                "MCP_SERVER_ALLOWED_ORIGINS": "https://foo.com, https://bar.com",
            },
            {
                "allowed_hosts": ["foo.com", "bar.com"],
                "allowed_origins": ["https://foo.com", "https://bar.com"],
            }
        ),
        # 6. Auth Secret Alias
        (
            {
                "MCP_SERVER_AUTH_SECRET": "supercheck",
            },
            {
                "auth_secret": "supercheck",
            }
        ),
        # 7. Redis separated fields
        (
            {
                "REDIS_HOST": "cache.internal",
                "REDIS_PORT": "6380",
            },
            {
                "redis_host": "cache.internal",
                "redis_port": 6380,
            }
        ),
        # 8. Empty strings (should be None)
        (
            {
                "MCP_SERVER_OAUTH_TOKEN_URL": "",
                "MCP_SERVER_LOGIN_URL": "",
                "DATABASE_URL": "",
            },
            {
                "oauth_token_url": None,
                "login_url": None,
                "database_url": None,
            }
        ),
        # 9. Public Base URL alias
        (
            {
                "MCP_PUBLIC_URL": "https://public.example.com/mcp",
            },
            {
                "public_base_url": "https://public.example.com/mcp",
            }
        ),
    ]
)
def test_config_env_vars(monkeypatch, env_vars, expected_values):
    # Clear existing env vars that might interfere
    for key in env_vars:
        monkeypatch.delenv(key, raising=False)

    # Set new env vars
    for key, val in env_vars.items():
        monkeypatch.setenv(key, val)

    settings = AppSettings()

    for field, expected in expected_values.items():
        val = getattr(settings, field)
        # Handle SecretStr comparison
        if hasattr(val, "get_secret_value"):
            assert val.get_secret_value() == expected
        # Handle URL string comparison
        elif hasattr(val, "scheme"):  # rudimentary check for AnyHttpUrl
            assert str(val) == expected.rstrip("/") if expected else expected
        else:
            assert val == expected
