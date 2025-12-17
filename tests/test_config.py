from mcp_oauth_server.config import AppSettings


def test_empty_oauth_urls_become_none():
    settings = AppSettings(
        oauth_token_url="",
        oauth_authorize_url="",
        oauth_redirect_url="",
        post_login_redirect_url="",
        login_url="",
    )
    assert settings.oauth_token_url is None
    assert settings.oauth_authorize_url is None
    assert settings.oauth_redirect_url is None
    assert settings.post_login_redirect_url is None
    assert settings.login_url is None


def test_redis_host_port_builds_url():
    settings = AppSettings(redis_host="redis.example.com", redis_port=6380)
    assert settings.redis_dsn == "redis://redis.example.com:6380/0"
