from __future__ import annotations

from typing import Annotated

from pydantic import AliasChoices, AnyHttpUrl, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppSettings(BaseSettings):
    """Application configuration loaded from environment variables or .env."""

    model_config = SettingsConfigDict(
        env_prefix="MCP_SERVER_",
        env_file=".env",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # OAuth Settings
    oauth_token_url: AnyHttpUrl | None = Field(
        default=None,
        description="OAuth token endpoint.",
    )
    oauth_registration_url: AnyHttpUrl | None = Field(
        default=None,
        description="OAuth dynamic client registration endpoint (overrides default /oauth/register).",
    )
    oauth_client_id: str | None = Field(default=None, description="OAuth client id.")
    oauth_client_secret: SecretStr | None = Field(default=None, description="OAuth client secret.")
    oauth_scope: str | None = Field(default=None, description="Space separated OAuth scopes.")
    oauth_audience: str | None = Field(default=None, description="Optional OAuth audience.")
    oauth_authorize_url: AnyHttpUrl | None = Field(
        default=None,
        description="OAuth authorize endpoint (for auth code/PKCE).",
    )
    oauth_redirect_url: AnyHttpUrl | None = Field(
        default=None,
        description="Redirect/callback URL for interactive auth.",
    )

    # Auth Flow
    login_url: AnyHttpUrl | None = Field(
        default=None,
        description="Login URL to redirect when auth fails (if not using built-in OAuth).",
        validation_alias=AliasChoices("login_url", "MCP_LOGIN_URL")
    )
    post_login_redirect_url: AnyHttpUrl | None = Field(
        default=None,
        description="Redirect URL to return to after login (encoded into login URL).",
        validation_alias=AliasChoices("post_login_redirect_url", "OAUTH_VALIDATE_REDIRECT")
    )
    access_token_ttl_seconds: Annotated[float, Field(gt=0)] = 3600.0
    auth_secret: SecretStr = Field(
        default="development-secret-key",
        description="Secret key for signing internal JWTs.",
        validation_alias=AliasChoices("auth_secret", "MCP_SERVER_AUTH_SECRET"),
    )

    # MCP Server Settings
    mcp_host: str = Field("127.0.0.1", description="Host for the Sanic HTTP server.")
    mcp_port: int = Field(8042, description="Port for the Sanic HTTP server.")
    mcp_path: str = Field("/mcp", description="HTTP path that exposes the MCP streamable HTTP transport.")
    health_path: str = Field("/health", description="HTTP path for lightweight health checks.")

    allowed_hosts: list[str] | str = Field(
        default_factory=list,
        description="Allowed Host headers for MCP transport (appended to defaults); accepts comma-separated env.",
    )
    allowed_origins: list[str] | str = Field(
        default_factory=list,
        description="Allowed Origin headers for MCP transport (appended to defaults); accepts comma-separated env.",
    )
    dns_rebinding_protection: bool = Field(
        True,
        description="Enable DNS rebinding protection for MCP transport.",
        validation_alias=AliasChoices(
            "dns_rebinding_protection",
            "ENABLE_DNS_REBINDING_PROTECTION",
        ),
    )
    public_base_url: AnyHttpUrl | None = Field(
        default=None,
        description="Public base URL (scheme/host and optional MCP path) used when advertising OAuth endpoints.",
        validation_alias=AliasChoices("public_base_url", "MCP_PUBLIC_URL"),
    )

    log_level: str = Field("INFO", description="Root log level.")
    json_response: bool = Field(True, description="Return MCP responses as JSON instead of SSE.")
    stateless_http: bool = Field(True, description="Use stateless streamable HTTP transport.")

    # Storage
    redis_url: str | None = Field(
        default=None,
        description="Redis URL for shared session/token storage.",
        validation_alias=AliasChoices("redis_url", "REDIS_URL"),
    )
    redis_host: str | None = Field(
        default=None,
        description="Redis host (alternative to REDIS_URL).",
        validation_alias=AliasChoices("redis_host", "REDIS_HOST"),
    )
    redis_port: int | None = Field(
        default=None,
        description="Redis port (alternative to REDIS_URL).",
        validation_alias=AliasChoices("redis_port", "REDIS_PORT"),
    )

    database_url: str | None = Field(
        default=None,
        description="PostgreSQL database URL (e.g. postgresql+asyncpg://user:pass@host/db).",
        validation_alias=AliasChoices("database_url", "DATABASE_URL"),
    )

    # Cookie Auth (Optional)
    cookie_name: str | None = Field(default=None, description="Cookie name carrying JWT session (if used).")
    cookie_value: str | None = Field(default=None, description="Raw cookie value to extract JWT from (optional).")

    @model_validator(mode="before")
    @classmethod
    def _empty_strings_to_none(cls, values: dict[str, object]) -> dict[str, object]:
        for key in (
            "oauth_token_url",
            "oauth_authorize_url",
            "oauth_redirect_url",
            "oauth_registration_url",
            "post_login_redirect_url",
            "login_url",
            "redis_url",
            "redis_host",
            "redis_port",
            "database_url",
        ):
            if values.get(key) == "":
                values[key] = None

        # Allow comma-separated allowed hosts/origins
        for list_key in ("allowed_hosts", "allowed_origins"):
            val = values.get(list_key)
            if isinstance(val, str):
                values[list_key] = [item.strip() for item in val.split(",") if item.strip()]
        return values

    @property
    def oauth_configured(self) -> bool:
        return bool(self.oauth_token_url and self.oauth_client_id and self.oauth_client_secret)

    @property
    def scope_list(self) -> list[str]:
        if not self.oauth_scope:
            return []
        return [scope for scope in self.oauth_scope.replace(",", " ").split() if scope]

    @property
    def redis_dsn(self) -> str | None:
        if self.redis_url:
            url = str(self.redis_url)
            if "://" not in url:
                url = f"redis://{url}"
            return url
        if self.redis_host:
            port = self.redis_port or 6379
            return f"redis://{self.redis_host}:{port}/0"
        return None
