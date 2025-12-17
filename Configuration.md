# MCP OAuth Server Configuration

## Build & Run
- **Local**:
  ```bash
python3.14 -m venv venv && source venv/bin/activate
  pip install -r requirements.txt
  cp .env.example .env  # Adjust variables
  python manage.py serve
  ```
- **Docker**:
  ```bash
  docker build -t mcp-oauth-server .
  docker run --rm -p 8080:8080 -e MCP_SERVER_LOG_LEVEL=DEBUG mcp-oauth-server
  ```
  Entrypoint is `manage.py serve` via `support/start.sh`.

## Environment Variables
Prefix all variables with `MCP_SERVER_`.

### Core Settings
- `MCP_SERVER_MCP_HOST` (default `127.0.0.1`)
- `MCP_SERVER_MCP_PORT` (default `8042`)
- `MCP_SERVER_MCP_PATH` (default `/mcp`)
- `MCP_SERVER_HEALTH_PATH` (default `/health`)
- `MCP_SERVER_PUBLIC_BASE_URL` (optional, e.g. `https://my-mcp.example.com/mcp`): Used to advertise OAuth endpoints with the public host.
- `MCP_SERVER_LOG_LEVEL` (default `INFO`)

### OAuth 2.0 & Authentication
If these are unset, the server advertises its own built-in mock/local OAuth endpoints.
- `MCP_SERVER_OAUTH_TOKEN_URL`: Upstream OAuth token endpoint.
- `MCP_SERVER_OAUTH_AUTHORIZE_URL`: Upstream OAuth authorize endpoint.
- `MCP_SERVER_OAUTH_CLIENT_ID`: Client ID for upstream OAuth.
- `MCP_SERVER_OAUTH_CLIENT_SECRET`: Client Secret.
- `MCP_SERVER_OAUTH_SCOPE`: Space-separated scopes.
- `MCP_SERVER_OAUTH_AUDIENCE`: Optional audience.
- `MCP_SERVER_OAUTH_REDIRECT_URL`: The redirect URL registered with the upstream provider (should point to your server).

### Auth Flow & Redirects
- `MCP_SERVER_LOGIN_URL`: Where to redirect users who are not authenticated (e.g., your app's login page).
- `MCP_SERVER_POST_LOGIN_REDIRECT_URL`: Where the login page should send the user back to (usually this MCP server).
- `MCP_SERVER_ACCESS_TOKEN_TTL_SECONDS`: TTL for tokens issued by the validation endpoint.

### Security
- `MCP_SERVER_DNS_REBINDING_PROTECTION` (default `True`).
- `MCP_SERVER_ALLOWED_HOSTS`: Comma-separated list of allowed Host headers.
- `MCP_SERVER_ALLOWED_ORIGINS`: Comma-separated list of allowed Origin headers.

### Storage (Redis)
Shared storage for sessions and tokens. If unset, uses in-memory storage (not recommended for production with multiple instances).
- `MCP_SERVER_REDIS_URL`: e.g., `redis://localhost:6379/0`
- Or `MCP_SERVER_REDIS_HOST` and `MCP_SERVER_REDIS_PORT`.

### Storage (PostgreSQL)
Optional persistent storage for sessions and registrations.
- `MCP_SERVER_DATABASE_URL`: e.g. `postgresql+asyncpg://user:pass@host/dbname`

### Cookie Authentication (Optional)
If your upstream API/App uses cookies, you can configure extraction:
- `MCP_SERVER_COOKIE_NAME`: Name of the cookie containing the token.
- `MCP_SERVER_COOKIE_VALUE`: Optional raw value (for debugging).

## Notes
- **Debug Mode**: passing `--debug` to the CLI enables auto-reload and `DEBUG` logging.
- **Tools**: By default, this server exposes `echo`, `add`, and `healthcheck` tools. Extend `mcp_server.py` to add your own.
