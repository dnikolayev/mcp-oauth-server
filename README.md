# MCP OAuth Server

![Build Status](https://github.com/yourusername/mcp-oauth-server/actions/workflows/ci.yml/badge.svg)


A generic implementation of a Model Context Protocol (MCP) server with built-in OAuth 2.0 support. It provides a solid foundation for building MCP servers that require robust authentication, whether acting as an OAuth 2.0 client to an upstream API or serving as a standalone authenticated agent.

> **Compatible with:** ChatGPT, Gemini, Claude, and other MCP-compliant clients.


## Features

- **OAuth 2.0 Support**: Built-in support for Authorization Code flow with PKCE, Client Credentials, and token management.
- **Generic Tools**: Comes with example tools (`echo`, `add`) and a structure to easily add your own.
- **FastMCP & Sanic**: Built on top of `mcp` (FastMCP) and `sanic` for high-performance async HTTP serving.
- **Storage**: Pluggable storage backends (Redis, PostgreSQL, Memory) for sessions and token storage.
- **Configuration**: Fully configurable via environment variables (`MCP_SERVER_*`).

## Quick Start (local)

```bash
python3.14 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # Adjust variables
python manage.py serve --debug
```

Default MCP endpoint: `http://127.0.0.1:8042/mcp`

## Docker

```bash
docker build -t mcp-oauth-server .
docker run --rm -p 8080:8080 mcp-oauth-server
```

## Tools

Includes basic tools for demonstration:
- `healthcheck()`: Checks server health.
- `echo(message)`: Echoes back the message.
- `add(a, b)`: Adds two numbers.

Extend `mcp_oauth_server/mcp_server.py` to add your own business logic tools.

## Configuration

See [Configuration.md](Configuration.md) for a detailed list of environment variables.

## Project Structure

- `mcp_oauth_server/`: Source code.
  - `mcp_server.py`: MCP tool definitions and server logic.
  - `http_server.py`: Sanic web server wrapper (handles OAuth, health, serving MCP).
  - `config.py`: Application configuration (Pydantic settings).
  - `auth.py` / `session_store.py`: Authentication and session management.
- `tests/`: Unit tests.

## Development

Run tests:
```bash
./test.sh
```

## License

[MIT](LICENSE)
