import logging
import sys

from sanic import Sanic

from mcp_oauth_server.config import AppSettings
from mcp_oauth_server.http_server import create_app
from mcp_oauth_server.mcp_server import build_mcp_server

# Configure logging
logging.basicConfig(level="INFO")

def main():
    # 1. Initialize settings (can load from .env)
    settings = AppSettings()
    
    # 2. Build the generic MCP server
    server = build_mcp_server(settings)
    
    # 3. Add custom tools
    @server.tool(description="Multiply two numbers")
    async def multiply(a: int, b: int) -> int:
        return a * b

    @server.tool(description="Reverse a string")
    async def reverse_string(text: str) -> str:
        return text[::-1]

    # 4. Create the Sanic app wrapper
    app = create_app(settings, server)

    # 5. Run the server
    # Note: Use single_process=True for simple scripts to avoid separate worker processes
    print(f"Starting MCP Server on http://{settings.mcp_host}:{settings.mcp_port}{settings.mcp_path}")
    app.run(host=settings.mcp_host, port=settings.mcp_port, single_process=True)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
