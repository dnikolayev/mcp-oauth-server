import logging
import sys

import aiohttp
from sanic import Sanic

from mcp_oauth_server.config import AppSettings
from mcp_oauth_server.http_server import create_app
from mcp_oauth_server.mcp_server import build_mcp_server

# Configure logging
logging.basicConfig(level="INFO")

def main():
    settings = AppSettings()
    server = build_mcp_server(settings)
    
    # Example usage of an external API
    # Note: For production, you might want to use a shared aiohttp.ClientSession
    # stored in app.ctx or server context.
    
    @server.tool(description="Fetch current BTC price from Coindesk")
    async def get_bitcoin_price() -> str:
        url = "https://api.coindesk.com/v1/bpi/currentprice.json"
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                data = await resp.json()
                return f"Current BTC Price: {data['bpi']['USD']['rate']} USD"

    app = create_app(settings, server)

    print(f"Starting Crypto MCP Server on http://{settings.mcp_host}:{settings.mcp_port}{settings.mcp_path}")
    app.run(host=settings.mcp_host, port=settings.mcp_port, single_process=True)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
