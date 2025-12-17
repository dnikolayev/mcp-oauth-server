
import asyncio
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from mcp_oauth_server import AppSettings, create_app
from mcp_oauth_server.mcp_server import build_mcp_server

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def custom_base64_extractor(raw_cookie: str) -> str | None:
    """
    Example custom extractor that expects the cookie to be a simple base64 encoded string.
    """
    import base64
    try:
        # Trivial example: decode base64 to get the token
        decoded = base64.b64decode(raw_cookie).decode("utf-8")
        logger.info(f"Custom extractor decoded token: {decoded}")
        return decoded
    except Exception as e:
        logger.error(f"Failed to extract token: {e}")
        return None


async def main():
    # 1. Define settings
    # We set a cookie name that our custom logic will look for
    settings = AppSettings(
        auth_secret="my-super-secret-key",
        cookie_name="my_custom_cookie",
        cookie_value=None # We will simulate an incoming cookie
    )

    # 2. Build MCP Server
    mcp = build_mcp_server(settings)

    @mcp.tool()
    def echo_token(ctx: Any) -> str:
        """Echoes the token used for auth."""
        # In a real scenario, you might access user info from context if propagated
        return "Token accessed via custom auth!"

    # 3. Create Sanic App with Custom Extractor
    # Pass our custom function to create_app
    app = create_app(
        settings, 
        mcp, 
        cookie_token_extractor=custom_base64_extractor
    )

    # 4. Run the server
    # For demonstration, we just print the setup. 
    # To run: python examples/04_custom_cookie_auth.py
    # Then send a request with Cookie: my_custom_cookie=<base64_of_token>
    
    logger.info("Starting server with custom cookie extractor...")
    
    # In a real run, you would use:
    # app.run(host="0.0.0.0", port=8000)
    
    # Let's simulate a check to prove it's wired up
    assert app.ctx.cookie_token_extractor is custom_base64_extractor
    logger.info("Verification passed: Custom extractor is registered on app.ctx")

if __name__ == "__main__":
    asyncio.run(main())
