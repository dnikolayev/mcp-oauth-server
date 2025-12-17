import logging
import os

from sanic import Sanic

from mcp_oauth_server.config import AppSettings
from mcp_oauth_server.http_server import create_app
from mcp_oauth_server.mcp_server import build_mcp_server

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    """
    Example of starting the MCP OAuth Server with PostgreSQL storage.
    
    Requires a running PostgreSQL instance.
    Set the MCP_SERVER_DATABASE_URL environment variable or modify the default below.
    
    Example:
    export MCP_SERVER_DATABASE_URL="postgresql+asyncpg://user:pass@localhost:5432/mcp_db"
    python examples/03_postgres_storage.py
    """
    
    # Check for database URL
    database_url = os.environ.get(
        "MCP_SERVER_DATABASE_URL", 
        "postgresql+asyncpg://postgres:postgres@localhost:5432/mcp_db"
    )
    
    logger.info(f"Starting server with database: {database_url}")
    
    # 1. Configure Settings with Database URL
    settings = AppSettings(
        database_url=database_url,
        mcp_path="/mcp",
        auth_secret="demo-secret" # In production, use a secure secret
    )

    # 2. Build the MCP Server (Tool Logic)
    mcp_server = build_mcp_server(settings)

    # 3. Create the HTTP App (Sanic) - This initializes the DB connection and tables
    app = create_app(settings, mcp_server, app_name="mcp-postgres-example")

    # 4. Run the Server
    # Note: In a real deployment, you might use Gunicorn or similar.
    # For this example, we use the Sanic dev server.
    try:
        app.run(
            host=settings.mcp_host,
            port=settings.mcp_port,
            debug=True,
            auto_reload=False # Disable auto-reload for script execution
        )
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        logger.error("Ensure PostgreSQL is running and the connection string is correct.")
        logger.error("You can set MCP_SERVER_DATABASE_URL to override the default.")

if __name__ == "__main__":
    main()
