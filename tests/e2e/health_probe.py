import asyncio
import os
import sys

import aiohttp

SERVER_URL = os.getenv("SERVER_URL", "http://127.0.0.1:8042")


async def check_health():
    url = f"{SERVER_URL}/health"
    print(f"Probing {url}...")
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url) as resp:
                print(f"Status: {resp.status}")
                text = await resp.text()
                print(f"Response: {text}")
                if resp.status == 200:
                    print("✅ Health probe passed")
                    return True
                else:
                    print("❌ Health probe failed")
                    return False
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False

if __name__ == "__main__":
    try:
        success = asyncio.run(check_health())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        sys.exit(1)
