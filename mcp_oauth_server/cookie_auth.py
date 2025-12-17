from __future__ import annotations

import json
import logging
import urllib.parse

logger = logging.getLogger(__name__)


def default_token_extractor(raw_cookie: str) -> str | None:
    """
    Default token extractor.
    Extract JWT token from encoded cookie payload.
    Supports JSON envelope {"auth":{"token":"JWT <token>"}} or raw JWT string.
    """
    try:
        decoded = urllib.parse.unquote(raw_cookie)
        # If it's already a JWT string (three dot-separated parts), return it.
        if decoded.count(".") == 2:
            return decoded if decoded.startswith("JWT ") else f"JWT {decoded}"

        payload = json.loads(decoded)
        token = payload.get("auth", {}).get("token")
        if token:
            return token
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Failed to decode cookie auth token: %s", exc)
    return None
