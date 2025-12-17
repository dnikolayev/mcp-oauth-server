from __future__ import annotations

import base64
import hashlib
import os
import secrets
import urllib.parse
from typing import Any


def generate_code_verifier() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")


def code_challenge_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def build_authorize_url(
    authorize_url: str,
    client_id: str,
    redirect_uri: str,
    scope: list[str] | None,
    code_challenge: str,
    state: str,
    audience: str | None = None,
) -> str:
    params: dict[str, Any] = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    if scope:
        params["scope"] = " ".join(scope)
    if audience:
        params["audience"] = audience
    return f"{authorize_url}?{urllib.parse.urlencode(params)}"


def generate_state() -> str:
    return secrets.token_urlsafe(24)
