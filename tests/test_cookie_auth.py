from mcp_oauth_server.cookie_auth import default_token_extractor


def test_extract_jwt_from_cookie():
    raw = (
        "%7B%22auth%22:%7B%22token%22:%22JWT%20abc123%22,"
        "%22expiration%22:%222025-12-20T13:30:31.538900%22%7D,%22guid%22:%22123%22%7D"
    )
    token = default_token_extractor(raw)
    assert token == "JWT abc123"


def test_extract_jwt_from_cookie_raw_jwt_string():
    raw = "abc.def.ghi"
    token = default_token_extractor(raw)
    assert token == "JWT abc.def.ghi"
