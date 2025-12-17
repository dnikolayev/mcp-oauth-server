from mcp_oauth_server.oauth_flow import build_authorize_url, code_challenge_s256, generate_code_verifier, generate_state


def test_code_challenge_round_trip():
    verifier = generate_code_verifier()
    challenge = code_challenge_s256(verifier)
    assert challenge
    assert challenge != verifier


def test_generate_state_unique():
    s1 = generate_state()
    s2 = generate_state()
    assert s1 != s2
    assert len(s1) > 10


def test_build_authorize_url_with_scope_and_audience():
    url = build_authorize_url(
        "https://auth.example.com/authorize",
        client_id="cid",
        redirect_uri="https://app/cb",
        scope=["read", "write"],
        code_challenge="abc",
        state="state123",
        audience="aud",
    )
    assert "response_type=code" in url
    assert "client_id=cid" in url
    assert "redirect_uri=https%3A%2F%2Fapp%2Fcb" in url
    assert "scope=read+write" in url
    assert "audience=aud" in url
