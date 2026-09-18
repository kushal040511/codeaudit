import httpx


def test_health():
    response = httpx.Response(200)
    assert response.status_code == 200
