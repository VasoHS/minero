import pytest
import requests

from miner.github_api import get_github_token, get_organization_repos


class FakeResponse:
    """Doble simple de requests.Response para tests sin red."""

    def __init__(self, payload, headers=None, error=None):
        self._payload = payload
        self.headers = headers or {}
        self._error = error
        self.raise_for_status_called = False

    def json(self):
        return self._payload

    def raise_for_status(self):
        self.raise_for_status_called = True
        if self._error is not None:
            raise self._error


def test_get_github_token_missing(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with pytest.raises(ValueError):
        get_github_token()


def test_get_github_token_present(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    assert get_github_token() == "test-token"


def test_get_organization_repos_headers_and_timeout(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    response = FakeResponse([{"name": "repo-a"}])
    captured = {}

    def fake_get(url, headers=None, params=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["params"] = params
        captured["timeout"] = timeout
        return response

    monkeypatch.setattr("miner.github_api.requests.get", fake_get)
    repos = get_organization_repos("test-org")

    assert repos == [{"name": "repo-a"}]
    assert captured["url"] == "https://api.github.com/orgs/test-org/repos"
    assert captured["headers"]["Authorization"] == "Bearer test-token"
    assert captured["headers"]["Accept"] == "application/vnd.github+json"
    assert captured["headers"]["X-GitHub-Api-Version"] == "2022-11-28"
    assert captured["timeout"] == 30
    assert captured["params"] == {"per_page": 100, "type": "all"}
    assert response.raise_for_status_called is True


def test_get_organization_repos_follows_link_pagination(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    next_link = (
        '<https://api.github.com/orgs/test-org/repos?page=2>; rel="next", '
        '<https://api.github.com/orgs/test-org/repos?page=2>; rel="last"'
    )
    page1 = FakeResponse([{"name": "repo-a"}], headers={"Link": next_link})
    page2 = FakeResponse([{"name": "repo-b"}])
    calls = []

    def fake_get(url, headers=None, params=None, timeout=None):
        calls.append({"url": url, "params": params})
        return page1 if len(calls) == 1 else page2

    monkeypatch.setattr("miner.github_api.requests.get", fake_get)
    repos = get_organization_repos("test-org")

    assert [r["name"] for r in repos] == ["repo-a", "repo-b"]
    assert len(calls) == 2
    assert calls[0]["params"] == {"per_page": 100, "type": "all"}
    assert calls[1]["params"] is None
    assert calls[1]["url"] == "https://api.github.com/orgs/test-org/repos?page=2"


def test_get_organization_repos_empty(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(
        "miner.github_api.requests.get", lambda *args, **kwargs: FakeResponse([])
    )

    assert get_organization_repos("test-org") == []


def test_get_organization_repos_ignores_foreign_next_link(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    next_link = '<https://evil.example.com/steal>; rel="next"'
    page1 = FakeResponse([{"name": "repo-a"}], headers={"Link": next_link})
    calls = []

    def fake_get(url, headers=None, params=None, timeout=None):
        calls.append(url)
        return page1

    monkeypatch.setattr("miner.github_api.requests.get", fake_get)
    repos = get_organization_repos("test-org")

    # No se sigue un Link a otro host (no se filtra el token).
    assert [r["name"] for r in repos] == ["repo-a"]
    assert len(calls) == 1


def test_get_organization_repos_quotes_org_name(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    captured = {}

    def fake_get(url, headers=None, params=None, timeout=None):
        captured["url"] = url
        return FakeResponse([])

    monkeypatch.setattr("miner.github_api.requests.get", fake_get)
    get_organization_repos("org/../evil")

    assert captured["url"] == "https://api.github.com/orgs/org%2F..%2Fevil/repos"


def test_get_organization_repos_raises_on_http_error(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    error = requests.HTTPError("500 Server Error")
    response = FakeResponse([], error=error)
    monkeypatch.setattr(
        "miner.github_api.requests.get", lambda *args, **kwargs: response
    )

    with pytest.raises(requests.HTTPError):
        get_organization_repos("test-org")
