import os
import pytest
import server
from server import APIManager, IPManager, app

# SSH credentials injected by the CI workflow (or set locally to run e2e tests).
_SSH_HOST = os.environ.get("TEST_SSH_HOST")
_SSH_USER = os.environ.get("TEST_SSH_USER")
_SSH_KEY  = os.environ.get("TEST_SSH_KEY")
SKIP_SSH  = not all([_SSH_HOST, _SSH_USER, _SSH_KEY])

TEST_CONFIG = {
    "api_tokens": [
        {
            "token": "valid-token",
            "permissions": {
                "allowed_servers":      ["test_server"],
                "allowed_command_names": ["echo_hello", "uptime"],
            },
        }
    ],
    "commands": {
        "echo_hello": {"command": "echo hello", "description": "Echo test"},
        "uptime":     {"command": "uptime",      "description": "System uptime"},
    },
    "ssh_servers": {
        "test_server": {
            "hostname":    _SSH_HOST or "localhost",
            "username":    _SSH_USER or "runner",
            "private_key": _SSH_KEY  or "/tmp/test_ssh_key",
        }
    },
}


@pytest.fixture(autouse=True)
def reset_managers():
    server.api_manager = APIManager(TEST_CONFIG)
    server.ip_manager  = IPManager()
    yield
    server.ip_manager  = IPManager()


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# Auth & permission unit tests (no SSH connection needed)
# ---------------------------------------------------------------------------

def test_missing_api_key_returns_401(client):
    resp = client.post(
        "/run-command",
        json={"server_name": "test_server", "command_name": "uptime"},
        headers={"X-Api-Key": ""},
    )
    assert resp.status_code == 401
    assert "Unauthorized" in resp.get_json()["error"]


def test_invalid_api_key_returns_401(client):
    resp = client.post(
        "/run-command",
        json={"server_name": "test_server", "command_name": "uptime"},
        headers={"X-Api-Key": "bad-key"},
    )
    assert resp.status_code == 401


def test_command_not_in_token_whitelist_returns_403(client):
    resp = client.post(
        "/run-command",
        json={"server_name": "test_server", "command_name": "reboot"},
        headers={"X-Api-Key": "valid-token"},
    )
    assert resp.status_code == 403
    assert "Forbidden" in resp.get_json()["error"]


def test_server_not_in_token_whitelist_returns_403(client):
    resp = client.post(
        "/run-command",
        json={"server_name": "prod_server", "command_name": "uptime"},
        headers={"X-Api-Key": "valid-token"},
    )
    assert resp.status_code == 403


def test_ip_blocked_after_three_failed_attempts(client):
    for _ in range(3):
        client.post(
            "/run-command",
            json={"server_name": "test_server", "command_name": "uptime"},
            headers={"X-Api-Key": "bad-key"},
        )
    resp = client.post(
        "/run-command",
        json={"server_name": "test_server", "command_name": "uptime"},
        headers={"X-Api-Key": "valid-token"},
    )
    assert resp.status_code == 403
    assert "blocked" in resp.get_json()["error"]


# ---------------------------------------------------------------------------
# End-to-end SSH tests (skipped unless CI sets TEST_SSH_* env vars)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(SKIP_SSH, reason="TEST_SSH_HOST/USER/KEY not set")
def test_e2e_echo_command(client):
    resp = client.post(
        "/run-command",
        json={"server_name": "test_server", "command_name": "echo_hello"},
        headers={"X-Api-Key": "valid-token"},
    )
    assert resp.status_code == 200
    assert "hello" in resp.get_json()["output"]


@pytest.mark.skipif(SKIP_SSH, reason="TEST_SSH_HOST/USER/KEY not set")
def test_e2e_uptime_command(client):
    resp = client.post(
        "/run-command",
        json={"server_name": "test_server", "command_name": "uptime"},
        headers={"X-Api-Key": "valid-token"},
    )
    data = resp.get_json()
    assert resp.status_code == 200
    assert data["output"]   # uptime always produces output
    assert data["error"] == ""
