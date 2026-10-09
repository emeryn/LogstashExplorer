import types
import uuid

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.api import mcp
from app.core.deps import Principal
from app.db.models import Role
from app.db.session import get_db

BEARER = {"Authorization": "Bearer lsx_test_x"}


class FakeDb:
    async def rollback(self):
        pass


def _client(role: Role = Role.USER) -> TestClient:
    user = types.SimpleNamespace(
        id=uuid.uuid4(), username="alice", role=role, display_name="Alice", email=None, auth_source="local",
        status="active", must_change_password=False, totp_enabled=False, last_login_at=None,
    )  # fmt: skip
    principal = Principal(user=user, token=types.SimpleNamespace(prefix="abcd1234"))

    async def fake_db():
        yield FakeDb()

    app = FastAPI()
    app.include_router(mcp.router)
    app.dependency_overrides[get_db] = fake_db
    app.dependency_overrides[mcp.get_token_principal] = lambda: principal
    return TestClient(app)


def _rpc(client: TestClient, method: str, params: dict | None = None, **headers):
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    return client.post("/api/mcp", json=body, headers={**BEARER, **headers})


def test_bearer_token_is_mandatory():
    async def fake_db():
        yield FakeDb()

    app = FastAPI()
    app.include_router(mcp.router)
    app.dependency_overrides[get_db] = fake_db
    res = TestClient(app).post("/api/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert res.status_code == 401
    assert res.headers["www-authenticate"].startswith("Bearer")


def test_initialize_and_notifications():
    client = _client()
    res = _rpc(client, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}})
    result = res.json()["result"]
    assert result["protocolVersion"] == "2025-06-18"
    assert "tools" in result["capabilities"]
    notif = client.post("/api/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=BEARER)
    assert notif.status_code == 202
    assert client.get("/api/mcp", headers=BEARER).status_code == 405


def test_tools_follow_the_user_role():
    names = {t["name"] for t in _rpc(_client(Role.USER), "tools/list").json()["result"]["tools"]}
    assert "run_agent" not in names and "list_projects" in names
    assert not names & {"delete_project", "share_project"}
    denied = _rpc(_client(Role.USER), "tools/call", {"name": "run_agent", "arguments": {}}).json()
    assert denied["error"]["code"] == mcp.INVALID_PARAMS
    names = {t["name"] for t in _rpc(_client(Role.ADVANCED), "tools/list").json()["result"]["tools"]}
    assert "run_agent" in names


def test_tools_delegate_to_route_handlers_with_the_token_principal(monkeypatch):
    seen = {}

    async def fake_projects(principal, db):
        seen["user"] = principal.user.username
        return [{"id": "p1", "name": "demo"}]

    monkeypatch.setattr("app.api.projects.projects", fake_projects)
    res = _rpc(_client(), "tools/call", {"name": "list_projects", "arguments": {}}).json()["result"]
    assert seen["user"] == "alice"
    assert not res["isError"]
    assert res["structuredContent"]["projects"][0]["name"] == "demo"


def test_access_denials_become_tool_errors(monkeypatch):
    async def denied(pid, principal, db):
        raise HTTPException(404, "Project not found")

    monkeypatch.setattr("app.api.projects.project_get", denied)
    res = _rpc(_client(), "tools/call", {"name": "get_project", "arguments": {"project_id": str(uuid.uuid4())}})
    result = res.json()["result"]
    assert result["isError"] and "404" in result["content"][0]["text"]


def test_invalid_arguments_are_not_echoed():
    res = _rpc(_client(), "tools/call", {"name": "get_project", "arguments": {"project_id": "secret-value"}})
    result = res.json()["result"]
    assert result["isError"] and "secret-value" not in result["content"][0]["text"]


@pytest.mark.parametrize(
    ("headers", "status"),
    [({"Origin": "https://evil.example"}, 403), ({"MCP-Protocol-Version": "1999-01-01"}, 400)],
)
def test_transport_guards(headers, status):
    assert _rpc(_client(), "ping", **headers).status_code == status
