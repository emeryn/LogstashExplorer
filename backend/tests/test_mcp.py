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
    """Just enough of AsyncSession: settings are read (defaults apply) and audit rows are collected."""

    def __init__(self, settings: dict | None = None):
        self.settings = settings or {}
        self.added: list = []

    async def get(self, model, key):
        value = self.settings.get(key)
        return types.SimpleNamespace(value=value) if value is not None else None

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        pass

    async def commit(self):
        pass

    async def rollback(self):
        pass


def _client(role: Role = Role.USER, scope: str = "write", db: FakeDb | None = None) -> TestClient:
    user = types.SimpleNamespace(
        id=uuid.uuid4(), username="alice", role=role, display_name="Alice", email=None, auth_source="local",
        status="active", must_change_password=False, totp_enabled=False, last_login_at=None,
    )  # fmt: skip
    principal = Principal(user=user, token=types.SimpleNamespace(prefix="abcd1234", scope=scope))
    session = db or FakeDb()

    async def fake_db():
        yield session

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


def test_read_only_token_only_sees_read_tools():
    names = {t["name"] for t in _rpc(_client(Role.ADVANCED, scope="read"), "tools/list").json()["result"]["tools"]}
    assert {"list_projects", "get_project", "run_pipeline"} <= names
    assert not names & {"create_project", "update_project", "duplicate_project", "run_agent"}
    denied = _rpc(_client(scope="read"), "tools/call", {"name": "create_project", "arguments": {}}).json()
    assert denied["error"]["code"] == mcp.INVALID_PARAMS


def test_server_can_be_disabled_by_an_administrator():
    client = _client(db=FakeDb({"mcp": {"enabled": False}}))
    assert _rpc(client, "ping").status_code == 403


def test_tool_calls_are_audited(monkeypatch):
    async def fake_projects(principal, db):
        return []

    monkeypatch.setattr("app.api.projects.projects", fake_projects)
    db = FakeDb()
    _rpc(_client(db=db), "tools/call", {"name": "list_projects", "arguments": {}})
    _rpc(_client(db=db), "tools/call", {"name": "get_project", "arguments": {"project_id": "nope"}})
    entries = [(a.action, a.target, a.outcome, a.details["token"]) for a in db.added]
    assert entries == [
        ("mcp.tool_call", "list_projects", "success", "abcd1234"),
        ("mcp.tool_call", "get_project", "failure", "abcd1234"),
    ]


def test_parser_tools_are_available_to_read_only_tokens():
    client = _client(scope="read")
    names = {t["name"] for t in _rpc(client, "tools/list").json()["result"]["tools"]}
    assert {"list_parsers", "get_parser", "detect_format", "apply_parser", "convert_auditd"} <= names
    sample = '%ASA-4-106023: Deny tcp src o:1.2.3.4/5 dst i:10.0.0.1/22 by access-group "X"'
    res = _rpc(client, "tools/call", {"name": "detect_format", "arguments": {"sample": sample}}).json()["result"]
    assert res["structuredContent"]["matches"][0]["id"] == "cisco-asa"
    listed = _rpc(client, "tools/call", {"name": "list_parsers", "arguments": {"category": "industrial"}}).json()
    assert {p["category"] for p in listed["result"]["structuredContent"]["parsers"]} == {"industrial"}
