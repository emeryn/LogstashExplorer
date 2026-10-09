"""MCP server (Model Context Protocol, Streamable HTTP transport, stateless JSON responses).

Authentication: the caller's personal API token (`Authorization: Bearer lsx_…`) only — no cookies.
Authorisation: every tool delegates to the very same route handlers as the web UI, called with the
token owner's principal. The MCP client therefore sees and does exactly what that user sees and does
in their session (own projects + personal/group shares, role-gated features), nothing more.
Deliberately not exposed: deletion, sharing management, token management and administration.
"""

import json
import logging
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app import __version__
from app.api import projects, workspace
from app.api.schemas import user_out
from app.core.deps import Principal, get_principal, get_principal_partial
from app.core.security import is_public_origin
from app.db.models import ROLE_RANK, Role
from app.db.session import get_db

router = APIRouter(prefix="/api", tags=["mcp"])
log = logging.getLogger(__name__)

PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26")
MAX_CONFIG = workspace.MAX_CONFIG
MAX_INPUT = workspace.MAX_INPUT

# JSON-RPC error codes
PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL_ERROR = -32700, -32600, -32601, -32602, -32603


# ---- Authentication --------------------------------------------------------------------------
async def get_token_principal(request: Request, db: AsyncSession = Depends(get_db)) -> Principal:
    """Bearer API token only. Same checks as the REST API (active account, no pending password change)."""
    if not request.headers.get("authorization", "").lower().startswith("bearer "):
        raise HTTPException(401, "API token required", headers={"WWW-Authenticate": 'Bearer realm="mcp"'})
    try:
        return await get_principal(await get_principal_partial(request, db))
    except HTTPException as exc:
        if exc.status_code == 401:
            exc.headers = {"WWW-Authenticate": 'Bearer realm="mcp", error="invalid_token"'}
        raise


# ---- Tool inputs -----------------------------------------------------------------------------
class NoArgs(BaseModel):
    pass


class ProjectRef(BaseModel):
    project_id: uuid.UUID = Field(description="Project identifier (see list_projects)")


class CreateProjectArgs(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    config: str = Field(max_length=MAX_CONFIG, description="Full logstash.conf content")
    sample: str | None = Field(default=None, max_length=MAX_INPUT, description="Sample source logs")
    input_format: Literal["lines", "json"] = "lines"
    instructions: str | None = Field(default=None, max_length=20_000)
    expected_output: str | None = Field(default=None, max_length=200_000)


class UpdateProjectArgs(BaseModel):
    project_id: uuid.UUID
    version: int = Field(ge=1, description="Version read with get_project (optimistic locking)")
    name: str | None = Field(default=None, min_length=1, max_length=128, description="Owner only")
    config: str | None = Field(default=None, max_length=MAX_CONFIG)
    sample: str | None = Field(default=None, max_length=MAX_INPUT)
    input_format: Literal["lines", "json"] | None = None
    instructions: str | None = Field(default=None, max_length=20_000)
    expected_output: str | None = Field(default=None, max_length=200_000)


class DuplicateArgs(BaseModel):
    project_id: uuid.UUID
    name: str | None = Field(default=None, max_length=128)


class RunArgs(BaseModel):
    config: str = Field(max_length=MAX_CONFIG, description="logstash.conf to test")
    input: str = Field(max_length=MAX_INPUT, description="Source logs (one event per line, or JSON lines)")
    input_format: Literal["lines", "json"] = "lines"


class AgentArgs(BaseModel):
    input: str = Field(min_length=1, max_length=MAX_INPUT, description="Source logs")
    input_format: Literal["lines", "json"] = "lines"
    instructions: str = Field(min_length=3, max_length=20_000, description="What the configuration must do")
    expected_output: str | None = Field(default=None, max_length=200_000, description="Expected JSON / JSON lines")
    initial_config: str | None = Field(default=None, max_length=MAX_CONFIG)
    max_iterations: int | None = Field(default=None, ge=1, le=20)


# ---- Tool implementations ----------------------------------------------------------------------
@dataclass
class Ctx:
    request: Request
    principal: Principal
    db: AsyncSession


async def _whoami(ctx: Ctx, _: NoArgs) -> dict:
    return {"user": user_out(ctx.principal.user)}


async def _list_projects(ctx: Ctx, _: NoArgs) -> dict:
    return {"projects": await projects.projects(principal=ctx.principal, db=ctx.db)}


async def _get_project(ctx: Ctx, a: ProjectRef) -> dict:
    return await projects.project_get(a.project_id, principal=ctx.principal, db=ctx.db)


async def _create_project(ctx: Ctx, a: CreateProjectArgs) -> dict:
    body = projects.ProjectIn(**a.model_dump())
    return await projects.project_create(body, ctx.request, principal=ctx.principal, db=ctx.db)


async def _update_project(ctx: Ctx, a: UpdateProjectArgs) -> dict:
    # Partial update on top of the version the user can read (access re-checked by the handler).
    current = await projects.project_get(a.project_id, principal=ctx.principal, db=ctx.db)
    fields = {k: current[k] for k in ("name", "config", "sample", "input_format", "instructions", "expected_output")}
    fields.update(a.model_dump(exclude={"project_id", "version"}, exclude_none=True))
    body = projects.ProjectUpdate(**fields, version=a.version, force=False)
    return await projects.project_update(a.project_id, body, ctx.request, principal=ctx.principal, db=ctx.db)


async def _duplicate_project(ctx: Ctx, a: DuplicateArgs) -> dict:
    body = projects.DuplicateIn(name=a.name)
    return await projects.project_duplicate(a.project_id, body, ctx.request, principal=ctx.principal, db=ctx.db)


async def _run_pipeline(ctx: Ctx, a: RunArgs) -> dict:
    body = workspace.RunIn(**a.model_dump())
    return await workspace.pipeline_run(body, principal=ctx.principal, db=ctx.db)


async def _run_agent(ctx: Ctx, a: AgentArgs) -> dict:
    body = workspace.AgentIn(**a.model_dump())
    response = await workspace.agent_run(body, ctx.request, principal=ctx.principal, db=ctx.db)
    events: list[dict] = []
    try:
        async for chunk in response.body_iterator:
            line = chunk.decode() if isinstance(chunk, bytes) else chunk
            events.extend(json.loads(part) for part in line.splitlines() if part.strip())
    finally:
        if response.background:
            await response.background()  # releases the user's run slot (idempotent)
    done = next((e for e in reversed(events) if e.get("type") == "done"), None)
    issues = [e["issues"] for e in events if e.get("type") == "evaluation"]
    errors = [e["message"] for e in events if e.get("type") == "error"]
    return {
        "success": bool(done and done.get("success")),
        "iterations": done.get("iterations") if done else 0,
        "config": done.get("config") if done else None,
        "last_issues": issues[-1] if issues else [],
        "errors": errors,
    }


@dataclass
class Tool:
    name: str
    description: str
    args: type[BaseModel]
    run: Callable[[Ctx, Any], Awaitable[dict]]
    min_role: Role = Role.USER
    read_only: bool = False

    def describe(self) -> dict:
        schema = self.args.model_json_schema()
        schema.pop("title", None)
        schema.setdefault("properties", {})
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": schema,
            "annotations": {"readOnlyHint": self.read_only, "destructiveHint": False, "openWorldHint": False},
        }


TOOLS = {
    t.name: t
    for t in (
        Tool("whoami", "Account behind the API token (username, role).", NoArgs, _whoami, read_only=True),
        Tool(
            "list_projects",
            "Projects visible to the user: owned ones and those shared with them (personally or via a group).",
            NoArgs,
            _list_projects,
            read_only=True,
        ),
        Tool(
            "get_project",
            "Open a project: configuration, sample logs, instructions, expected output and current version.",
            ProjectRef,
            _get_project,
            read_only=True,
        ),
        Tool("create_project", "Save a new project owned by the user.", CreateProjectArgs, _create_project),
        Tool(
            "update_project",
            "Save changes to a project the user may write. Only provided fields change. "
            "Fails with a conflict if `version` is not the latest one.",
            UpdateProjectArgs,
            _update_project,
        ),
        Tool(
            "duplicate_project",
            "Copy a readable project into a new project owned by the user.",
            DuplicateArgs,
            _duplicate_project,
        ),
        Tool(
            "run_pipeline",
            "Run a Logstash configuration on sample logs in the isolated runner and return events and errors.",
            RunArgs,
            _run_pipeline,
            read_only=True,
        ),
        Tool(
            "run_agent",
            "Autonomous agent: generate, run and auto-correct a Logstash filter until it meets the instructions "
            "(and the expected output when given). Can take several minutes.",
            AgentArgs,
            _run_agent,
            min_role=Role.ADVANCED,
        ),
    )
}


def _allowed(tool: Tool, principal: Principal) -> bool:
    return ROLE_RANK[principal.user.role] >= ROLE_RANK[tool.min_role]


def _tool_result(data: dict) -> dict:
    data = jsonable_encoder(data)  # UUIDs, datetimes…
    return {
        "content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False)}],
        "structuredContent": data,
        "isError": False,
    }


def _tool_error(message: str) -> dict:
    return {"content": [{"type": "text", "text": message}], "isError": True}


# ---- JSON-RPC dispatch -----------------------------------------------------------------------
class RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


async def _dispatch(method: str, params: dict, ctx: Ctx) -> dict:
    if method == "initialize":
        requested = params.get("protocolVersion")
        return {
            "protocolVersion": requested if requested in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "logstash-explorer", "title": "Logstash Explorer", "version": __version__},
            "instructions": (
                f"Acting as '{ctx.principal.user.username}' (role {ctx.principal.user.role.value}). "
                "Tools only reach projects this user can open in the web workspace. "
                "Use run_pipeline to test a configuration before saving it with update_project."
            ),
        }
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": [t.describe() for t in TOOLS.values() if _allowed(t, ctx.principal)]}
    if method == "tools/call":
        return await _call_tool(params, ctx)
    raise RpcError(METHOD_NOT_FOUND, f"Method not found: {method}")


async def _call_tool(params: dict, ctx: Ctx) -> dict:
    name = params.get("name")
    tool = TOOLS.get(name) if isinstance(name, str) else None
    if tool is None or not _allowed(tool, ctx.principal):
        raise RpcError(INVALID_PARAMS, f"Unknown tool: {name}")  # do not reveal role-gated tools
    try:
        args = tool.args.model_validate(params.get("arguments") or {})
    except ValidationError as exc:
        # Do not echo submitted values (may contain logs/secrets).
        details = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
        return _tool_error(f"Invalid arguments: {details}")
    log.info(
        "mcp tool call",
        extra={"ctx": {"user": ctx.principal.user.username, "tool": tool.name, "token": ctx.principal.token.prefix}},
    )
    try:
        return _tool_result(await tool.run(ctx, args))
    except HTTPException as exc:
        await ctx.db.rollback()
        return _tool_error(f"{exc.status_code}: {exc.detail}")


def _check_origin(request: Request) -> None:
    """DNS-rebinding protection required by the MCP transport spec."""
    origin = request.headers.get("origin")
    if origin and not is_public_origin(origin):
        raise HTTPException(403, "Origin not allowed")


def _rpc_error(msg_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


@router.post("/mcp")
async def mcp_endpoint(
    request: Request, principal: Principal = Depends(get_token_principal), db: AsyncSession = Depends(get_db)
) -> Response:
    _check_origin(request)
    version = request.headers.get("mcp-protocol-version")
    if version and version not in PROTOCOL_VERSIONS:
        return JSONResponse(_rpc_error(None, INVALID_REQUEST, f"Unsupported protocol version: {version}"), 400)
    try:
        message = json.loads(await request.body())
    except ValueError, UnicodeDecodeError:
        return JSONResponse(_rpc_error(None, PARSE_ERROR, "Parse error"), 400)
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return JSONResponse(_rpc_error(None, INVALID_REQUEST, "Invalid request (batches are not supported)"), 400)
    msg_id = message.get("id")
    if "method" not in message or msg_id is None:
        return Response(status_code=202)  # notification or client response: nothing to answer when stateless
    params = message.get("params") or {}
    if not isinstance(params, dict) or not isinstance(message["method"], str):
        return JSONResponse(_rpc_error(msg_id, INVALID_PARAMS, "Invalid params"))
    ctx = Ctx(request=request, principal=principal, db=db)
    try:
        result = await _dispatch(message["method"], params, ctx)
    except RpcError as exc:
        return JSONResponse(_rpc_error(msg_id, exc.code, exc.message))
    except Exception:  # noqa: BLE001
        log.exception("mcp request failed")
        return JSONResponse(_rpc_error(msg_id, INTERNAL_ERROR, "Internal error"))
    return JSONResponse({"jsonrpc": "2.0", "id": msg_id, "result": result})


@router.get("/mcp")
@router.delete("/mcp")
async def mcp_no_stream(_: Principal = Depends(get_token_principal)) -> Response:
    """Stateless server: no server-initiated SSE stream and no session to terminate."""
    return Response(status_code=405, headers={"Allow": "POST"})
