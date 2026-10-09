"""Workspace: run pipelines, convert EVTX, autonomous agent (streamed NDJSON)."""

import json
import logging
from typing import Literal

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.background import BackgroundTask

from app.core.config import get_settings
from app.core.deps import Principal, require_role
from app.db.models import Role
from app.db.session import get_db, sessionmaker
from app.services.agent import run_agent
from app.services.audit import audit
from app.services.concurrency import RunSlot, user_run_slot
from app.services.evtx2json import evtx_to_json_lines, is_evtx
from app.services.runner_client import RunnerError, run_pipeline
from app.services.settings_store import get_setting

router = APIRouter(prefix="/api", tags=["workspace"])
log = logging.getLogger(__name__)
any_user = require_role(Role.USER)
advanced = require_role(Role.ADVANCED)

MAX_CONFIG = 256 * 1024
MAX_INPUT = 5 * 1024 * 1024


class RunIn(BaseModel):
    config: str = Field(max_length=MAX_CONFIG)
    input: str = Field(max_length=MAX_INPUT)
    input_format: Literal["lines", "json"] = "lines"


@router.post("/pipeline/run")
async def pipeline_run(
    body: RunIn, principal: Principal = Depends(any_user), db: AsyncSession = Depends(get_db)
) -> dict:
    ecs = (await get_setting(db, "ai"))["ecs_compatibility"]
    async with user_run_slot(principal.user.id):
        try:
            result = await run_pipeline(body.config, body.input, body.input_format, ecs)
        except RunnerError as exc:
            raise HTTPException(503, str(exc)) from exc
    log.info(
        "pipeline run",
        extra={
            "ctx": {"user": principal.user.username, "ok": result.get("ok"), "duration_ms": result.get("duration_ms")}
        },
    )
    return result


@router.post("/pipeline/evtx")
async def pipeline_evtx(
    request: Request,
    file: UploadFile = File(...),
    principal: Principal = Depends(any_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    s = get_settings()
    limit = s.max_upload_mb * 1024 * 1024
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, f"File larger than {s.max_upload_mb} MB")
    if not is_evtx(data[:8]):
        raise HTTPException(422, "Not a Windows EVTX file")
    try:
        text, count, truncated = await run_in_threadpool(evtx_to_json_lines, data, s.max_evtx_records)
    except Exception as exc:  # noqa: BLE001 - parser errors on malformed files
        raise HTTPException(422, f"EVTX parsing failed: {exc.__class__.__name__}") from exc
    await audit(
        db,
        "data.evtx_import",
        request=request,
        actor=principal.user,
        target=(file.filename or "")[:256],
        details={"records": count, "truncated": truncated},
    )
    await db.commit()
    return {"input": text, "input_format": "json", "records": count, "truncated": truncated}


# ---- Autonomous agent ------------------------------------------------------------------------
class AgentIn(BaseModel):
    input: str = Field(min_length=1, max_length=MAX_INPUT)
    input_format: Literal["lines", "json"] = "lines"
    instructions: str = Field(min_length=3, max_length=20_000)
    expected_output: str | None = Field(default=None, max_length=200_000)
    initial_config: str | None = Field(default=None, max_length=MAX_CONFIG)
    max_iterations: int | None = Field(default=None, ge=1, le=20)


@router.post("/agent/run")
async def agent_run(
    body: AgentIn, request: Request, principal: Principal = Depends(advanced), db: AsyncSession = Depends(get_db)
) -> StreamingResponse:
    ai = await get_setting(db, "ai")
    max_iter = min(body.max_iterations or ai["max_iterations"], get_settings().agent_max_iterations, 20)
    # Reserve the user's slot now so a refused session fails fast with a clear 429.
    slot = RunSlot(principal.user.id)
    await audit(
        db,
        "agent.run",
        request=request,
        actor=principal.user,
        details={"provider": ai["provider"], "model": ai["model"], "max_iterations": max_iter},
    )
    await db.commit()

    async def stream():
        try:
            # Own DB session: the request-scoped one is closed while the response streams.
            async with sessionmaker()() as agent_db:
                async for event in run_agent(
                    agent_db,
                    logs=body.input,
                    input_format=body.input_format,
                    instructions=body.instructions,
                    expected_raw=body.expected_output,
                    initial_config=body.initial_config,
                    max_iterations=max_iter,
                ):
                    yield json.dumps(event, default=str, ensure_ascii=False) + "\n"
        except Exception:  # noqa: BLE001
            log.exception("agent run failed")
            yield json.dumps({"type": "error", "message": "Internal agent error"}) + "\n"
        finally:
            slot.release()

    return StreamingResponse(
        stream(),
        media_type="application/x-ndjson",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        background=BackgroundTask(slot.release),  # also released if the stream never started
    )
