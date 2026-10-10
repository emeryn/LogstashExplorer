"""Library of ready-made parsers: browse, open and detect the format of a sample."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app import parsers
from app.core.deps import Principal, require_role
from app.db.models import Role

router = APIRouter(prefix="/api/parsers", tags=["parsers"])
any_user = require_role(Role.USER)


class DetectIn(BaseModel):
    sample: str = Field(min_length=1, max_length=5 * 1024 * 1024)
    input_format: Literal["lines", "json"] | None = None


@router.get("")
async def parser_list(
    category: str | None = Query(default=None, max_length=32), _: Principal = Depends(any_user)
) -> dict:
    items = [p.summary() for p in parsers.all_parsers() if not category or p.category == category]
    return {"categories": [{"id": k, "label": v} for k, v in parsers.CATEGORIES.items()], "parsers": items}


@router.get("/{parser_id}")
async def parser_get(parser_id: str, _: Principal = Depends(any_user)) -> dict:
    parser = parsers.get(parser_id)
    if parser is None:
        raise HTTPException(404, "Parser not found")
    return parser.full()


@router.post("/detect")
async def parser_detect(body: DetectIn, _: Principal = Depends(any_user)) -> dict:
    return {"matches": parsers.detect(body.sample, body.input_format)}
