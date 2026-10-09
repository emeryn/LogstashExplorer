"""Projects: save, duplicate and share Logstash workspaces between colleagues.

Access model
- owner  : everything, including sharing and deletion;
- write  : read + save (optimistic locking on `version`);
- read   : open and duplicate (a duplicate belongs to whoever made it).
Administrators get no implicit access to other people's projects (data minimisation).
"""

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import Principal, require_role
from app.db.models import (
    ROLE_RANK,
    AuthSource,
    GroupMapping,
    Pipeline,
    PipelineGroupShare,
    PipelineShare,
    Role,
    SharePermission,
    User,
    UserGroup,
    UserStatus,
    utcnow,
)
from app.db.session import get_db
from app.services.audit import audit

router = APIRouter(prefix="/api", tags=["projects"])
any_user = require_role(Role.USER)

MAX_CONFIG = 256 * 1024
MAX_INPUT = 5 * 1024 * 1024
Access = Literal["owner", "write", "read"]
RANK = {"read": 1, "write": 2, "owner": 3}


class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    config: str = Field(max_length=MAX_CONFIG)
    sample: str | None = Field(default=None, max_length=MAX_INPUT)
    input_format: Literal["lines", "json"] = "lines"
    instructions: str | None = Field(default=None, max_length=20_000)
    expected_output: str | None = Field(default=None, max_length=200_000)


class ProjectUpdate(ProjectIn):
    version: int = Field(ge=1)
    force: bool = False  # overwrite a newer version (explicit user choice after a conflict)


class DuplicateIn(BaseModel):
    name: str | None = Field(default=None, max_length=128)


class ShareIn(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    permission: SharePermission


def _best(perms) -> Access | None:
    values = [p.value if isinstance(p, SharePermission) else p for p in perms if p]
    return max(values, key=lambda v: RANK[v]) if values else None


def _group_shares_for(uid: uuid.UUID):
    """Group shares matching one of the user's directory groups (same source, case-insensitive)."""
    return (
        select(PipelineGroupShare)
        .join(
            UserGroup,
            (UserGroup.source == PipelineGroupShare.source) & (UserGroup.group_key == PipelineGroupShare.group_key),
        )
        .where(UserGroup.user_id == uid)
    )


async def _access(db: AsyncSession, principal: Principal, pid: uuid.UUID, need: Access) -> tuple[Pipeline, Access]:
    p = await db.get(Pipeline, pid)
    if p is None:
        raise HTTPException(404, "Project not found")
    if p.owner_id == principal.user.id:
        access: Access | None = "owner"
    else:
        uid = principal.user.id
        direct = await db.scalars(
            select(PipelineShare.permission).where(PipelineShare.pipeline_id == pid, PipelineShare.user_id == uid)
        )
        via_groups = await db.scalars(
            _group_shares_for(uid)
            .where(PipelineGroupShare.pipeline_id == pid)
            .with_only_columns(PipelineGroupShare.permission)
        )
        access = _best([*direct, *via_groups])  # highest of personal and group shares
        if access is None:
            raise HTTPException(404, "Project not found")  # do not reveal existence
    if RANK[access] < RANK[need]:
        raise HTTPException(403, "Insufficient rights on this project")
    return p, access


async def _owner_name(db: AsyncSession, owner_id: uuid.UUID) -> str:
    owner = await db.get(User, owner_id)
    return owner.username if owner else "?"


def _meta(p: Pipeline, access: str, owner: str, shares: int | None = None) -> dict:
    return {
        "id": str(p.id),
        "name": p.name,
        "input_format": p.input_format,
        "version": p.version,
        "updated_at": p.updated_at,
        "updated_by": p.updated_by,
        "owner": owner,
        "access": access,
        "shares": shares,
    }


async def _full(db: AsyncSession, p: Pipeline, access: str) -> dict:
    return {
        **_meta(p, access, await _owner_name(db, p.owner_id)),
        "config": p.config,
        "sample": p.sample,
        "instructions": p.instructions,
        "expected_output": p.expected_output,
    }


@router.get("/pipelines")
async def projects(principal: Principal = Depends(any_user), db: AsyncSession = Depends(get_db)) -> list[dict]:
    uid = principal.user.id
    user_shares = (
        select(PipelineShare.pipeline_id, func.count().label("n")).group_by(PipelineShare.pipeline_id).subquery()
    )
    group_shares = (
        select(PipelineGroupShare.pipeline_id, func.count().label("n"))
        .group_by(PipelineGroupShare.pipeline_id)
        .subquery()
    )
    mine = await db.execute(
        select(Pipeline, user_shares.c.n, group_shares.c.n)
        .outerjoin(user_shares, user_shares.c.pipeline_id == Pipeline.id)
        .outerjoin(group_shares, group_shares.c.pipeline_id == Pipeline.id)
        .where(Pipeline.owner_id == uid)
    )
    out = [_meta(p, "owner", principal.user.username, (nu or 0) + (ng or 0)) for p, nu, ng in mine]

    # Projects shared with me personally or through one of my directory groups (best permission wins).
    best: dict[uuid.UUID, list] = {}
    for pid, perm in await db.execute(
        select(PipelineShare.pipeline_id, PipelineShare.permission).where(PipelineShare.user_id == uid)
    ):
        best.setdefault(pid, []).append(perm)
    group_rows = await db.execute(
        _group_shares_for(uid).with_only_columns(
            PipelineGroupShare.pipeline_id, PipelineGroupShare.permission, PipelineGroupShare.group
        )
    )
    via: dict[uuid.UUID, list[str]] = {}
    for pid, perm, group in group_rows:
        best.setdefault(pid, []).append(perm)
        via.setdefault(pid, []).append(group)
    if best:
        rows = await db.execute(
            select(Pipeline, User.username)
            .join(User, User.id == Pipeline.owner_id)
            .where(Pipeline.id.in_(best), Pipeline.owner_id != uid)
        )
        for p, owner in rows:
            meta = _meta(p, _best(best[p.id]), owner)
            meta["via_groups"] = sorted(set(via.get(p.id, [])))
            out.append(meta)
    return sorted(out, key=lambda m: m["updated_at"], reverse=True)


@router.post("/pipelines")
async def project_create(
    body: ProjectIn, request: Request, principal: Principal = Depends(any_user), db: AsyncSession = Depends(get_db)
) -> dict:
    p = Pipeline(owner_id=principal.user.id, updated_by=principal.user.username, **body.model_dump())
    db.add(p)
    await db.flush()
    await audit(db, "project.create", request=request, actor=principal.user, target=str(p.id))
    await db.commit()
    return await _full(db, p, "owner")


@router.get("/pipelines/{pid}")
async def project_get(
    pid: uuid.UUID, principal: Principal = Depends(any_user), db: AsyncSession = Depends(get_db)
) -> dict:
    p, access = await _access(db, principal, pid, "read")
    return await _full(db, p, access)


@router.get("/pipelines/{pid}/meta")
async def project_meta(
    pid: uuid.UUID, principal: Principal = Depends(any_user), db: AsyncSession = Depends(get_db)
) -> dict:
    """Lightweight polling endpoint: lets an open editor notice a colleague's newer version."""
    p, access = await _access(db, principal, pid, "read")
    return _meta(p, access, await _owner_name(db, p.owner_id))


@router.put("/pipelines/{pid}")
async def project_update(
    pid: uuid.UUID,
    body: ProjectUpdate,
    request: Request,
    principal: Principal = Depends(any_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    p, access = await _access(db, principal, pid, "write")
    if p.version != body.version and not body.force:
        raise HTTPException(
            409,
            f"Conflict: {p.updated_by or 'a colleague'} saved version {p.version} "
            f"(you were editing version {body.version}).",
        )
    data = body.model_dump(exclude={"version", "force"})
    if access != "owner":
        data.pop("name")  # only the owner renames
    for k, v in data.items():
        setattr(p, k, v)
    p.version = p.version + 1
    p.updated_by = principal.user.username
    p.updated_at = utcnow()
    if body.force:
        await audit(db, "project.overwrite", request=request, actor=principal.user, target=str(p.id),
                    details={"overwritten_version": p.version - 1, "base_version": body.version})  # fmt: skip
    await db.commit()
    return await _full(db, p, access)


@router.post("/pipelines/{pid}/duplicate")
async def project_duplicate(
    pid: uuid.UUID,
    body: DuplicateIn,
    request: Request,
    principal: Principal = Depends(any_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    src, _ = await _access(db, principal, pid, "read")
    copy = Pipeline(
        owner_id=principal.user.id,
        name=(body.name or f"{src.name} (copy)")[:128],
        config=src.config,
        sample=src.sample,
        input_format=src.input_format,
        instructions=src.instructions,
        expected_output=src.expected_output,
        updated_by=principal.user.username,
    )
    db.add(copy)
    await db.flush()
    await audit(db, "project.duplicate", request=request, actor=principal.user, target=str(copy.id),
                details={"source": str(src.id)})  # fmt: skip
    await db.commit()
    return await _full(db, copy, "owner")


@router.delete("/pipelines/{pid}")
async def project_delete(
    pid: uuid.UUID, request: Request, principal: Principal = Depends(any_user), db: AsyncSession = Depends(get_db)
) -> dict:
    p, _ = await _access(db, principal, pid, "owner")
    await db.delete(p)
    await audit(db, "project.delete", request=request, actor=principal.user, target=str(pid), details={"name": p.name})
    await db.commit()
    return {"ok": True}


# ---- Sharing ---------------------------------------------------------------------------------
@router.get("/pipelines/{pid}/shares")
async def shares(
    pid: uuid.UUID, principal: Principal = Depends(any_user), db: AsyncSession = Depends(get_db)
) -> list[dict]:
    await _access(db, principal, pid, "owner")
    rows = await db.execute(
        select(PipelineShare, User.username, User.display_name)
        .join(User, User.id == PipelineShare.user_id)
        .where(PipelineShare.pipeline_id == pid)
        .order_by(User.username)
    )
    return [
        {"user_id": str(s.user_id), "username": u, "display_name": d, "permission": s.permission.value}
        for s, u, d in rows
    ]


@router.put("/pipelines/{pid}/shares")
async def share_upsert(
    pid: uuid.UUID,
    body: ShareIn,
    request: Request,
    principal: Principal = Depends(any_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    p, _ = await _access(db, principal, pid, "owner")
    target = (
        await db.execute(select(User).where(func.lower(User.username) == body.username.strip().lower()))
    ).scalar_one_or_none()
    if target is None or target.status != UserStatus.ACTIVE or target.auth_source == AuthSource.SERVICE:
        raise HTTPException(404, "User not found or inactive")
    if target.id == p.owner_id:
        raise HTTPException(400, "The owner already has full rights")
    share = (
        await db.execute(
            select(PipelineShare).where(PipelineShare.pipeline_id == pid, PipelineShare.user_id == target.id)
        )
    ).scalar_one_or_none()
    if share is None:
        db.add(PipelineShare(pipeline_id=pid, user_id=target.id, permission=body.permission))
    else:
        share.permission = body.permission
    try:
        await db.flush()
    except IntegrityError as exc:
        raise HTTPException(409, "Share already exists") from exc
    await audit(db, "project.share", request=request, actor=principal.user, target=str(pid),
                details={"with": target.username, "permission": body.permission.value})  # fmt: skip
    await db.commit()
    return {"ok": True}


@router.delete("/pipelines/{pid}/shares/{user_id}")
async def share_delete(
    pid: uuid.UUID,
    user_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(any_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _access(db, principal, pid, "owner")
    share = (
        await db.execute(
            select(PipelineShare).where(PipelineShare.pipeline_id == pid, PipelineShare.user_id == user_id)
        )
    ).scalar_one_or_none()
    if share is None:
        raise HTTPException(404, "Share not found")
    await db.delete(share)
    await audit(db, "project.unshare", request=request, actor=principal.user, target=str(pid),
                details={"user_id": str(user_id)})  # fmt: skip
    await db.commit()
    return {"ok": True}


@router.get("/users/directory")
async def directory(
    q: str = Query(min_length=2, max_length=64),
    principal: Principal = Depends(any_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Colleague lookup for sharing: active human accounts only, minimal fields, capped results."""
    pattern = f"%{q.lower().replace('%', '').replace('_', '')}%"
    rows = await db.execute(
        select(User.username, User.display_name)
        .where(
            User.status == UserStatus.ACTIVE,
            User.auth_source != AuthSource.SERVICE,
            User.id != principal.user.id,
            or_(func.lower(User.username).like(pattern), func.lower(User.display_name).like(pattern)),
        )
        .order_by(User.username)
        .limit(15)
    )
    return [{"username": u, "display_name": d} for u, d in rows]


# ---- Sharing with directory groups -------------------------------------------------------------
class GroupShareIn(BaseModel):
    source: Literal["ldap", "oidc"]
    group: str = Field(min_length=1, max_length=512)
    permission: SharePermission


def _is_admin(principal: Principal) -> bool:
    return ROLE_RANK[principal.user.role] >= ROLE_RANK[Role.ADMIN]


@router.get("/groups/mine")
async def my_groups(principal: Principal = Depends(any_user), db: AsyncSession = Depends(get_db)) -> list[dict]:
    """Directory groups asserted at my last SSO/LDAPS login (local accounts have none)."""
    rows = await db.execute(
        select(UserGroup.source, UserGroup.group, UserGroup.synced_at)
        .where(UserGroup.user_id == principal.user.id)
        .order_by(UserGroup.source, UserGroup.group)
    )
    return [{"source": s, "group": g, "synced_at": t} for s, g, t in rows]


@router.get("/groups/directory")
async def groups_directory(
    q: str = Query(default="", max_length=128),
    principal: Principal = Depends(any_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Groups the caller may share with: their own groups; administrators also see every known group
    (seen at a login or used in a role mapping). Avoids exposing the directory structure to everyone."""
    pattern = f"%{q.lower().replace('%', '').replace('_', '')}%"
    if _is_admin(principal):
        seen = select(UserGroup.source, UserGroup.group).where(UserGroup.group_key.like(pattern))
        mapped = select(GroupMapping.source, GroupMapping.group).where(func.lower(GroupMapping.group).like(pattern))
        stmt = seen.union(mapped)
    else:
        stmt = select(UserGroup.source, UserGroup.group).where(
            UserGroup.user_id == principal.user.id, UserGroup.group_key.like(pattern)
        )
    members = dict(
        (tuple(r[:2]), r[2])
        for r in await db.execute(
            select(UserGroup.source, UserGroup.group_key, func.count()).group_by(UserGroup.source, UserGroup.group_key)
        )
    )
    rows = sorted({(s, g) for s, g in await db.execute(stmt)}, key=lambda r: (r[0], r[1].lower()))[:50]
    return [{"source": s, "group": g, "members": members.get((s, g.lower()), 0)} for s, g in rows]


@router.get("/pipelines/{pid}/group-shares")
async def group_shares(
    pid: uuid.UUID, principal: Principal = Depends(any_user), db: AsyncSession = Depends(get_db)
) -> list[dict]:
    await _access(db, principal, pid, "owner")
    rows = await db.scalars(
        select(PipelineGroupShare)
        .where(PipelineGroupShare.pipeline_id == pid)
        .order_by(PipelineGroupShare.source, PipelineGroupShare.group)
    )
    members = await db.execute(
        select(UserGroup.source, UserGroup.group_key, func.count()).group_by(UserGroup.source, UserGroup.group_key)
    )
    counts = {(s, k): n for s, k, n in members}
    return [
        {
            "id": s.id,
            "source": s.source,
            "group": s.group,
            "permission": s.permission.value,
            "members": counts.get((s.source, s.group_key), 0),
        }
        for s in rows
    ]


@router.put("/pipelines/{pid}/group-shares")
async def group_share_upsert(
    pid: uuid.UUID,
    body: GroupShareIn,
    request: Request,
    principal: Principal = Depends(any_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _access(db, principal, pid, "owner")
    group = body.group.strip()
    key = group.lower()
    # Prefer the directory's canonical spelling when the group has been seen at a login.
    group = (
        await db.scalar(
            select(UserGroup.group).where(UserGroup.source == body.source, UserGroup.group_key == key).limit(1)
        )
        or group
    )
    if not _is_admin(principal):
        member = await db.scalar(
            select(UserGroup.id).where(
                UserGroup.user_id == principal.user.id, UserGroup.source == body.source, UserGroup.group_key == key
            )
        )
        if member is None:
            raise HTTPException(403, "You can only share with a group you are a member of")
    share = await db.scalar(
        select(PipelineGroupShare).where(
            PipelineGroupShare.pipeline_id == pid,
            PipelineGroupShare.source == body.source,
            PipelineGroupShare.group_key == key,
        )
    )
    if share is None:
        db.add(
            PipelineGroupShare(
                pipeline_id=pid,
                source=body.source,
                group=group,
                group_key=key,
                permission=body.permission,
                created_by=principal.user.username,
            )
        )
    else:
        share.permission = body.permission
    await db.flush()
    await audit(
        db,
        "project.share_group",
        request=request,
        actor=principal.user,
        target=str(pid),
        details={"source": body.source, "group": group, "permission": body.permission.value},
    )
    await db.commit()
    return {"ok": True}


@router.delete("/pipelines/{pid}/group-shares/{share_id}")
async def group_share_delete(
    pid: uuid.UUID,
    share_id: int,
    request: Request,
    principal: Principal = Depends(any_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _access(db, principal, pid, "owner")
    share = await db.get(PipelineGroupShare, share_id)
    if share is None or share.pipeline_id != pid:
        raise HTTPException(404, "Share not found")
    await db.delete(share)
    await audit(
        db,
        "project.unshare_group",
        request=request,
        actor=principal.user,
        target=str(pid),
        details={"source": share.source, "group": share.group},
    )
    await db.commit()
    return {"ok": True}
