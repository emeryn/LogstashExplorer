"""Just-in-time provisioning for OIDC / LDAPS identities with directory group → role mapping."""

from dataclasses import dataclass, field

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ROLE_RANK, AuthSource, GroupMapping, Role, User, UserGroup, UserStatus, utcnow
from app.services.settings_store import get_setting

MAX_GROUPS = 500


@dataclass
class ExternalIdentity:
    source: AuthSource  # OIDC or LDAP
    external_id: str
    username: str
    email: str | None = None
    display_name: str | None = None
    groups: list[str] = field(default_factory=list)


async def map_groups(db: AsyncSession, source: str, groups: list[str]) -> Role | None:
    """Highest role among matching mappings (case-insensitive), or None if no mapping matches."""
    if not groups:
        return None
    wanted = {g.lower() for g in groups}
    rows = (await db.execute(select(GroupMapping).where(GroupMapping.source == source))).scalars()
    roles = [m.role for m in rows if m.group.lower() in wanted]
    return max(roles, key=lambda r: ROLE_RANK[r]) if roles else None


async def provision(db: AsyncSession, ident: ExternalIdentity) -> tuple[User, bool]:
    """Return (user, created). New accounts are 'pending' unless auto-provisioning is enabled."""
    user = (
        await db.execute(select(User).where(User.auth_source == ident.source, User.external_id == ident.external_id))
    ).scalar_one_or_none()
    mapped = await map_groups(db, ident.source.value, ident.groups)
    created = False

    if user is None:
        cfg = await get_setting(db, "provisioning")
        username = ident.username
        if (await db.execute(select(User.id).where(User.username == username))).first():
            username = f"{ident.username}@{ident.source.value}"
        user = User(
            username=username[:128],
            email=ident.email,
            display_name=ident.display_name,
            auth_source=ident.source,
            external_id=ident.external_id,
            role=mapped or Role(cfg["default_role"]),
            status=UserStatus.ACTIVE if cfg["auto_provisioning"] else UserStatus.PENDING,
        )
        db.add(user)
        created = True
    else:
        # Directory groups are authoritative when at least one mapping matches.
        if mapped is not None:
            user.role = mapped
        user.email = ident.email or user.email
        user.display_name = ident.display_name or user.display_name

    if user.status == UserStatus.ACTIVE:
        user.last_login_at = utcnow()
    await db.flush()
    await sync_groups(db, user, ident.source.value, ident.groups)
    return user, created


async def sync_groups(db: AsyncSession, user: User, source: str, groups: list[str]) -> None:
    """Replace the stored directory groups of `user` for `source` (used by group-based sharing)."""
    await db.execute(delete(UserGroup).where(UserGroup.user_id == user.id, UserGroup.source == source))
    seen: set[str] = set()
    for g in groups[:MAX_GROUPS]:
        g = g.strip()[:512]
        key = g.lower()
        if not g or key in seen:
            continue
        seen.add(key)
        db.add(UserGroup(user_id=user.id, source=source, group=g, group_key=key))
    await db.flush()
