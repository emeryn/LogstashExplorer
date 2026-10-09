from pydantic import BaseModel, Field

from app.db.models import User


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class CredentialIn(BaseModel):
    credential: dict
    name: str = Field(default="Security key", max_length=128)


class ChangePasswordIn(BaseModel):
    current_password: str = Field(max_length=1024)
    new_password: str = Field(min_length=1, max_length=1024)


class TokenIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    expires_in_days: int = Field(default=90, ge=1, le=3650)


def user_out(user: User) -> dict:
    return {
        "id": str(user.id),
        "username": user.username,
        "display_name": user.display_name,
        "email": user.email,
        "role": user.role.value,
        "status": user.status.value,
        "auth_source": user.auth_source.value,
        "must_change_password": user.must_change_password,
        "totp_enabled": user.totp_enabled,
        "locked": bool(user.locked_until),
        "last_login_at": user.last_login_at,
        "created_at": user.created_at,
    }
