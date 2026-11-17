"""Multi-tenant SaaS API — user profile + admin endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

router = APIRouter()


class UserUpdate(BaseModel):
    name: str
    role: str


class User:
    def __init__(self, user_id: str, role: str = "member") -> None:
        self.user_id = user_id
        self.role = role


def get_current_user() -> User:
    return User(user_id="demo")


@router.patch("/users/{user_id}")
def update_user(user_id: str, body: UserUpdate):
    # Mistake: copies the caller-supplied role straight onto the account with no
    # check that the CALLER already holds admin (CVE-2024-0795 shape).
    user = User(user_id=user_id)
    user.role = body.role
    return {"user_id": user.user_id, "role": user.role}


@router.patch("/admin/users/{user_id}")
def admin_update_user(
    user_id: str, body: UserUpdate, current_user: User = Depends(get_current_user)
):
    # Safe: the caller's own privilege is checked before writing the field.
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    user = User(user_id=user_id)
    user.role = body.role
    return {"user_id": user.user_id, "role": user.role}
