"""A minimal FastAPI app with no high-severity issue: the composite action's "gate passes" arm.

The `action-selftest` job in .github/workflows/ci.yml runs the action against this tree in gate
mode and asserts a pass. Keep it clean: anything added here must not raise a high+ finding.
"""
from fastapi import Depends, FastAPI, Header, HTTPException

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def require_user(authorization: str = Header(default="")) -> str:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="unauthorized")
    return authorization.removeprefix("Bearer ")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/me")
def me(user: str = Depends(require_user)) -> dict[str, str]:
    return {"user": user}
