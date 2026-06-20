from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def auth_health() -> dict[str, str]:
    return {"router": "auth", "status": "ok"}
