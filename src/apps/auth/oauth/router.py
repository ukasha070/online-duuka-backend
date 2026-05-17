from fastapi import APIRouter

from .google.router import router as google_oauth_router

router = APIRouter(
    prefix="",
    tags=["OAuth"],
)

router.include_router(google_oauth_router, prefix="/google", tags=["google-auth"])
