from fastapi import APIRouter

from apps.auth.user.router import router as user_router
from apps.auth.oauth.router import router as oauth_router
from apps.auth.two_factor.router import router as two_factor_router
from apps.auth.verification.router import router as verification_router
from apps.auth.password_reset.router import router as password_reset_router

auth_router = APIRouter(prefix="", tags=["auth"])

auth_router.include_router(user_router)
auth_router.include_router(oauth_router, prefix="/oauth")
auth_router.include_router(two_factor_router, prefix="/2fa")
auth_router.include_router(verification_router, prefix="/verification")
auth_router.include_router(password_reset_router, prefix="/password-reset")
