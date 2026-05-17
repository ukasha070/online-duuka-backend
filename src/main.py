from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

# from slowapi.util import get_remote_address


from apps.auth.router import auth_router
from core.config import settings

app = FastAPI(
    title="Online Duuka API",
    description="API for Online Duuka, an e-commerce platform.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_HOSTS,
    allow_credentials=True,
    allow_methods=settings.ALLOWED_METHODS,
    allow_headers=["*"],
)
app.router


limiter = Limiter(
    key_func=lambda request: request.client.host,
)


# Register the error handler
app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler,  # type: ignore
)

app.mount(
    "/static",
    StaticFiles(directory=settings.BASE_DIR / "static"),
    name="static",
)
app.mount(
    "/media",
    StaticFiles(directory=settings.BASE_DIR / "media"),
    name="media",
)
app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])


@app.get("/api/health")
async def health_check():
    return {"message": "Service is running"}
