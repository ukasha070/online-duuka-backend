from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.core._orjson import CustomORJSONResponse
from app.core.redis_client import close_redis_client
from app.routers import admin, agents, auth, billing, boosters, conversations, locations, products, shops, users
from app.services.cache_service import init_cache


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_cache(app)
    yield
    await close_redis_client()


app = FastAPI(
    title="Online Duuka API",
    description="API for Online Duuka, an e-commerce platform.",
    version="1.0.0",
    default_response_class=CustomORJSONResponse,
    docs_url=None if settings.ENV == "production" else "/docs",
    redoc_url=None if settings.ENV == "production" else "/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_HOSTS,
    allow_credentials=True,
    allow_methods=settings.ALLOWED_METHODS,
    allow_headers=["*"],
)

limiter = Limiter(key_func=lambda request: request.client.host if request.client else "unknown")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

static_dir = settings.BASE_DIR / "static"
media_dir = settings.BASE_DIR / "media"

if static_dir.exists():
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

media_dir.mkdir(parents=True, exist_ok=True)
app.mount("/media", StaticFiles(directory=media_dir), name="media")

app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(users.router, prefix="/api/users", tags=["Users"])
app.include_router(agents.router, prefix="/api/agents", tags=["Agents"])
app.include_router(shops.router, prefix="/api/shops", tags=["Shops"])
app.include_router(products.router, prefix="/api/products", tags=["Products"])
app.include_router(boosters.router, prefix="/api/boosters", tags=["Boosters"])
app.include_router(billing.router, prefix="/api/billing", tags=["Billing"])
app.include_router(conversations.router, prefix="/api/conversations", tags=["Conversations"])
app.include_router(locations.router, prefix="/api/locations", tags=["Locations"])
app.include_router(admin.router, prefix="/api/admin", tags=["Admin"])


@app.get("/api/health")
async def health_check() -> dict[str, str | bool]:
    return {"message": "Service is running", "cache_enabled": bool(getattr(app.state, "cache_enabled", False))}
