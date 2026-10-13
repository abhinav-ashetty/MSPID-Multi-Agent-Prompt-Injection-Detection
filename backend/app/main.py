"""AIShield FastAPI Application Entry Point."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api import health
from app.api import security
from app.api import simulation


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown events."""
    # Startup
    from app.database.database import create_tables
    create_tables()
    print(f"Starting {settings.app_name} v{settings.app_version}")
    yield
    # Shutdown
    print(f"Shutting down {settings.app_name}")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        debug=settings.debug,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[origin.strip() for origin in settings.frontend_origins.split(",") if origin.strip()],
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type"],
    )

    # Include API routers
    app.include_router(
        health.router,
        prefix=settings.api_prefix,
    )
    
    app.include_router(
        security.router,
        prefix=settings.api_prefix,
    )

    app.include_router(
        simulation.router,
        prefix=settings.api_prefix,
    )

    # Root endpoint
    @app.get("/", tags=["Root"])
    async def root():
        return {
            "message": f"Welcome to {settings.app_name}",
            "version": settings.app_version,
            "docs": "/docs",
        }

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
