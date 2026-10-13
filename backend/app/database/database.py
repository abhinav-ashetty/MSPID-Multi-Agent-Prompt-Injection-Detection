"""Database setup and session management for AIShield Defender persistence."""

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy.pool import StaticPool
from typing import Generator
import os
from pathlib import Path


class Base(DeclarativeBase):
    """Base class for all database models."""
    pass


def get_database_url() -> str:
    """Get the database URL for SQLite.
    
    Returns:
        SQLite database URL pointing to backend/data/aishield.db
    """
    # Ensure data directory exists
    data_dir = Path(__file__).resolve().parent.parent / "data"
    data_dir.mkdir(exist_ok=True)
    
    # SQLite database file path
    db_path = data_dir / "aishield.db"
    
    # Return SQLite URL
    return f"sqlite:///{db_path.absolute()}"


def create_database_engine():
    """Create and configure the SQLAlchemy engine for SQLite.
    
    Returns:
        Configured SQLAlchemy engine instance
    """
    database_url = get_database_url()
    
    # Create engine with appropriate settings for SQLite
    engine = create_engine(
        database_url,
        connect_args={"check_same_thread": False},  # Needed for SQLite
        poolclass=StaticPool,  # Use static pool for SQLite in development
        echo=False,  # Set to True for SQL query logging
    )
    
    return engine


# Create engine and session factory
engine = create_database_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator:
    """Dependency to get database session.
    
    Yields:
        SQLAlchemy database session
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables() -> None:
    """Create all database tables.

    This function is idempotent - safe to call multiple times.
    It imports the repository module to ensure all models are registered
    with the Base metadata before creating tables.
    """
    # Import repositories to register their models with Base metadata.
    from app.database import repository  # noqa: F401
    from app.database import simulation_repository  # noqa: F401
    Base.metadata.create_all(bind=engine)
    columns = {column["name"] for column in inspect(engine).get_columns("security_assessments")}
    if "gemini_used" not in columns:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE security_assessments "
                    "ADD COLUMN gemini_used BOOLEAN NOT NULL DEFAULT 1"
                )
            )
