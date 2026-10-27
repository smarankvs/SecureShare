import logging
from typing import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.core.config import settings

logger = logging.getLogger("secureshare.db")

raw_db_url = settings.get_database_url()

# Attempt to configure primary database engine (PostgreSQL by default)
engine = None
SessionLocal = None
Base = declarative_base()


def get_engine():
    global engine, SessionLocal
    if engine is not None:
        return engine

    try:
        if raw_db_url.startswith("sqlite"):
            eng = create_engine(raw_db_url, connect_args={"check_same_thread": False})
        else:
            eng = create_engine(
                raw_db_url,
                pool_size=10,
                max_overflow=20,
                pool_pre_ping=True,
                pool_recycle=300,
            )
            # Test connectivity
            with eng.connect() as conn:
                conn.execute(text("SELECT 1"))

        engine = eng
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        logger.info(f"Database connected using: {raw_db_url.split('@')[-1] if '@' in raw_db_url else 'local'}")
        return engine
    except Exception as exc:
        logger.warning(
            f"Primary database connection to PostgreSQL failed: {exc}. "
            "Falling back to local SQLite database (secureshare.db) for instant execution."
        )
        sqlite_fallback = "sqlite:///./secureshare.db"
        eng = create_engine(sqlite_fallback, connect_args={"check_same_thread": False})
        engine = eng
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        return engine


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that provides a transactional database session per request.
    Automatically handles rollback on exceptions and cleanup upon completion.
    """
    if SessionLocal is None:
        get_engine()
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    """
    Create database tables if they do not exist.
    """
    try:
        eng = get_engine()
        Base.metadata.create_all(bind=eng)
        logger.info("Database schema initialized successfully.")
    except Exception as exc:
        logger.error(f"Error initializing database schema: {exc}")
        raise
