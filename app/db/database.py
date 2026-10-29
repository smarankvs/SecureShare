import logging
from typing import Generator
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.core.config import settings

logger = logging.getLogger("secureshare.db")

raw_db_url = settings.get_database_url()

# Attempt to configure primary database engine (PostgreSQL by default)
engine = None
SessionLocal = None
Base = declarative_base()


def _ensure_sqlite_schema(eng):
    """Backfill legacy SQLite schema for older fallback databases missing newer columns."""
    if not str(eng.url).startswith("sqlite"):
        return

    with eng.begin() as conn:
        inspector = inspect(conn)
        if not inspector.has_table("users"):
            Base.metadata.create_all(bind=eng)
            return

        columns = {column["name"] for column in inspector.get_columns("users")}
        if "username" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN username VARCHAR(50)"))

        index_names = {index["name"] for index in inspector.get_indexes("users")}
        if "ix_users_username" not in index_names:
            try:
                conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_username ON users (username)"))
            except Exception:
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_users_username ON users (username)"))


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

        if str(eng.url).startswith("sqlite"):
            _ensure_sqlite_schema(eng)

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
        _ensure_sqlite_schema(eng)
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
    Create database tables if they do not exist and backfill legacy SQLite schema.
    """
    try:
        eng = get_engine()
        Base.metadata.create_all(bind=eng)
        _ensure_sqlite_schema(eng)
        logger.info("Database schema initialized successfully.")
    except Exception as exc:
        logger.error(f"Error initializing database schema: {exc}")
        raise
