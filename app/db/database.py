from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from app.core.config import settings


class Base(DeclarativeBase):
    pass


def normalized_database_url(raw: str) -> str:
    value = raw.strip()
    # Marketplace providers commonly expose postgres:// or postgresql:// URLs.
    if value.startswith("postgres://"):
        value = "postgresql+psycopg://" + value[len("postgres://"):]
    elif value.startswith("postgresql://"):
        value = "postgresql+psycopg://" + value[len("postgresql://"):]
    parsed = make_url(value)
    if parsed.drivername.startswith("sqlite") and parsed.database and not parsed.database.startswith("/") and parsed.database != ":memory:":
        # Resolve relative SQLite paths from the repository root, not the process CWD.
        from app.core.config import ROOT_DIR
        value = parsed.set(database=str((ROOT_DIR / parsed.database).resolve())).render_as_string(hide_password=False)
    return value


DATABASE_URL = normalized_database_url(settings.database_url)
connect_args = {"check_same_thread": False, "timeout": 20} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
