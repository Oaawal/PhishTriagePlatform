import os

from sqlmodel import Session, SQLModel, create_engine

# Use DATABASE_URL from the environment (Render, Railway, Supabase, Neon...).
# Falls back to SQLite for local development.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./dev.db")

# Some providers still hand out postgres:// URLs, which SQLAlchemy rejects.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, echo=False, connect_args=connect_args, pool_pre_ping=True)


def init_db():
    from api import models  # noqa: F401  (registers tables)
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session
