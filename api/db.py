import os

from sqlmodel import Session, SQLModel, create_engine

# Use DATABASE_URL from the environment (Render, Railway, Supabase, Neon...).
# Falls back to SQLite for local development.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./dev.db")

# Use the psycopg (v3) driver explicitly. Providers hand out postgres:// or
# postgresql:// URLs; SQLAlchemy rejects the first and may pick a different
# driver for the second depending on its version.
for prefix in ("postgres://", "postgresql://", "postgresql+psycopg2://"):
    if DATABASE_URL.startswith(prefix):
        DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len(prefix):]
        break

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, echo=False, connect_args=connect_args, pool_pre_ping=True)


def init_db():
    from api import models  # noqa: F401  (registers tables)
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session
