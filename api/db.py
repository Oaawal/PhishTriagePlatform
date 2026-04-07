import os
from sqlmodel import SQLModel, create_engine, Session

# Use DATABASE_URL from environment (Render, Supabase, Neon, etc.)
# Fallback to SQLite for local development
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./dev.db")

# SQLite requires special connection args
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

# Create engine
engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args=connect_args
)


# Initialize database and create tables
def init_db():
    from api.models import Case, Number, Report
    SQLModel.metadata.create_all(engine)


# Dependency for FastAPI routes
def get_session():
    with Session(engine) as session:
        yield session
