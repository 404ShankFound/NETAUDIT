"""SQLAlchemy setup for the PCAP-to-SQLite module."""
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from app.config import DATABASE_URL

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    """Provide one database session per HTTP request."""
    database = SessionLocal()
    try:
        yield database
    finally:
        database.close()
