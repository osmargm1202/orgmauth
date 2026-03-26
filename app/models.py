from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    Boolean,
    ForeignKey,
    Text,
    Index,
)
from sqlalchemy.orm import relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    google_id = Column(String(255), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False)
    picture = Column(Text, nullable=True)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    last_access = Column(DateTime, nullable=True)

    denied_apps = relationship(
        "UserDeniedApp", back_populates="user", cascade="all, delete-orphan"
    )
    sessions = relationship(
        "Session", back_populates="user", cascade="all, delete-orphan"
    )
    access_logs = relationship(
        "AccessLog", back_populates="user", cascade="all, delete-orphan"
    )


class Application(Base):
    __tablename__ = "applications"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )


class UserDeniedApp(Base):
    __tablename__ = "user_denied_apps"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    app_name = Column(String(100), nullable=False)
    denied_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    denied_by = Column(String(255), nullable=True)

    user = relationship("User", back_populates="denied_apps")

    __table_args__ = (Index("idx_user_denied_app", "user_id", "app_name", unique=True),)


class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    refresh_token_hash = Column(String(255), nullable=False)
    access_token_hash = Column(String(255), nullable=False)
    app_name = Column(String(100), nullable=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    revoked = Column(Boolean, default=False, nullable=False)

    user = relationship("User", back_populates="sessions")


class OAuthFlow(Base):
    __tablename__ = "oauth_flows"

    id = Column(Integer, primary_key=True, index=True)
    state_id = Column(String(128), unique=True, index=True, nullable=False)
    flow_id = Column(String(128), index=True, nullable=False)
    app_name = Column(String(100), nullable=False)
    redirect_uri = Column(Text, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    consumed_at = Column(DateTime, nullable=True)


class AccessLog(Base):
    __tablename__ = "access_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    app_name = Column(String(100), nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    timestamp = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )

    user = relationship("User", back_populates="access_logs")

    __table_args__ = (
        Index("idx_access_log_app", "app_name"),
        Index("idx_access_log_timestamp", "timestamp"),
    )
