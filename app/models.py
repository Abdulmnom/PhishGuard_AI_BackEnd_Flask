from sqlalchemy import Column, Integer, String, UniqueConstraint, ForeignKey, DateTime, Boolean, Text
from sqlalchemy.orm import relationship
from .database import Base
from datetime import datetime, timezone


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("email", name="uq_users_email"),
        UniqueConstraint("username", name="uq_users_username"),
    )

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), nullable=False, index=True)
    username = Column(String(255), nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    scan_logs = relationship("ScanLog", back_populates="user")


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    scan_type = Column(String(16), nullable=False)  # 'url' or 'email'
    input_value = Column(String(1024), nullable=False)
    reachable = Column(Boolean, nullable=True)
    status_code = Column(Integer, nullable=True)
    result_json = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    user = relationship("User", back_populates="scan_logs")
