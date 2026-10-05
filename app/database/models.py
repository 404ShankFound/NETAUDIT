"""Readable SQLite tables for analyses, extracted packet telemetry, and alerts."""
from datetime import datetime
from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.database import Base


class Analysis(Base):
    __tablename__ = "analyses"
    id: Mapped[int] = mapped_column(primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    status: Mapped[str] = mapped_column(String(30), default="processing")
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    duration: Mapped[float] = mapped_column(Float, default=0.0)
    threat_score: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[str] = mapped_column(String(20), default="Low")
    statistics_json: Mapped[str] = mapped_column(Text, default="{}")
    threat_reasons_json: Mapped[str] = mapped_column(Text, default="[]")
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    packets: Mapped[list["Packet"]] = relationship(back_populates="analysis", cascade="all, delete-orphan")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="analysis", cascade="all, delete-orphan")


class Packet(Base):
    __tablename__ = "packets"
    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id"), index=True)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    packet_number: Mapped[int] = mapped_column(Integer)
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    protocol: Mapped[str] = mapped_column(String(30), default="OTHER", index=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    packet_length: Mapped[int] = mapped_column(Integer, default=0)
    tcp_flags: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dns_query: Mapped[str | None] = mapped_column(String(255), nullable=True)
    http_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    http_method: Mapped[str | None] = mapped_column(String(20), nullable=True)
    http_uri: Mapped[str | None] = mapped_column(String(500), nullable=True)
    analysis: Mapped[Analysis] = relationship(back_populates="packets")


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id"), index=True)
    alert_type: Mapped[str] = mapped_column(String(80))
    severity: Mapped[str] = mapped_column(String(20))
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    description: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str] = mapped_column(Text)
    score: Mapped[int] = mapped_column(Integer)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    analysis: Mapped[Analysis] = relationship(back_populates="alerts")
