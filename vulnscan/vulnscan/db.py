"""Persistence: scan metadata + live progress in SQL (SQLite locally, Postgres in Docker).
Findings and reports are files under DATA_DIR/scans/<id>/."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import Settings, get_settings


class Base(DeclarativeBase):
    pass


class ScanRow(Base):
    __tablename__ = "scans"
    id = Column(String(32), primary_key=True)
    target = Column(Text, nullable=False)
    kind = Column(String(16))
    profile = Column(String(16))
    status = Column(String(16), default="queued")  # queued | running | done | failed
    stage = Column(String(16), default="queued")
    request_json = Column(Text)
    progress_json = Column(Text, default="{}")
    summary_json = Column(Text, default="{}")
    error = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    finished_at = Column(DateTime(timezone=True), nullable=True)

    def to_dict(self, with_progress: bool = True) -> dict:
        d = {
            "id": self.id, "target": self.target, "kind": self.kind, "profile": self.profile, "status": self.status,
            "stage": self.stage, "error": self.error, "summary": json.loads(self.summary_json or "{}"),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
        }
        if with_progress:
            d["progress"] = json.loads(self.progress_json or "{}")
        return d


class Store:
    def __init__(self, settings: Settings | None = None):
        s = settings or get_settings()
        kwargs = {"connect_args": {"check_same_thread": False}} if s.db_url.startswith("sqlite") else {"pool_pre_ping": True}
        self.engine = create_engine(s.db_url, **kwargs)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(self.engine, expire_on_commit=False)

    def create(self, scan_id: str, target: str, kind: str, profile: str, request_json: str) -> ScanRow:
        with self.Session() as db:
            row = ScanRow(id=scan_id, target=target, kind=kind, profile=profile, request_json=request_json)
            db.add(row)
            db.commit()
            return row

    def get(self, scan_id: str) -> ScanRow | None:
        with self.Session() as db:
            return db.get(ScanRow, scan_id)

    def list(self, limit: int = 100) -> list[ScanRow]:
        with self.Session() as db:
            return list(db.scalars(select(ScanRow).order_by(ScanRow.created_at.desc()).limit(limit)))

    def update(self, scan_id: str, **fields) -> None:
        with self.Session() as db:
            row = db.get(ScanRow, scan_id)
            if not row:
                return
            for k, v in fields.items():
                if k in ("progress", "summary"):
                    setattr(row, f"{k}_json", json.dumps(v, default=str))
                else:
                    setattr(row, k, v)
            db.commit()

    def delete(self, scan_id: str) -> None:
        with self.Session() as db:
            row = db.get(ScanRow, scan_id)
            if row:
                db.delete(row)
                db.commit()
