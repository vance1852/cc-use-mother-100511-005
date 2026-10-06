"""封装 SQLite 连接、建表和事务边界。"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS organizations (
    organization_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actors (
    actor_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sites (
    site_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    name TEXT NOT NULL,
    timezone_name TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 1),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS domain_records (
    record_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    category TEXT NOT NULL,
    external_key TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    UNIQUE(site_id, category, external_key)
);
CREATE TABLE IF NOT EXISTS request_receipts (
    request_id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    occurred_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actor_capabilities (
    actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    capability TEXT NOT NULL,
    granted_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(actor_id, capability)
);
CREATE TABLE IF NOT EXISTS risk_events (
    event_id TEXT PRIMARY KEY,
    origin_organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    summary TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    current_revision INTEGER NOT NULL CHECK(current_revision >= 1),
    status TEXT NOT NULL CHECK(status IN ('active', 'withdrawn')),
    agreed_level TEXT,
    submitted_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS risk_event_revisions (
    event_id TEXT NOT NULL REFERENCES risk_events(event_id),
    revision INTEGER NOT NULL,
    summary TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    change_note TEXT NOT NULL,
    proposed_level TEXT,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY(event_id, revision)
);
CREATE TABLE IF NOT EXISTS risk_participants (
    event_id TEXT NOT NULL REFERENCES risk_events(event_id),
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    relation TEXT NOT NULL CHECK(relation IN ('originator', 'recipient')),
    added_at TEXT NOT NULL,
    PRIMARY KEY(event_id, organization_id)
);
CREATE TABLE IF NOT EXISTS risk_id_mappings (
    mapping_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES risk_events(event_id),
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    local_reference TEXT NOT NULL,
    mapped_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    UNIQUE(event_id, organization_id),
    UNIQUE(organization_id, local_reference)
);
CREATE TABLE IF NOT EXISTS risk_level_proposals (
    proposal_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES risk_events(event_id),
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    revision INTEGER NOT NULL,
    proposed_level TEXT NOT NULL,
    rationale TEXT NOT NULL,
    proposed_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    UNIQUE(event_id, organization_id, revision)
);
CREATE TABLE IF NOT EXISTS risk_level_agreements (
    event_id TEXT NOT NULL REFERENCES risk_events(event_id),
    revision INTEGER NOT NULL,
    agreed_level TEXT NOT NULL,
    agreed_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY(event_id, revision)
);
CREATE TABLE IF NOT EXISTS risk_receipts (
    receipt_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES risk_events(event_id),
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    revision INTEGER NOT NULL,
    content_hash TEXT NOT NULL,
    note TEXT,
    received_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    UNIQUE(event_id, organization_id, revision)
);
CREATE TABLE IF NOT EXISTS risk_obligations (
    obligation_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES risk_events(event_id),
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    kind TEXT NOT NULL,
    required_level TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('open', 'discharged')),
    created_revision INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    discharged_at TEXT,
    discharge_note TEXT,
    UNIQUE(event_id, organization_id, kind, created_revision)
);
CREATE TABLE IF NOT EXISTS risk_deliveries (
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    seq INTEGER NOT NULL,
    event_id TEXT NOT NULL REFERENCES risk_events(event_id),
    kind TEXT NOT NULL CHECK(kind IN ('submitted', 'revised', 'level_agreed', 'withdrawn')),
    revision INTEGER NOT NULL,
    enqueued_at TEXT NOT NULL,
    completed_at TEXT,
    PRIMARY KEY(organization_id, seq)
);
"""


class Database:
    """管理 SQLite 数据库并为服务提供短事务。"""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self.connection = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = 5000")
        self.connection.executescript(SCHEMA)

    @contextmanager
    def transaction(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """在异常时回滚，在成功时提交。"""

        self.connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
        try:
            yield self.connection
        except Exception:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()

    def close(self) -> None:
        """关闭底层连接。"""

        self.connection.close()
