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
CREATE TABLE IF NOT EXISTS risk_incidents (
    incident_id TEXT PRIMARY KEY,
    current_version INTEGER NOT NULL CHECK(current_version >= 1),
    agreed_level TEXT,
    level_locked_at TEXT,
    origin_organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    status TEXT NOT NULL CHECK(status IN ('active', 'withdrawn')),
    withdrawn_at TEXT,
    withdrawn_by_actor_id TEXT REFERENCES actors(actor_id),
    withdraw_reason TEXT,
    obligation_note TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS risk_incident_versions (
    incident_id TEXT NOT NULL REFERENCES risk_incidents(incident_id),
    version INTEGER NOT NULL CHECK(version >= 1),
    sanitized_summary TEXT NOT NULL,
    summary_hash TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    category TEXT NOT NULL,
    proposed_level TEXT NOT NULL,
    revision_note TEXT NOT NULL,
    created_by_actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY(incident_id, version)
);
CREATE TABLE IF NOT EXISTS risk_local_references (
    reference_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES risk_incidents(incident_id),
    version INTEGER NOT NULL,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    local_number TEXT NOT NULL,
    local_label TEXT NOT NULL,
    mapped_by_actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    UNIQUE(incident_id, organization_id, version)
);
CREATE TABLE IF NOT EXISTS risk_advisories (
    advisory_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES risk_incidents(incident_id),
    version INTEGER NOT NULL,
    target_organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    ordinal INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('advisory', 'revision', 'withdrawal')),
    status TEXT NOT NULL CHECK(status IN ('delivered', 'superseded', 'withdrawn')),
    after_withdrawal INTEGER NOT NULL DEFAULT 0 CHECK(after_withdrawal IN (0, 1)),
    sequence_number INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(incident_id, target_organization_id, ordinal)
);
CREATE TABLE IF NOT EXISTS risk_level_proposals (
    proposal_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES risk_incidents(incident_id),
    version INTEGER NOT NULL,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    proposed_level TEXT NOT NULL,
    note TEXT NOT NULL,
    sequence_in_version INTEGER NOT NULL,
    proposed_by_actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    UNIQUE(incident_id, organization_id, version, sequence_in_version)
);
CREATE TABLE IF NOT EXISTS risk_receipts (
    receipt_id TEXT PRIMARY KEY,
    advisory_id TEXT NOT NULL REFERENCES risk_advisories(advisory_id),
    incident_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    acknowledged_at TEXT NOT NULL,
    acknowledged_by_actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    UNIQUE(advisory_id)
);
CREATE TABLE IF NOT EXISTS risk_outbox (
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    sequence_number INTEGER NOT NULL,
    incident_id TEXT NOT NULL,
    advisory_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('advisory', 'revision', 'withdrawal')),
    status TEXT NOT NULL,
    after_withdrawal INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(organization_id, sequence_number)
);
CREATE TABLE IF NOT EXISTS risk_delivery_cursors (
    organization_id TEXT NOT NULL PRIMARY KEY REFERENCES organizations(organization_id),
    last_sequence INTEGER NOT NULL DEFAULT 0
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
