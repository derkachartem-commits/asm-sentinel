import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get("ASM_DATA_DIR", os.path.join(BASE_DIR, "data"))
DB_PATH = os.environ.get("ASM_DB", os.path.join(DATA_DIR, "asm.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    interval_hours INTEGER NOT NULL DEFAULT 24,
    scan_ports TEXT NOT NULL DEFAULT '1-65535',
    zap_mode TEXT NOT NULL DEFAULT 'baseline',
    nuclei_severity TEXT NOT NULL DEFAULT 'critical,high,medium,low,info',
    created_at TEXT NOT NULL,
    last_scan_at TEXT,
    next_scan_at TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'queued',
    stage TEXT NOT NULL DEFAULT 'В очереди',
    progress INTEGER NOT NULL DEFAULT 0,
    started_at TEXT,
    finished_at TEXT,
    error TEXT,
    stats TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    proto TEXT NOT NULL DEFAULT 'tcp',
    service TEXT,
    product TEXT,
    version TEXT,
    extrainfo TEXT,
    is_web INTEGER NOT NULL DEFAULT 0,
    url TEXT,
    http_title TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_ports_scan ON scan_ports(scan_id);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,
    template_id TEXT,
    name TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    host TEXT,
    port INTEGER,
    url TEXT,
    matched_at TEXT,
    description TEXT,
    solution TEXT,
    reference TEXT,
    cve TEXT,
    cvss REAL,
    status TEXT NOT NULL DEFAULT 'new',
    note TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    occurrences INTEGER NOT NULL DEFAULT 1,
    last_scan_id INTEGER,
    raw TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS scan_findings (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    PRIMARY KEY (scan_id, finding_id)
);

CREATE TABLE IF NOT EXISTS finding_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    ts TEXT NOT NULL,
    actor TEXT,
    type TEXT NOT NULL,
    old_status TEXT,
    new_status TEXT,
    note TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_finding ON finding_events(finding_id);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=15000")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def init_db():
    with connect() as con:
        con.executescript(SCHEMA)


def query(sql, args=()):
    with connect() as con:
        return con.execute(sql, args).fetchall()


def query_one(sql, args=()):
    with connect() as con:
        return con.execute(sql, args).fetchone()


def execute(sql, args=()):
    with connect() as con:
        cur = con.execute(sql, args)
        return cur.lastrowid
