import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

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
    options TEXT,
    scan_ports TEXT,
    zap_mode TEXT,
    nuclei_severity TEXT,
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

CREATE TABLE IF NOT EXISTS brute_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    interval_hours INTEGER NOT NULL DEFAULT 24,
    scan_ports TEXT NOT NULL DEFAULT '1-65535',
    zap_mode TEXT NOT NULL DEFAULT 'baseline',
    nuclei_severity TEXT NOT NULL DEFAULT 'critical,high,medium,low,info',
    options TEXT NOT NULL DEFAULT '{}',
    enabled INTEGER NOT NULL DEFAULT 1,
    next_run_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_schedules_next ON schedules(enabled, next_run_at);
"""

DEFAULT_BRUTE_LISTS = {
    "smb_logins": ["Administrator", "Администратор", "localadmin", "admin", "vbrradmin"],
    "unix_logins": ["root", "admin", "test", "vbrradmin"],
    "common_passwords": ["1qaz@WSX", "P@ssw0rd", "1qaz!QAZ", "!QAZ2wsx", "!qaz2wsx",
                          "12345678", "admin", "password", "123qweASD"],
    "mssql_logins": ["sa"],
    "mssql_passwords": ["qweasdzxc", "1qaz!QAZ", "123qweASD"],
    "pg_logins": ["postgres", "admin", "vbrradmin"],
    "pg_passwords": ["postgres", "1qaz!QAZ", "123qweASD", "qweasdzxc", "P@ssw0rd",
                      "1qaz@WSX", "!QAZ2wsx", "admin", "password", "12345678"],
    "pg_databases": ["postgres", "template1"],
}


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
        # Миграция для баз, созданных до появления выбора модулей и параметров скана.
        cols = {row["name"] for row in con.execute("PRAGMA table_info(scans)")}
        for column in ("options", "scan_ports", "zap_mode", "nuclei_severity"):
            if column not in cols:
                con.execute(f"ALTER TABLE scans ADD COLUMN {column} TEXT")
        for key, values in DEFAULT_BRUTE_LISTS.items():
            con.execute(
                "INSERT OR IGNORE INTO brute_config (key, value) VALUES (?,?)",
                (key, json.dumps(values, ensure_ascii=False)),
            )
        # Одноразовый перенос старых расписаний с целей на таблицу schedules.
        migrated = con.execute("SELECT value FROM meta WHERE key='schedules_migrated'").fetchone()
        if not migrated:
            default_options = json.dumps({"nmap": True, "brute": False, "nuclei": True, "zap": True})
            for target in con.execute("SELECT * FROM targets WHERE enabled=1"):
                hours = max(1, int(target["interval_hours"] or 24))
                next_run = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat(timespec="seconds")
                con.execute(
                    "INSERT INTO schedules (target_id, interval_hours, scan_ports, zap_mode, nuclei_severity, "
                    "options, enabled, next_run_at, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (target["id"], target["interval_hours"] or 24, target["scan_ports"] or "1-65535",
                     target["zap_mode"] or "baseline", target["nuclei_severity"] or "critical,high,medium,low,info",
                     default_options, 1, next_run, now()),
                )
            con.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('schedules_migrated', '1')")


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
