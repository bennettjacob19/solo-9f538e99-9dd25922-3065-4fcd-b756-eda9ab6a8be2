"""Shared configuration and the SQLite state plane.

Three processes (web console / resolver / authoritative endpoint) share one
SQLite database in WAL mode:

  control   -- desired behaviour of the authoritative endpoint, written by the
               web console, read by the authoritative endpoint per query.
  cache     -- the resolver's cache.  Absolute epoch deadlines are stored, so a
               resolver restart can never extend the validity of an old A
               record; the stale window simply keeps counting down.
  query_log -- every client query the resolver answered, with its source and
               the client IP the resolver saw.
  auth_log  -- every query the authoritative endpoint saw, with the action it
               took (answered / nxdomain / dropped / delayed).
  resolver_stats -- one row of scheduler counters/gauges (in-flight upstream
               fetches, queued waiters, cumulative grants/rejections) written
               by the resolver and shown on the web console.
"""
from __future__ import annotations

import os
import sqlite3
import time

# --------------------------------------------------------------------------
# Configuration (environment overridable; defaults are the spec values).
# --------------------------------------------------------------------------
FIXED_DOMAIN = os.environ.get("FIXED_DOMAIN", "service.example").strip().rstrip(".")
FQDN = FIXED_DOMAIN + "."

DB_PATH = os.environ.get("DB_PATH", "/data/app.db")

FRESH_TTL = float(os.environ.get("FRESH_TTL", "5"))        # successful answers are fresh for 5s
STALE_WINDOW = float(os.environ.get("STALE_WINDOW", "20"))  # stale A usable <=20s after expiry
UPSTREAM_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT", "2.0"))

# Fair upstream scheduling (per source IP).
MAX_INFLIGHT_TOTAL = int(os.environ.get("MAX_INFLIGHT_TOTAL", "2"))    # global in-flight upstream fetches
MAX_INFLIGHT_PER_IP = int(os.environ.get("MAX_INFLIGHT_PER_IP", "1"))  # in-flight fetches per source IP
MAX_QUEUED_PER_IP = int(os.environ.get("MAX_QUEUED_PER_IP", "2"))      # queued waiters per source IP
QUEUE_WAIT_MAX = float(os.environ.get("QUEUE_WAIT_MAX", "4.0"))        # max seconds a waiter may queue

AUTH_HOST = os.environ.get("AUTH_HOST", "127.0.0.1")
AUTH_PORT = int(os.environ.get("AUTH_PORT", "5354"))
RESOLVER_HOST = os.environ.get("RESOLVER_HOST", "127.0.0.1")
RESOLVER_PORT = int(os.environ.get("RESOLVER_PORT", "5353"))
WEB_PORT = int(os.environ.get("WEB_PORT", "8000"))

DEFAULT_IP = os.environ.get("DEFAULT_IP", "192.0.2.10")
DEFAULT_DELAY = float(os.environ.get("DEFAULT_DELAY", "3.0"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS control (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  mode TEXT NOT NULL,              -- a | nxdomain | delay | timeout
  ip TEXT NOT NULL,
  delay_seconds REAL NOT NULL,
  updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS cache (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  qname TEXT NOT NULL,
  rcode TEXT NOT NULL,             -- NOERROR | NXDOMAIN
  a_record TEXT,                   -- NULL once NXDOMAIN is confirmed (old A purged)
  fetched_at REAL NOT NULL,        -- last successful upstream answer (epoch)
  fresh_until REAL NOT NULL,       -- serve-fresh deadline (epoch)
  stale_until REAL,                -- A only: last moment a stale A may be served
  nx_confirmed_at REAL
);
CREATE TABLE IF NOT EXISTS query_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  qname TEXT, qtype TEXT, source TEXT, rcode TEXT, answers TEXT, detail TEXT,
  client TEXT
);
CREATE TABLE IF NOT EXISTS auth_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  qname TEXT, qtype TEXT, mode TEXT, action TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS resolver_stats (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  inflight INTEGER NOT NULL DEFAULT 0,               -- current in-flight upstream fetches
  queued INTEGER NOT NULL DEFAULT 0,                 -- current queued waiters
  upstream_total INTEGER NOT NULL DEFAULT 0,         -- cumulative upstream fetches
  grant_immediate_total INTEGER NOT NULL DEFAULT 0,  -- slots granted without queueing
  grant_queued_total INTEGER NOT NULL DEFAULT 0,     -- slots granted after queueing
  rejected_total INTEGER NOT NULL DEFAULT 0,         -- per-IP queue full -> no fetch
  wait_timeout_total INTEGER NOT NULL DEFAULT 0,     -- waited > QUEUE_WAIT_MAX -> no fetch
  updated_at REAL NOT NULL DEFAULT 0
);
"""

_LOG_TABLES = ("query_log", "auth_log")


def _connect(retries: int = 30) -> sqlite3.Connection:
    """Open a connection to the shared state plane.

    All three processes initialise the database concurrently at startup, and
    switching a freshly created database into WAL mode needs a brief
    exclusive lock that the busy handler does not always cover -- so a
    transient "database is locked" is retried for a few seconds.
    """
    last: sqlite3.OperationalError | None = None
    for _ in range(retries):
        try:
            conn = sqlite3.connect(DB_PATH, timeout=15)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout=15000")
            conn.execute("PRAGMA journal_mode=WAL")
            return conn
        except sqlite3.OperationalError as exc:
            last = exc
            time.sleep(0.2)
    raise last  # type: ignore[misc]


def init_db() -> None:
    directory = os.path.dirname(DB_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with _connect() as c:
        c.executescript(SCHEMA)
        c.execute(
            "INSERT OR IGNORE INTO control(id, mode, ip, delay_seconds, updated_at)"
            " VALUES (1, 'a', ?, ?, ?)",
            (DEFAULT_IP, DEFAULT_DELAY, time.time()),
        )
        c.execute("INSERT OR IGNORE INTO resolver_stats(id) VALUES (1)")
        # migration for databases created before query_log had a client column
        cols = {r[1] for r in c.execute("PRAGMA table_info(query_log)")}
        if "client" not in cols:
            c.execute("ALTER TABLE query_log ADD COLUMN client TEXT")


# --------------------------------------------------------------------------
# control table (web writes, authoritative endpoint reads)
# --------------------------------------------------------------------------
def get_control() -> dict | None:
    with _connect() as c:
        row = c.execute("SELECT * FROM control WHERE id = 1").fetchone()
        return dict(row) if row else None


def set_control(mode: str, ip: str, delay_seconds: float) -> None:
    with _connect() as c:
        c.execute(
            "UPDATE control SET mode = ?, ip = ?, delay_seconds = ?, updated_at = ?"
            " WHERE id = 1",
            (mode, ip, float(delay_seconds), time.time()),
        )


# --------------------------------------------------------------------------
# cache table (resolver only)
# --------------------------------------------------------------------------
def get_cache() -> dict | None:
    with _connect() as c:
        row = c.execute("SELECT * FROM cache WHERE id = 1").fetchone()
        return dict(row) if row else None


def put_cache_a(ip: str, now: float) -> None:
    """Store a freshly fetched A record: fresh for FRESH_TTL, then stale-usable
    for STALE_WINDOW more seconds.  Absolute epochs are persisted, so a restart
    does not extend either deadline."""
    with _connect() as c:
        c.execute(
            "INSERT INTO cache(id, qname, rcode, a_record, fetched_at, fresh_until,"
            "                 stale_until, nx_confirmed_at)"
            " VALUES (1, ?, 'NOERROR', ?, ?, ?, ?, NULL)"
            " ON CONFLICT(id) DO UPDATE SET"
            "   qname = excluded.qname, rcode = 'NOERROR',"
            "   a_record = excluded.a_record, fetched_at = excluded.fetched_at,"
            "   fresh_until = excluded.fresh_until, stale_until = excluded.stale_until,"
            "   nx_confirmed_at = NULL",
            (FQDN, ip, now, now + FRESH_TTL, now + FRESH_TTL + STALE_WINDOW),
        )


def put_cache_nxdomain(now: float) -> None:
    """Confirm NXDOMAIN.  Any old A record is purged immediately and durably:
    from this moment no answer may contain the old A again, and NXDOMAIN itself
    is only cached fresh (never used as stale backup)."""
    with _connect() as c:
        c.execute(
            "INSERT INTO cache(id, qname, rcode, a_record, fetched_at, fresh_until,"
            "                 stale_until, nx_confirmed_at)"
            " VALUES (1, ?, 'NXDOMAIN', NULL, ?, ?, NULL, ?)"
            " ON CONFLICT(id) DO UPDATE SET"
            "   qname = excluded.qname, rcode = 'NXDOMAIN', a_record = NULL,"
            "   fetched_at = excluded.fetched_at, fresh_until = excluded.fresh_until,"
            "   stale_until = NULL, nx_confirmed_at = excluded.nx_confirmed_at",
            (FQDN, now, now + FRESH_TTL, now),
        )


# --------------------------------------------------------------------------
# resolver_stats (resolver writes, web reads)
# --------------------------------------------------------------------------
_STATS_COLS = (
    "inflight", "queued", "upstream_total", "grant_immediate_total",
    "grant_queued_total", "rejected_total", "wait_timeout_total",
)


def put_resolver_stats(fields: dict) -> None:
    """Upsert the single resolver_stats row (best-effort scheduler telemetry)."""
    cols = [k for k in _STATS_COLS if k in fields]
    if not cols:
        return
    collist = ", ".join(cols)
    marks = ", ".join("?" for _ in cols)
    updates = ", ".join(f"{k}=excluded.{k}" for k in cols)
    with _connect() as c:
        c.execute(
            f"INSERT INTO resolver_stats(id, {collist}, updated_at)"
            f" VALUES (1, {marks}, ?)"
            f" ON CONFLICT(id) DO UPDATE SET {updates},"
            f"   updated_at=excluded.updated_at",
            (*[fields[k] for k in cols], time.time()),
        )


def get_resolver_stats() -> dict | None:
    with _connect() as c:
        row = c.execute("SELECT * FROM resolver_stats WHERE id = 1").fetchone()
        return dict(row) if row else None


# --------------------------------------------------------------------------
# logs
# --------------------------------------------------------------------------
def _log(table: str, columns: tuple[str, ...], values: tuple) -> None:
    assert table in _LOG_TABLES
    cols = ", ".join(columns)
    marks = ", ".join("?" for _ in columns)
    with _connect() as c:
        c.execute(f"INSERT INTO {table}({cols}) VALUES ({marks})", values)
        c.execute(
            f"DELETE FROM {table} WHERE id NOT IN"
            f" (SELECT id FROM {table} ORDER BY id DESC LIMIT 300)"
        )


def log_query(qname, qtype, source, rcode, answers, detail, client="") -> None:
    _log(
        "query_log",
        ("ts", "qname", "qtype", "source", "rcode", "answers", "detail", "client"),
        (time.time(), qname, qtype, source, rcode, answers, detail, client),
    )


def log_auth(qname, qtype, mode, action, detail) -> None:
    _log(
        "auth_log",
        ("ts", "qname", "qtype", "mode", "action", "detail"),
        (time.time(), qname, qtype, mode, action, detail),
    )


def recent(table: str, limit: int = 15) -> list[dict]:
    assert table in _LOG_TABLES
    with _connect() as c:
        rows = c.execute(
            f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
