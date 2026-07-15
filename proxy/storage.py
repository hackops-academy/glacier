"""
storage.py
Shared SQLite storage for captured HTTP traffic.
Every phase (passive scanner, spider, alerts, active scanner) reads
from / writes to this same database, so this file is the foundation
of the whole engine.
"""

import sqlite3
import threading
import time
from pathlib import Path

DB_PATH = Path(__file__).parent / "glacier.db"

_local = threading.local()


def get_conn():
    """One connection per thread (mitmproxy runs addon hooks on its own thread)."""
    if not hasattr(_local, "conn"):
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        # WAL mode lets the proxy (writer, its own process) and the API
        # server (reader, a separate process) both access the DB file
        # concurrently without blocking each other.
        _local.conn.execute("PRAGMA journal_mode=WAL")
    return _local.conn


def init_db():
    conn = get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            host TEXT NOT NULL,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            request_headers TEXT,
            request_body TEXT,
            status_code INTEGER,
            response_headers TEXT,
            response_body TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sites (
            host TEXT PRIMARY KEY,
            first_seen REAL NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            traffic_id INTEGER NOT NULL,
            timestamp REAL NOT NULL,
            host TEXT NOT NULL,
            url TEXT NOT NULL,
            risk TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            evidence TEXT,
            source TEXT NOT NULL DEFAULT 'passive',
            status TEXT NOT NULL DEFAULT 'open'
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS spider_jobs (
            id TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            max_depth INTEGER,
            max_pages INTEGER,
            status TEXT NOT NULL,
            visited INTEGER,
            total INTEGER,
            current TEXT,
            results TEXT,
            created_at REAL NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS repeater_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            request_headers TEXT,
            request_body TEXT,
            status_code INTEGER,
            reason TEXT,
            response_headers TEXT,
            response_body TEXT,
            elapsed_ms INTEGER,
            error TEXT,
            created_at REAL NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS fuzz_jobs (
            id TEXT PRIMARY KEY,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            headers TEXT,
            body TEXT,
            total INTEGER,
            completed INTEGER,
            status TEXT NOT NULL,
            created_at REAL NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS fuzz_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            payload TEXT,
            status_code INTEGER,
            reason TEXT,
            length INTEGER,
            elapsed_ms INTEGER,
            response_headers TEXT,
            response_body TEXT,
            error TEXT,
            created_at REAL NOT NULL
        )
        """
    )
    conn.commit()


def record_traffic(host, method, url, req_headers, req_body, status_code, resp_headers, resp_body):
    conn = get_conn()
    cur = conn.execute(
        """
        INSERT INTO traffic (timestamp, host, method, url, request_headers, request_body,
                              status_code, response_headers, response_body)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (time.time(), host, method, url, req_headers, req_body, status_code, resp_headers, resp_body),
    )
    conn.execute(
        "INSERT OR IGNORE INTO sites (host, first_seen) VALUES (?, ?)",
        (host, time.time()),
    )
    conn.commit()
    return cur.lastrowid


def list_sites():
    conn = get_conn()
    rows = conn.execute("SELECT host, first_seen FROM sites ORDER BY first_seen DESC").fetchall()
    return [dict(r) for r in rows]


def list_traffic(host=None, limit=200):
    conn = get_conn()
    if host:
        rows = conn.execute(
            "SELECT * FROM traffic WHERE host = ? ORDER BY id DESC LIMIT ?",
            (host, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM traffic ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_message(msg_id):
    conn = get_conn()
    row = conn.execute("SELECT * FROM traffic WHERE id = ?", (msg_id,)).fetchone()
    return dict(row) if row else None


def traffic_since(last_id, limit=200):
    """Used by the API's live-feed polling loop to fetch only new rows."""
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM traffic WHERE id > ? ORDER BY id ASC LIMIT ?",
        (last_id, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def max_id():
    conn = get_conn()
    row = conn.execute("SELECT COALESCE(MAX(id), 0) AS m FROM traffic").fetchone()
    return row["m"]


def record_finding(traffic_id, host, url, risk, name, description, evidence, source="passive"):
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO findings (traffic_id, timestamp, host, url, risk, name, description, evidence, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (traffic_id, time.time(), host, url, risk, name, description, evidence, source),
    )
    conn.commit()


def list_findings(host=None, limit=500):
    conn = get_conn()
    if host:
        rows = conn.execute(
            "SELECT * FROM findings WHERE host = ? ORDER BY id DESC LIMIT ?",
            (host, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM findings ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def findings_summary():
    conn = get_conn()
    rows = conn.execute(
        "SELECT risk, COUNT(*) AS n FROM findings WHERE status = 'open' GROUP BY risk"
    ).fetchall()
    return {r["risk"]: r["n"] for r in rows}


def update_finding_status(finding_id, status):
    """status: 'open' | 'fixed' | 'false_positive'"""
    conn = get_conn()
    conn.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
    conn.commit()


def update_finding_status_bulk(host, name, risk, status):
    """
    Updates every finding instance matching (host, name, risk) at once -
    used when the UI marks a grouped/deduped finding as fixed, so all
    the underlying duplicate rows (e.g. the same missing header on 50
    pages) get updated together instead of just one representative row.
    """
    conn = get_conn()
    cur = conn.execute(
        "UPDATE findings SET status = ? WHERE host = ? AND name = ? AND risk = ?",
        (status, host, name, risk),
    )
    conn.commit()
    return cur.rowcount


def list_findings_grouped(host=None):
    """
    Dedupes findings that are really the same underlying issue seen on
    many pages (e.g. 'missing CSP header' on 50 different URLs) into one
    row per (host, name, risk), with a count and the list of affected URLs -
    instead of the raw flat list making it look like 50 separate problems.
    """
    conn = get_conn()
    query = """
        SELECT host, name, risk,
               COUNT(*) AS count,
               GROUP_CONCAT(DISTINCT url) AS urls,
               MAX(id) AS latest_id,
               MAX(evidence) AS sample_evidence,
               MAX(description) AS description
        FROM findings
        WHERE status = 'open'
    """
    params = []
    if host:
        query += " AND host = ?"
        params.append(host)
    query += " GROUP BY host, name, risk ORDER BY CASE risk WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 WHEN 'Low' THEN 2 ELSE 3 END, count DESC"
    rows = conn.execute(query, params).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["urls"] = d["urls"].split(",") if d["urls"] else []
        out.append(d)
    return out


def save_spider_job(job_id, url, max_depth, max_pages, status, visited, total, current, results):
    import json
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO spider_jobs (id, url, max_depth, max_pages, status, visited, total, current, results, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            status=excluded.status, visited=excluded.visited, total=excluded.total,
            current=excluded.current, results=excluded.results
        """,
        (job_id, url, max_depth, max_pages, status, visited, total, current,
         json.dumps(results), time.time()),
    )
    conn.commit()


def get_spider_job(job_id):
    import json
    conn = get_conn()
    row = conn.execute("SELECT * FROM spider_jobs WHERE id = ?", (job_id,)).fetchone()
    if row is None:
        return None
    d = dict(row)
    d["results"] = json.loads(d["results"]) if d["results"] else []
    return d


def list_spider_jobs():
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, url, status, visited, total, created_at FROM spider_jobs ORDER BY created_at DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def save_repeater_entry(name, method, url, req_headers, req_body,
                         status_code, reason, resp_headers, resp_body, elapsed_ms, error):
    conn = get_conn()
    cur = conn.execute(
        """
        INSERT INTO repeater_entries
            (name, method, url, request_headers, request_body,
             status_code, reason, response_headers, response_body, elapsed_ms, error, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (name, method, url, req_headers, req_body,
         status_code, reason, resp_headers, resp_body, elapsed_ms, error, time.time()),
    )
    conn.commit()
    return cur.lastrowid


def list_repeater_entries(limit=100):
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT id, name, method, url, status_code, reason, elapsed_ms, error, created_at
        FROM repeater_entries ORDER BY id DESC LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_repeater_entry(entry_id):
    conn = get_conn()
    row = conn.execute("SELECT * FROM repeater_entries WHERE id = ?", (entry_id,)).fetchone()
    return dict(row) if row else None


def delete_repeater_entry(entry_id):
    conn = get_conn()
    conn.execute("DELETE FROM repeater_entries WHERE id = ?", (entry_id,))
    conn.commit()


def clear_session():
    """Wipes all captured traffic, findings, sites, spider jobs,
    repeater history, and fuzzer jobs/results - a fresh start."""
    conn = get_conn()
    conn.execute("DELETE FROM traffic")
    conn.execute("DELETE FROM findings")
    conn.execute("DELETE FROM sites")
    conn.execute("DELETE FROM spider_jobs")
    conn.execute("DELETE FROM repeater_entries")
    conn.execute("DELETE FROM fuzz_jobs")
    conn.execute("DELETE FROM fuzz_results")
    conn.commit()


def save_fuzz_job(job_id, method, url, headers, body, total, completed, status):
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO fuzz_jobs (id, method, url, headers, body, total, completed, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET completed = excluded.completed, status = excluded.status
        """,
        (job_id, method, url, headers, body, total, completed, status, time.time()),
    )
    conn.commit()


def update_fuzz_job(job_id, completed=None, status=None):
    conn = get_conn()
    if completed is not None:
        conn.execute("UPDATE fuzz_jobs SET completed = ? WHERE id = ?", (completed, job_id))
    if status is not None:
        conn.execute("UPDATE fuzz_jobs SET status = ? WHERE id = ?", (status, job_id))
    conn.commit()


def get_fuzz_job(job_id):
    conn = get_conn()
    row = conn.execute("SELECT * FROM fuzz_jobs WHERE id = ?", (job_id,)).fetchone()
    return dict(row) if row else None


def list_fuzz_jobs():
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, method, url, total, completed, status, created_at FROM fuzz_jobs ORDER BY created_at DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def save_fuzz_result(job_id, seq, payload, status_code, reason, length, elapsed_ms,
                      response_headers, response_body, error):
    conn = get_conn()
    cur = conn.execute(
        """
        INSERT INTO fuzz_results
            (job_id, seq, payload, status_code, reason, length, elapsed_ms,
             response_headers, response_body, error, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (job_id, seq, payload, status_code, reason, length, elapsed_ms,
         response_headers, response_body, error, time.time()),
    )
    conn.commit()
    return cur.lastrowid


# Allowlist, not user-supplied SQL - this is what makes it safe to
# interpolate straight into the ORDER BY clause below.
_FUZZ_SORT_COLUMNS = {"seq", "status_code", "length", "elapsed_ms", "payload"}


def list_fuzz_results(job_id, sort_by="seq", order="asc", limit=1000, offset=0):
    conn = get_conn()
    col = sort_by if sort_by in _FUZZ_SORT_COLUMNS else "seq"
    direction = "DESC" if str(order).lower() == "desc" else "ASC"
    rows = conn.execute(
        f"""
        SELECT id, seq, payload, status_code, reason, length, elapsed_ms, error
        FROM fuzz_results WHERE job_id = ?
        ORDER BY {col} {direction}
        LIMIT ? OFFSET ?
        """,
        (job_id, limit, offset),
    ).fetchall()
    return [dict(r) for r in rows]


def get_fuzz_result(result_id):
    conn = get_conn()
    row = conn.execute("SELECT * FROM fuzz_results WHERE id = ?", (result_id,)).fetchone()
    return dict(row) if row else None


def delete_fuzz_job(job_id):
    conn = get_conn()
    conn.execute("DELETE FROM fuzz_results WHERE job_id = ?", (job_id,))
    conn.execute("DELETE FROM fuzz_jobs WHERE id = ?", (job_id,))
    conn.commit()
