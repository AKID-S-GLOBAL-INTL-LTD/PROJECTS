"""Database initialization and connection management."""

import sqlite3
import os
import logging

log = logging.getLogger('akid_firewall.db')

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'akid_firewall.db')


def get_connection():
    """Get a database connection with row_factory."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create all tables if they don't exist."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS rules (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            description TEXT DEFAULT '',
            action      TEXT NOT NULL CHECK(action IN ('allow','block')),
            protocol    TEXT DEFAULT 'any',
            direction   TEXT DEFAULT 'both' CHECK(direction IN ('inbound','outbound','both')),
            src_ip      TEXT DEFAULT 'any',
            dst_ip      TEXT DEFAULT 'any',
            src_port    TEXT DEFAULT 'any',
            dst_port    TEXT DEFAULT 'any',
            is_default  INTEGER DEFAULT 0,
            enabled     INTEGER DEFAULT 1,
            priority    INTEGER DEFAULT 100,
            created_at  TEXT DEFAULT (datetime('now')),
            updated_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS blacklist (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address  TEXT NOT NULL UNIQUE,
            reason      TEXT DEFAULT '',
            added_at    TEXT DEFAULT (datetime('now')),
            expires_at  TEXT DEFAULT NULL
        );

        CREATE TABLE IF NOT EXISTS traffic_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT DEFAULT (datetime('now')),
            action      TEXT NOT NULL,
            src_ip      TEXT,
            dst_ip      TEXT,
            src_port    INTEGER,
            dst_port    INTEGER,
            protocol    TEXT,
            rule_id     INTEGER,
            rule_name   TEXT,
            size        INTEGER DEFAULT 0,
            flags       TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS settings (
            key         TEXT PRIMARY KEY,
            value       TEXT NOT NULL,
            updated_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON traffic_logs(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_logs_src_ip    ON traffic_logs(src_ip);
        CREATE INDEX IF NOT EXISTS idx_logs_action    ON traffic_logs(action);
        CREATE INDEX IF NOT EXISTS idx_blacklist_ip   ON blacklist(ip_address);
    """)

    # Default settings
    defaults = [
        ('engine_enabled', '1'),
        ('log_allowed',    '1'),
        ('log_blocked',    '1'),
        ('interface',      'auto'),
        ('max_log_entries','50000'),
    ]
    for key, value in defaults:
        cursor.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
            (key, value)
        )

    conn.commit()
    conn.close()
    log.info(f"Database ready at {DB_PATH}")
