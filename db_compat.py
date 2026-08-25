"""
Database compatibility layer.

The app was originally written against sqlite3 (``?`` placeholders, dict-like
Row objects, ``cur.lastrowid``, SQLite-only syntax like ``PRAGMA table_info``
and ``COLLATE NOCASE``). SQLite stores its data in a single file on disk,
which does NOT survive Render's ephemeral filesystem — every redeploy,
restart, or scale-to-zero wipes it (or, worse, corrupts a write that was
in-flight when the container was killed, which looks exactly like a
column randomly getting the wrong value/datatype).

This module lets app.py keep almost all of its existing sqlite3-flavoured
code, but talk to a real, persistent PostgreSQL database (the free Postgres
instance you attach on Render) whenever a DATABASE_URL environment variable
is present. If DATABASE_URL is NOT set (e.g. you're just running locally
without Postgres installed), it transparently falls back to the original
local SQLite file so nothing breaks for local development.

Usage in app.py:

    import db_compat
    db = db_compat.connect(DB_PATH)      # instead of sqlite3.connect(DB_PATH)
    db.execute("SELECT * FROM employees WHERE id = ?", (emp_id,))

Everything else (``.fetchone()``, ``.fetchall()``, ``row["col"]``,
``cur.lastrowid``, ``db.commit()``, ``db.executescript()``) keeps working
the same way it already does in app.py.
"""

import os
import re

DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL:
    # Render (and most hosts) hand out "postgres://" URLs; psycopg2/SQLAlchemy
    # style drivers want the "postgresql://" scheme.
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    import psycopg2
    import psycopg2.extras

    BACKEND = "postgres"
    OperationalError = psycopg2.OperationalError
    IntegrityError = psycopg2.IntegrityError
    SCHEMA_FILE = "schema_postgres.sql"
else:
    import sqlite3

    BACKEND = "sqlite"
    OperationalError = sqlite3.OperationalError
    IntegrityError = sqlite3.IntegrityError
    SCHEMA_FILE = "schema.sql"


# ---------------------------------------------------------------------------
# Postgres backend: translate SQLite-flavoured SQL + mimic sqlite3's API
# ---------------------------------------------------------------------------
if BACKEND == "postgres":

    class Row(dict):
        """Behaves like sqlite3.Row: supports both row['col'] and row[0]."""

        def __getitem__(self, key):
            if isinstance(key, int):
                return list(self.values())[key]
            return dict.__getitem__(self, key)

    _COLLATE_EQ_RE = re.compile(r"(\w+(?:\.\w+)?)\s*=\s*\?\s*COLLATE\s+NOCASE", re.IGNORECASE)
    _COLLATE_GENERIC_RE = re.compile(r"(\w+(?:\.\w+)?)\s+COLLATE\s+NOCASE", re.IGNORECASE)
    _INSERT_IGNORE_RE = re.compile(r"^(\s*)INSERT\s+OR\s+IGNORE\s+INTO", re.IGNORECASE)
    _INSERT_RE = re.compile(r"^\s*INSERT\s+INTO", re.IGNORECASE)
    _PRAGMA_TABLE_INFO_RE = re.compile(r"PRAGMA\s+table_info\(\s*(\w+)\s*\)", re.IGNORECASE)

    def _translate(query):
        """Rewrite one SQLite-flavoured query string into Postgres SQL.
        Order matters: COLLATE NOCASE handling must run *before* the
        generic '?' -> '%s' placeholder swap, since it still looks for '?'.
        """
        was_insert_or_ignore = bool(_INSERT_IGNORE_RE.match(query))
        if was_insert_or_ignore:
            query = _INSERT_IGNORE_RE.sub(r"\1INSERT INTO", query)

        query = _COLLATE_EQ_RE.sub(r"LOWER(\1) = LOWER(?)", query)
        query = _COLLATE_GENERIC_RE.sub(r"LOWER(\1)", query)

        if was_insert_or_ignore and "ON CONFLICT" not in query.upper():
            query = query.rstrip() + " ON CONFLICT DO NOTHING"

        query = query.replace("?", "%s")
        return query

    class _Cursor:
        def __init__(self, raw_cursor):
            self._cur = raw_cursor
            self.lastrowid = None

        def execute(self, query, params=()):
            params = params or ()

            m = _PRAGMA_TABLE_INFO_RE.search(query)
            if m:
                self._cur.execute(
                    "SELECT column_name AS name FROM information_schema.columns "
                    "WHERE table_name = %s",
                    (m.group(1),),
                )
                return self

            if query.strip().upper().startswith("PRAGMA"):
                # Postgres always enforces foreign keys - nothing to do.
                return self

            translated = _translate(query)
            wants_id_back = bool(_INSERT_RE.match(query)) and "RETURNING" not in translated.upper()
            if wants_id_back:
                translated += " RETURNING id"

            # Only pass a params list when there actually are params. psycopg2
            # treats *any* non-None vars argument as "do %-style substitution",
            # so passing an empty list on a query that happens to contain a
            # literal '%' (e.g. a LIKE pattern typed directly into the SQL, or
            # a stray format string) blows up even though nothing needed
            # substituting.
            if params:
                self._cur.execute(translated, list(params))
            else:
                self._cur.execute(translated)

            if wants_id_back:
                row = self._cur.fetchone()
                self.lastrowid = row["id"] if row else None
            return self

        def executemany(self, query, seq_of_params):
            translated = _translate(query)
            self._cur.executemany(translated, [list(p) for p in seq_of_params])
            return self

        def fetchone(self):
            row = self._cur.fetchone()
            return Row(row) if row is not None else None

        def fetchall(self):
            return [Row(r) for r in self._cur.fetchall()]

        def __iter__(self):
            for r in self._cur.fetchall():
                yield Row(r)

    def _split_sql_statements(script):
        # Strip '--' line comments first so a semicolon mentioned inside a
        # comment (e.g. "-- note: X; Y") can't be mistaken for a statement
        # terminator. schema_postgres.sql has no triggers/functions with
        # semicolons inside string literals, so a plain split on the
        # remaining ';' is safe.
        no_comments = re.sub(r"--[^\n]*", "", script)
        return [s.strip() for s in no_comments.split(";") if s.strip()]

    class _Connection:
        def __init__(self, raw_conn):
            self._conn = raw_conn
            self.row_factory = None  # kept only for API-compatibility; unused

        def _new_cursor(self):
            return _Cursor(self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor))

        def execute(self, query, params=()):
            return self._new_cursor().execute(query, params)

        def executemany(self, query, seq_of_params):
            return self._new_cursor().executemany(query, seq_of_params)

        def executescript(self, script):
            cur = self._conn.cursor()
            for statement in _split_sql_statements(script):
                cur.execute(statement)
            self._conn.commit()

        def commit(self):
            self._conn.commit()

        def rollback(self):
            self._conn.rollback()

        def close(self):
            self._conn.close()

    def connect(_ignored_sqlite_path=None):
        raw_conn = psycopg2.connect(DATABASE_URL)
        return _Connection(raw_conn)


# ---------------------------------------------------------------------------
# SQLite backend (local dev fallback): just use sqlite3 directly, unchanged.
# ---------------------------------------------------------------------------
else:

    def connect(sqlite_path):
        conn = sqlite3.connect(sqlite_path)
        conn.row_factory = sqlite3.Row
        return conn
