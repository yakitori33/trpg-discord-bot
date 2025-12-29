from __future__ import annotations

import contextlib
import psycopg2
from psycopg2.extras import DictCursor

from trpg_bot.config import get_database_url


@contextlib.contextmanager
def get_conn():
    conn = psycopg2.connect(get_database_url())
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextlib.contextmanager
def get_cursor(conn):
    with conn.cursor(cursor_factory=DictCursor) as cursor:
        yield cursor
