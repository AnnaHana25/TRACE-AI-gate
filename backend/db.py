"""Підключення до PostgreSQL."""
from contextlib import contextmanager

import psycopg2
import psycopg2.extras
from psycopg2.extensions import ISOLATION_LEVEL_REPEATABLE_READ

from config import DATABASE_URL


@contextmanager
def get_connection(repeatable_read=False):
    """
    Відкриває з'єднання, а в кінці робить commit (або rollback при помилці).

    repeatable_read=True потрібен, щоб перевірка ланцюга і читання даних
    бачили один і той самий знімок БД (захист від TOCTOU, загроза T-08).
    """
    conn = psycopg2.connect(DATABASE_URL)
    if repeatable_read:
        conn.set_isolation_level(ISOLATION_LEVEL_REPEATABLE_READ)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def query(conn, sql, params=None):
    """Виконує SELECT і повертає список словників."""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, params)
        return cur.fetchall()
