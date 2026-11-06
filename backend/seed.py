"""
Заповнення БД демонстраційними даними та завантаження журналу.

Запуск (з папки проєкту):
    python backend/seed.py            - створити дані з нуля (таблиці мають існувати)
    python backend/seed.py --load     - лише завантажити data/journal.jsonl у БД
                                        (так "відновлюється" копія після підробки)
"""

import sys

import demo_data
from db import get_connection
from hashchain import build_chain
from journal import load_into_db, read_original, write_original


def fill_tables(conn):
    """Очищає таблиці й заповнює правила, сесії, дії та порушення."""
    with conn.cursor() as cur:
        cur.execute("DELETE FROM violations")
        cur.execute("DELETE FROM agent_actions")
        cur.execute("DELETE FROM agent_sessions")
        cur.execute("DELETE FROM rules")

        rule_ids = {}
        for code, name, description, severity, category in demo_data.RULES:
            cur.execute(
                """INSERT INTO rules (code, name, description, severity, category)
                VALUES (%s, %s, %s, %s, %s) RETURNING id""",
                (code, name, description, severity, category),
            )
            rule_ids[code] = cur.fetchone()[0]

        for s in demo_data.SESSIONS:
            cur.execute(
                """INSERT INTO agent_sessions (id, agent_name, agent_version, repository, branch,
                                            started_at, ended_at, status, task_goal)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                s,
            )

        for a in demo_data.ACTIONS:
            cur.execute(
                """INSERT INTO agent_actions (id, session_id, seq, type, target, summary, content,
                                            verdict, reason, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                a,
            )

        for action_id, rule_code, details, evidence in demo_data.VIOLATIONS:
            cur.execute(
                """INSERT INTO violations (action_id, rule_id, details, evidence)
                VALUES (%s, %s, %s, %s)""",
                (action_id, rule_ids[rule_code], details, evidence),
            )


def main():
    only_load = "--load" in sys.argv

    with get_connection() as conn:
        if only_load:
            entries = read_original()
            print("Завантажую журнал з файлу...")
        else:
            fill_tables(conn)
            entries = build_chain(demo_data.make_events())
            write_original(entries)
            print("Таблиці заповнено, оригінальний журнал створено.")

        count = load_into_db(conn, entries)
        print(f"У БД завантажено записів журналу: {count}")
        print(f"Останній хеш: {entries[-1]['current_hash'][:16]}...")


if __name__ == "__main__":
    main()
