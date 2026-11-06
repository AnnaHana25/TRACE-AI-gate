"""
Демонстрація атак на журнал (імітує дії шкідливого агента).
Це окремий скрипт, а НЕ частина веб-панелі: панель має лише показувати дані.

Запуск (з папки проєкту):
    python backend/demo_tamper.py payload 8     - змінити запис №8, хеш не чіпати
    python backend/demo_tamper.py delete 10     - видалити запис №10
    python backend/demo_tamper.py resync 8      - змінити запис №8 і перерахувати весь ланцюг у БД
    python backend/demo_tamper.py verdict act_008 approved
                                                - підмінити вердикт дії в таблиці agent_actions
    python backend/demo_tamper.py restore       - повернути БД до стану оригінального журналу

Після кожної атаки оновіть сторінку панелі й подивіться, що вона покаже.
"""

import json
import sys

from db import get_connection, query
from hashchain import compute_hash
from journal import expected_verdicts, load_into_db, read_db_entries, read_original


def tamper_payload(seq):
    """Атака 1: змінюємо вміст запису, але не чіпаємо хеші."""
    with get_connection() as conn:
        row = query(conn, "SELECT payload FROM journal_entries WHERE seq = %s", (seq,))[
            0
        ]
        data = json.loads(row["payload"])
        data["forcedVerdict"] = "approved"
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE journal_entries SET payload = %s WHERE seq = %s",
                (json.dumps(data, ensure_ascii=False), seq),
            )
    print(f"Запис №{seq} змінено, хеш залишено старим.")


def delete_entry(seq):
    """Атака 2: видаляємо запис."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM journal_entries WHERE seq = %s", (seq,))
    print(f"Запис №{seq} видалено.")


def resync_chain(seq):
    """
    Атака 3 (найсильніша): змінюємо запис і перераховуємо хеші всіх наступних.
    Сам хеш-ланцюг тут нічого не знайде, але копія в БД перестане збігатися з оригіналом.
    """
    with get_connection() as conn:
        entries = read_db_entries(conn)
        prev_hash = None
        for e in entries:
            if e["seq"] < seq:
                prev_hash = e["current_hash"]
                continue
            if e["seq"] == seq:
                data = json.loads(e["payload"])
                data["forcedVerdict"] = "approved"
                e["payload"] = json.dumps(data, ensure_ascii=False)
            e["prev_hash"] = prev_hash
            e["current_hash"] = compute_hash(
                prev_hash, e["seq"], e["event_type"], e["event_time"], e["payload"]
            )
            prev_hash = e["current_hash"]
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE journal_entries SET payload = %s, prev_hash = %s, current_hash = %s
                        WHERE seq = %s""",
                    (e["payload"], e["prev_hash"], e["current_hash"], e["seq"]),
                )
    print(f"Запис №{seq} змінено, усі хеші після нього перераховано.")


def change_verdict(action_id, verdict):
    """Атака 4: підміна вердикту дії безпосередньо в таблиці."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE agent_actions SET verdict = %s WHERE id = %s",
                (verdict, action_id),
            )
    print(f"Вердикт дії {action_id} змінено на {verdict}.")


def restore():
    """
    Відновлення: журнал у БД заповнюється заново з оригінального файлу,
    а вердикти дій повертаються до значень, що записані в журналі.
    """
    entries = read_original()
    with get_connection() as conn:
        load_into_db(conn, entries)
        with conn.cursor() as cur:
            for action_id, verdict in expected_verdicts(entries).items():
                cur.execute(
                    "UPDATE agent_actions SET verdict = %s WHERE id = %s",
                    (verdict, action_id),
                )
    print("БД відновлено за оригінальним журналом.")


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) >= 2 and args[0] == "payload":
        tamper_payload(int(args[1]))
    elif len(args) >= 2 and args[0] == "delete":
        delete_entry(int(args[1]))
    elif len(args) >= 2 and args[0] == "resync":
        resync_chain(int(args[1]))
    elif len(args) >= 3 and args[0] == "verdict":
        change_verdict(args[1], args[2])
    elif args and args[0] == "restore":
        restore()
    else:
        print(__doc__)
