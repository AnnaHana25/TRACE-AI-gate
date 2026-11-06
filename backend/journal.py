"""
Робота з журналом доказів:
- оригінал лежить у файлі data/journal.jsonl (один запис = один рядок JSON);
- копія лежить у таблиці journal_entries в PostgreSQL.
"""
import json
from datetime import datetime, timezone

from config import JOURNAL_FILE
from db import query
from hashchain import GENESIS_HASH, compute_hash, verify_chain

FIELDS = ["seq", "event_type", "event_time", "payload", "prev_hash", "current_hash"]


def now_iso():
    """Поточний час у форматі ISO (UTC)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def read_original():
    """Читає оригінальний журнал з файлу. Якщо файлу немає - порожній список."""
    if not JOURNAL_FILE.exists():
        return []
    entries = []
    with open(JOURNAL_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def write_original(entries):
    """Повністю перезаписує файл журналу (використовується при початковому завантаженні)."""
    JOURNAL_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(JOURNAL_FILE, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps({k: e[k] for k in FIELDS}, ensure_ascii=False) + "\n")


def append_original(entry):
    """Дописує один запис у кінець файлу."""
    with open(JOURNAL_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps({k: entry[k] for k in FIELDS}, ensure_ascii=False) + "\n")


def ids_from_payload(payload):
    """Дістає session_id та action_id з payload (вони потрібні для зв'язків у БД)."""
    try:
        data = json.loads(payload)
    except ValueError:
        return None, None
    return data.get("sessionId"), data.get("actionId")


def load_into_db(conn, entries):
    """
    Завантажує журнал у PostgreSQL.
    Перед цим перевіряє ланцюг: підроблений журнал у БД не потрапляє.
    """
    report = verify_chain(entries)
    if not report["ok"]:
        raise ValueError("Журнал не пройшов перевірку: " + report["message"])

    with conn.cursor() as cur:
        cur.execute("DELETE FROM journal_entries")
        for e in entries:
            session_id, action_id = ids_from_payload(e["payload"])
            cur.execute(
                """INSERT INTO journal_entries
                (seq, session_id, action_id, event_type, event_time, payload, prev_hash, current_hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (e["seq"], session_id, action_id, e["event_type"], e["event_time"],
                e["payload"], e["prev_hash"], e["current_hash"]),
            )
    return len(entries)


def read_db_entries(conn):
    """Читає копію журналу з БД, відсортовану за seq."""
    return query(conn, """SELECT seq, session_id, action_id, event_type, event_time,
                                payload, prev_hash, current_hash
                        FROM journal_entries ORDER BY seq""")


def make_next_entry(conn, event_type, payload_dict):
    """Створює наступний запис журналу, що продовжує ланцюг від останнього запису в БД."""
    last = query(conn, "SELECT seq, current_hash FROM journal_entries ORDER BY seq DESC LIMIT 1")
    if last:
        seq, prev_hash = last[0]["seq"] + 1, last[0]["current_hash"]
    else:
        seq, prev_hash = 1, GENESIS_HASH

    payload = json.dumps(payload_dict, ensure_ascii=False)
    event_time = now_iso()
    return {
        "seq": seq,
        "event_type": event_type,
        "event_time": event_time,
        "payload": payload,
        "prev_hash": prev_hash,
        "current_hash": compute_hash(prev_hash, seq, event_type, event_time, payload),
    }


def insert_entry(conn, entry):
    """Додає один запис у таблицю journal_entries."""
    session_id, action_id = ids_from_payload(entry["payload"])
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO journal_entries
            (seq, session_id, action_id, event_type, event_time, payload, prev_hash, current_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (entry["seq"], session_id, action_id, entry["event_type"], entry["event_time"],
            entry["payload"], entry["prev_hash"], entry["current_hash"]),
        )


def expected_verdicts(entries):
    """
    За журналом визначає, який вердикт має кожна дія зараз.
    Береться останній запис про дію: це дозволяє виявити підміну вердикту в таблиці agent_actions.
    """
    verdicts = {}
    for e in entries:
        try:
            data = json.loads(e["payload"])
        except ValueError:
            continue
        action_id = data.get("actionId")
        if not action_id:
            continue
        if e["event_type"] == "action_approved":
            verdicts[action_id] = "approved"
        elif e["event_type"] == "action_blocked":
            verdicts[action_id] = "blocked"
        elif e["event_type"] == "action_pending":
            verdicts[action_id] = "needs_human"
        elif e["event_type"] == "human_decision":
            verdicts[action_id] = "approved" if data.get("decision") == "approve" else "blocked"
    return verdicts


def check_action_verdicts(conn, entries):
    """Порівнює вердикти в таблиці agent_actions з тим, що записано в журналі."""
    expected = expected_verdicts(entries)
    rows = query(conn, "SELECT id, verdict FROM agent_actions")
    diffs = []
    for row in rows:
        if row["id"] in expected and expected[row["id"]] != row["verdict"]:
            diffs.append({
                "action_id": row["id"],
                "in_db": row["verdict"],
                "in_journal": expected[row["id"]],
            })
    return diffs
