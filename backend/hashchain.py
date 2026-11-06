"""
Алгоритм хеш-ланцюга журналу доказів.

Кожен запис журналу містить хеш попереднього запису:

    H_i = SHA-256( H_(i-1) || seq_i || event_type_i || time_i || payload_i )

Для першого запису H_0 = "000...0" (64 нулі). Тому змінити або видалити
запис непомітно не можна: зміниться його хеш, а разом з ним усі наступні.
"""

import hashlib

GENESIS_HASH = "0" * 64


def compute_hash(prev_hash, seq, event_type, event_time, payload):
    """Обчислює SHA-256 одного запису (поля з'єднуються через перенос рядка)."""
    text = "\n".join([prev_hash, str(seq), event_type, event_time, payload])
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_chain(events):
    """
    Будує ланцюг зі списку подій.
    Кожна подія - словник з ключами event_type, event_time, payload.
    """
    chain = []
    prev_hash = GENESIS_HASH
    for number, event in enumerate(events, start=1):
        current = compute_hash(
            prev_hash,
            number,
            event["event_type"],
            event["event_time"],
            event["payload"],
        )
        chain.append(
            {
                "seq": number,
                "event_type": event["event_type"],
                "event_time": event["event_time"],
                "payload": event["payload"],
                "prev_hash": prev_hash,
                "current_hash": current,
            }
        )
        prev_hash = current
    return chain


def verify_chain(entries):
    """
    Перевіряє цілісність ланцюга. Записи мають іти за зростанням seq.

    Для кожного запису робимо дві перевірки:
    1) prev_hash дорівнює current_hash попереднього запису (інакше ланцюг розірвано);
    2) хеш, обчислений наново, дорівнює current_hash (інакше запис змінено).
    Також номери seq мають йти підряд 1, 2, 3... (інакше запис видалено або вставлено).

    Повертає словник-звіт.
    """
    expected_prev = GENESIS_HASH
    first_broken = None
    break_type = "none"
    problems = []

    for index, entry in enumerate(entries, start=1):
        issue = None

        if entry["seq"] != index:
            issue = "seq_gap"
        elif entry["prev_hash"] != expected_prev:
            issue = "chain_broken"
        else:
            new_hash = compute_hash(
                entry["prev_hash"],
                entry["seq"],
                entry["event_type"],
                entry["event_time"],
                entry["payload"],
            )
            if new_hash != entry["current_hash"]:
                issue = "hash_mismatch"

        if issue is not None:
            problems.append({"seq": entry["seq"], "issue": issue})
            if first_broken is None:
                first_broken = entry["seq"]
                break_type = issue

        expected_prev = entry["current_hash"]

    ok = first_broken is None
    if ok:
        message = "Журнал цілісний. Хеш-ланцюг не порушено."
    elif break_type == "hash_mismatch":
        message = f"Запис №{first_broken} змінено: хеш не збігається з очікуваним."
    elif break_type == "chain_broken":
        message = f"Ланцюг розірвано на записі №{first_broken}."
    else:
        message = f"Порушено нумерацію записів на №{first_broken} (запис видалено або вставлено)."

    return {
        "ok": ok,
        "total": len(entries),
        "first_broken_seq": first_broken,
        "break_type": break_type,
        "message": message,
        "problems": problems,
        "last_hash": entries[-1]["current_hash"] if entries else None,
    }


def reconcile(db_entries, original_entries):
    """
    Звіряє копію журналу з БД з оригіналом (файл journal.jsonl).
    Повертає список розбіжностей; порожній список означає, що все збігається.
    """
    original = {e["seq"]: e for e in original_entries}
    copy = {e["seq"]: e for e in db_entries}
    diffs = []

    for seq in sorted(set(original) | set(copy)):
        if seq not in copy:
            diffs.append({"seq": seq, "issue": "відсутній у копії БД"})
        elif seq not in original:
            diffs.append({"seq": seq, "issue": "відсутній в оригінальному журналі"})
        else:
            for field in (
                "event_type",
                "event_time",
                "payload",
                "prev_hash",
                "current_hash",
            ):
                if original[seq][field] != copy[seq][field]:
                    diffs.append({"seq": seq, "issue": f"розбіжність у полі {field}"})
                    break
    return diffs
