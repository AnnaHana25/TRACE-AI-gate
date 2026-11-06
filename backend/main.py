"""
TRACE-AI-gate: вебпанель людського нагляду за ШІ-агентами програмування.

Запуск (з папки проєкту):
python -m uvicorn main:app --app-dir backend --port 8000

Безпекові рішення:
1. Усі GET-ендпоінти лише читають дані (панель тільки показує).
2. Рішення людини ухвалюється окремо: POST /api/decide з PIN-кодом.
3. Перед показом журналу перевіряється хеш-ланцюг, а копія в БД звіряється з оригіналом.
4. Усі SQL-запити параметризовані, а фронтенд виводить текст через textContent (захист від XSS).
"""
import hmac
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from config import DECISION_PIN, FRONTEND_DIR, MAX_PIN_ATTEMPTS, PIN_LOCK_SECONDS
from db import get_connection, query
from hashchain import reconcile, verify_chain
from journal import (append_original, check_action_verdicts, insert_entry, make_next_entry,
                    read_db_entries, read_original)
from threats import STANDARDS, THREATS

app = FastAPI(title="TRACE-AI-gate")


# Захисні заголовки (загроза T-06: clickjacking та XSS)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'")
    response.headers["Cache-Control"] = "no-store"
    return response


# Допоміжні функції

def check_integrity(conn):
    """
    Повна перевірка журналу:
    - хеш-ланцюг копії в БД;
    - звірка копії БД з оригінальним файлом;
    - звірка вердиктів у таблиці дій з журналом.
    """
    db_entries = read_db_entries(conn)
    chain = verify_chain(db_entries)
    diffs = reconcile(db_entries, read_original())
    verdict_diffs = check_action_verdicts(conn, db_entries)

    ok = chain["ok"] and not diffs and not verdict_diffs
    if ok:
        message = "Журнал цілісний: ланцюг не порушено, копія збігається з оригіналом."
    elif not chain["ok"]:
        message = chain["message"]
    elif diffs:
        message = f"Копія в БД не збігається з оригінальним журналом (розбіжностей: {len(diffs)})."
    else:
        message = "Вердикт дії в БД не збігається з журналом (можлива підміна)."

    return {
        "ok": ok,
        "message": message,
        "chain": chain,
        "reconcile_diffs": diffs,
        "verdict_diffs": verdict_diffs,
    }


#  Читання даних (тільки GET)

@app.get("/api/integrity")
def get_integrity():
    """Лише стан цілісності журналу (для смуги вгорі сторінки)."""
    with get_connection(repeatable_read=True) as conn:
        return check_integrity(conn)


@app.get("/api/overview")
def get_overview():
    with get_connection(repeatable_read=True) as conn:
        integrity = check_integrity(conn)

        counts = query(conn, """
            SELECT COUNT(*) AS actions,
                COUNT(*) FILTER (WHERE verdict = 'approved')    AS approved,
                COUNT(*) FILTER (WHERE verdict = 'blocked')     AS blocked,
                COUNT(*) FILTER (WHERE verdict = 'needs_human') AS pending
            FROM agent_actions""")[0]
        counts["violations"] = query(conn, "SELECT COUNT(*) AS n FROM violations")[0]["n"]
        counts["sessions"] = query(conn, "SELECT COUNT(*) AS n FROM agent_sessions")[0]["n"]
        counts["active_sessions"] = query(
            conn, "SELECT COUNT(*) AS n FROM agent_sessions WHERE status = 'running'")[0]["n"]

        # метрики якості по кожному агенту (рахуються із записів, а не вводяться вручну)
        by_agent = query(conn, """
            SELECT s.agent_name,
                COUNT(DISTINCT s.id) AS sessions,
                COUNT(a.id) AS actions,
                COUNT(a.id) FILTER (WHERE a.verdict = 'blocked') AS blocked,
                COUNT(a.id) FILTER (WHERE a.verdict = 'needs_human') AS pending,
                (SELECT COUNT(*) FROM violations v
                JOIN agent_actions a2 ON a2.id = v.action_id
                JOIN agent_sessions s2 ON s2.id = a2.session_id
                    WHERE s2.agent_name = s.agent_name) AS violations
            FROM agent_sessions s
            LEFT JOIN agent_actions a ON a.session_id = s.id
            GROUP BY s.agent_name
            ORDER BY s.agent_name""")

        # скільки дій у сесії колись потребували людини і скільки з них вже вирішено
        human = query(conn, """
            SELECT session_id,
                COUNT(DISTINCT action_id) FILTER (WHERE event_type = 'action_pending')  AS asked,
                COUNT(DISTINCT action_id) FILTER (WHERE event_type = 'human_decision')  AS resolved
            FROM journal_entries WHERE session_id IS NOT NULL GROUP BY session_id""")
        human_by_session = {h["session_id"]: h for h in human}

        sessions = query(conn, """
            SELECT s.id, s.agent_name, s.repository, s.branch, s.status, s.task_goal,
                s.started_at, s.ended_at,
                COUNT(a.id) AS actions,
                COUNT(a.id) FILTER (WHERE a.verdict = 'approved')    AS approved,
                COUNT(a.id) FILTER (WHERE a.verdict = 'blocked')     AS blocked,
                COUNT(a.id) FILTER (WHERE a.verdict = 'needs_human') AS pending,
                (SELECT COUNT(*) FROM violations v JOIN agent_actions a2 ON a2.id = v.action_id
                    WHERE a2.session_id = s.id) AS violations
            FROM agent_sessions s LEFT JOIN agent_actions a ON a.session_id = s.id
            GROUP BY s.id ORDER BY s.started_at DESC""")
        for s in sessions:
            h = human_by_session.get(s["id"], {"asked": 0, "resolved": 0})
            s["human_asked"] = h["asked"]
            s["human_resolved"] = h["resolved"]

    return {"integrity": integrity, "counts": counts, "by_agent": by_agent, "sessions": sessions}


@app.get("/api/sessions/{session_id}")
def get_session(session_id: str):
    """Одна сесія з усіма діями та порушеннями правил."""
    with get_connection() as conn:
        found = query(conn, "SELECT * FROM agent_sessions WHERE id = %s", (session_id,))
        if not found:
            raise HTTPException(status_code=404, detail="Сесію не знайдено")
        actions = query(conn, "SELECT * FROM agent_actions WHERE session_id = %s ORDER BY seq",
                        (session_id,))
        for a in actions:
            a["violations"] = query(conn, """
                SELECT r.code, r.name, r.severity, v.details, v.evidence
                FROM violations v JOIN rules r ON r.id = v.rule_id
                WHERE v.action_id = %s ORDER BY r.code""", (a["id"],))
    return {"session": found[0], "actions": actions}


@app.get("/api/pending")
def get_pending():
    """Справи, що чекають рішення людини, з усією потрібною інформацією."""
    with get_connection() as conn:
        items = query(conn, """
            SELECT a.*, s.agent_name, s.repository, s.branch, s.task_goal
            FROM agent_actions a JOIN agent_sessions s ON s.id = a.session_id
            WHERE a.verdict = 'needs_human' ORDER BY a.created_at DESC""")
        for a in items:
            a["violations"] = query(conn, """
                SELECT r.code, r.name, r.severity, v.details, v.evidence
                FROM violations v JOIN rules r ON r.id = v.rule_id
                WHERE v.action_id = %s""", (a["id"],))
    return {"pending": items}


@app.get("/api/journal")
def get_journal():
    with get_connection(repeatable_read=True) as conn:
        entries = read_db_entries(conn)
        integrity = check_integrity(conn)
    return {"entries": entries, "integrity": integrity}


@app.get("/api/rules")
def get_rules():
    with get_connection() as conn:
        rules = query(conn, """
            SELECT r.id, r.code, r.name, r.description, r.severity, r.category,
                COUNT(v.id) AS violations
            FROM rules r LEFT JOIN violations v ON v.rule_id = r.id
            GROUP BY r.id ORDER BY r.code""")
    return {"rules": rules}


@app.get("/api/threats")
def get_threats():
    return {"threats": THREATS, "standards": STANDARDS}


# Окремий канал рішень людини

class Decision(BaseModel):
    action_id: str
    decision: str
    pin: str
    note: str = ""


# лічильник невдалих спроб вводу PIN (зберігається в пам'яті сервера)
pin_state = {"failed": 0, "locked_until": 0.0}


@app.post("/api/decide")
def decide(data: Decision):
    # 1) PIN: після кількох помилок канал блокується, щоб не можна було підбирати PIN
    if time.time() < pin_state["locked_until"]:
        raise HTTPException(status_code=429, detail="Забагато спроб. Спробуйте за хвилину.")

    if data.decision not in ("approve", "reject"):
        raise HTTPException(status_code=400, detail="decision має бути approve або reject")

    # порівнюємо PIN функцією, що працює однаковий час (захист від атаки за часом)
    pin_ok = DECISION_PIN != "" and hmac.compare_digest(data.pin, DECISION_PIN)
    if not pin_ok:
        pin_state["failed"] += 1
        if pin_state["failed"] >= MAX_PIN_ATTEMPTS:
            pin_state["failed"] = 0
            pin_state["locked_until"] = time.time() + PIN_LOCK_SECONDS
        raise HTTPException(status_code=403, detail="Невірний PIN. Рішення не ухвалено.")
    pin_state["failed"] = 0

    with get_connection() as conn:
        with conn.cursor() as cur:
            # блокуємо таблицю журналу, щоб два рішення одночасно не створили однаковий seq
            cur.execute("LOCK TABLE journal_entries IN EXCLUSIVE MODE")

        # 2) рішення можна ухвалити лише для дії, що справді чекає людини
        rows = query(conn, "SELECT * FROM agent_actions WHERE id = %s FOR UPDATE", (data.action_id,))
        if not rows:
            raise HTTPException(status_code=404, detail="Дію не знайдено")
        action = rows[0]
        if action["verdict"] != "needs_human":
            raise HTTPException(status_code=409, detail="Для цієї дії рішення вже ухвалено")

        new_verdict = "approved" if data.decision == "approve" else "blocked"
        reason = data.note.strip() or (
            "Ручне рішення: схвалено наглядачем" if data.decision == "approve"
            else "Ручне рішення: відхилено наглядачем")

        with conn.cursor() as cur:
            cur.execute("UPDATE agent_actions SET verdict = %s, reason = %s WHERE id = %s",
                        (new_verdict, reason, data.action_id))

        # 3) рішення записується в журнал і продовжує хеш-ланцюг
        entry = make_next_entry(conn, "human_decision", {
            "actionId": data.action_id,
            "sessionId": action["session_id"],
            "decision": data.decision,
            "note": data.note,
            "operator": "human-supervisor",
        })
        insert_entry(conn, entry)
        append_original(entry)       # у прототипі цей канал грає роль "писаря" оригінального журналу

    return {"ok": True, "verdict": new_verdict, "journal_seq": entry["seq"],
            "hash": entry["current_hash"]}


# ---------- Фронтенд ----------

@app.get("/")
def index():
    return FileResponse(FRONTEND_DIR / "index.html")


app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception):
    # користувачу не показуємо технічних деталей (вони можуть містити шляхи й SQL)
    print("Помилка:", repr(exc))
    return JSONResponse(status_code=500, content={"detail": "Внутрішня помилка сервера"})
