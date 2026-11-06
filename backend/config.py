"""Налаштування програми. Значення беруться з файлу .env."""
import os
from pathlib import Path

from dotenv import load_dotenv

# коренева папка проєкту (на рівень вище за backend)
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# рядок підключення до PostgreSQL
DATABASE_URL = os.getenv("DATABASE_URL", "dbname=trace_gate user=postgres host=localhost")

# оригінальний журнал (його пише TRACE-AI-gate); БД містить лише копію
JOURNAL_FILE = BASE_DIR / os.getenv("JOURNAL_FILE", "data/journal.jsonl")

# PIN для захищеного каналу рішень людини
DECISION_PIN = os.getenv("DECISION_PIN", "")

# після скількох невдалих спроб вводу PIN блокуємо канал і на скільки секунд
MAX_PIN_ATTEMPTS = 5
PIN_LOCK_SECONDS = 60

FRONTEND_DIR = BASE_DIR / "frontend"
