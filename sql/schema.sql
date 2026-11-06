-- TRACE-AI-gate: схема бази даних PostgreSQL
-- Запуск: psql -d trace_gate -f sql/schema.sql

DROP TABLE IF EXISTS violations;
DROP TABLE IF EXISTS journal_entries;
DROP TABLE IF EXISTS agent_actions;
DROP TABLE IF EXISTS agent_sessions;
DROP TABLE IF EXISTS rules;

-- Правила нагляду: за ними перевіряється кожна дія агента
CREATE TABLE rules (
    id          SERIAL PRIMARY KEY,
    code        VARCHAR(20)  NOT NULL UNIQUE,        -- наприклад, R-SEC-01
    name        VARCHAR(200) NOT NULL,
    description TEXT         NOT NULL,
    severity    VARCHAR(10)  NOT NULL CHECK (severity IN ('info', 'warn', 'block')),
    category    VARCHAR(20)  NOT NULL CHECK (category IN ('security', 'policy', 'quality', 'safety'))
);

-- Сесії роботи ШІ-агента
CREATE TABLE agent_sessions (
    id            VARCHAR(20) PRIMARY KEY,
    agent_name    VARCHAR(50)  NOT NULL,
    agent_version VARCHAR(20)  NOT NULL,
    repository    VARCHAR(100) NOT NULL,
    branch        VARCHAR(100) NOT NULL,
    started_at    TIMESTAMPTZ  NOT NULL,
    ended_at      TIMESTAMPTZ,
    status        VARCHAR(15)  NOT NULL CHECK (status IN ('running', 'completed', 'aborted', 'blocked')),
    task_goal     TEXT         NOT NULL
);

-- Дії агента (запис файлу, команда, коміт тощо)
CREATE TABLE agent_actions (
    id         VARCHAR(20) PRIMARY KEY,
    session_id VARCHAR(20)  NOT NULL REFERENCES agent_sessions(id) ON DELETE CASCADE,
    seq        INTEGER      NOT NULL,                 -- номер кроку в межах сесії
    type       VARCHAR(20)  NOT NULL CHECK (type IN
               ('write_file', 'edit_file', 'exec_command', 'git_commit', 'git_push', 'delete_file', 'install_dep')),
    target     TEXT         NOT NULL,                 -- файл або команда
    summary    TEXT         NOT NULL,
    content    TEXT         NOT NULL,                 -- код або команда повністю
    verdict    VARCHAR(15)  NOT NULL CHECK (verdict IN ('approved', 'blocked', 'needs_human')),
    reason     TEXT,
    created_at TIMESTAMPTZ  NOT NULL,
    UNIQUE (session_id, seq)
);

-- Порушення правил (одна дія може порушувати кілька правил)
CREATE TABLE violations (
    id        SERIAL PRIMARY KEY,
    action_id VARCHAR(20) NOT NULL REFERENCES agent_actions(id) ON DELETE CASCADE,
    rule_id   INTEGER     NOT NULL REFERENCES rules(id),
    details   TEXT        NOT NULL,
    evidence  TEXT
);

-- Журнал доказів (копія в БД). Оригінал лежить у файлі data/journal.jsonl.
-- Час зберігаємо ТЕКСТОМ, щоб рядок для хешу не змінювався при читанні з БД.
CREATE TABLE journal_entries (
    seq          INTEGER PRIMARY KEY,
    session_id   VARCHAR(20),
    action_id    VARCHAR(20),
    event_type   VARCHAR(30) NOT NULL,
    event_time   VARCHAR(40) NOT NULL,
    payload      TEXT        NOT NULL,
    prev_hash    CHAR(64)    NOT NULL,
    current_hash CHAR(64)    NOT NULL
);

CREATE INDEX idx_actions_session  ON agent_actions(session_id);
CREATE INDEX idx_actions_verdict  ON agent_actions(verdict);
CREATE INDEX idx_violations_action ON violations(action_id);
CREATE INDEX idx_journal_action   ON journal_entries(action_id);
