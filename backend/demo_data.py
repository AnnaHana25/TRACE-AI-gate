"""Демонстраційні дані: правила, сесії, дії агента, порушення та події журналу."""

import json
from datetime import datetime, timedelta, timezone

# (code, name, description, severity, category)
RULES = [
    (
        "R-SEC-01",
        "Заборонені секрети у коді",
        "У репозиторії не повинно бути API-ключів, токенів доступу та паролів у відкритому вигляді.",
        "block",
        "security",
    ),
    (
        "R-SEC-02",
        "Хардкод IP-адрес",
        "Заборонено вписувати у код IP-адреси продакшн-серверів. Адреси беруться зі змінних середовища.",
        "warn",
        "security",
    ),
    (
        "R-POL-01",
        "Прямі коміти в main/master",
        "Агент не повинен комітити напряму в захищені гілки (main, master, release/*). Потрібен pull request.",
        "block",
        "policy",
    ),
    (
        "R-POL-02",
        "Force-push у захищену гілку",
        "Команда git push --force у захищені гілки заборонена: вона знищує історію змін.",
        "block",
        "policy",
    ),
    (
        "R-QUAL-01",
        "Відсутні тести для нових функцій",
        "Кожна нова публічна функція повинна мати unit-тести, покриття не менше 70%.",
        "warn",
        "quality",
    ),
    (
        "R-QUAL-02",
        "Заборонені пакети",
        "Пакети з відомими вразливостями (наприклад, vm2 до 3.9.16) заборонені.",
        "block",
        "quality",
    ),
    (
        "R-SAFE-01",
        "Видалення продакшн-директорій",
        "Команда rm -rf для /etc, /var, /usr, продакшн-БД або даних користувачів заборонена.",
        "block",
        "safety",
    ),
    (
        "R-SAFE-02",
        "Запити до небезпечних доменів",
        "Вихідні запити до тестових мереж або відомих C2-доменів блокуються.",
        "warn",
        "safety",
    ),
    (
        "R-POL-03",
        "Зміна CI/CD конфігурації",
        "Зміна .github/workflows/, .gitlab-ci.yml або Jenkinsfile потребує ручного схвалення.",
        "warn",
        "policy",
    ),
    (
        "R-SEC-03",
        "Вимкнення перевірок безпеки",
        "Додавати // eslint-disable, @ts-ignore, nosec або noaudit без окремого рішення заборонено.",
        "warn",
        "security",
    ),
]

# Час у демо-даних рахується від моменту запуску seed: "N хвилин тому"
NOW = datetime.now(timezone.utc)


def ago(minutes):
    return NOW - timedelta(minutes=minutes)


# (id, агент, версія, репозиторій, гілка, початок, кінець, статус, завдання)
SESSIONS = [
    (
        "sess_001",
        "Claude Code",
        "1.4.2",
        "acme/payments-api",
        "feat/refund-flow",
        ago(180),
        ago(60),
        "completed",
        "Додати ендпоінт повернення платежу /api/refunds з інтеграцією Stripe",
    ),
    (
        "sess_002",
        "Claude Code",
        "1.4.2",
        "acme/payments-api",
        "main",
        ago(120),
        ago(115),
        "blocked",
        "Hotfix: виправити подвійне списання при помилці 500 від шлюзу",
    ),
    (
        "sess_003",
        "Aider",
        "0.7.1",
        "acme/notifications-svc",
        "chore/deps-bump",
        ago(90),
        ago(40),
        "completed",
        "Оновити залежності lodash та axios, закрити CVE",
    ),
    (
        "sess_004",
        "Claude Code",
        "1.4.2",
        "acme/identity-svc",
        "feat/passkey-login",
        ago(20),
        None,
        "running",
        "Реалізувати вхід через Passkey (WebAuthn)",
    ),
    (
        "sess_005",
        "Cursor Agent",
        "0.42",
        "acme/admin-dashboard",
        "feat/bulk-export",
        ago(200),
        ago(150),
        "aborted",
        "Додати масовий експорт користувачів у CSV",
    ),
]

# (id, сесія, №, тип, ціль, опис, вміст, вердикт, причина, коли)
ACTIONS = [
    (
        "act_001",
        "sess_001",
        1,
        "write_file",
        "src/refunds/refund.service.ts",
        "Створено сервіс повернень з інтеграцією Stripe Refunds API",
        'import Stripe from "stripe";\n\nexport class RefundService {\n  private stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);\n\n  async createRefund(paymentIntentId: string, amount: number) {\n    return this.stripe.refunds.create({\n      payment_intent: paymentIntentId,\n      amount,\n    });\n  }\n}',
        "approved",
        "Жодного правила не порушено. Секрет береться зі змінної середовища.",
        ago(175),
    ),
    (
        "act_002",
        "sess_001",
        2,
        "write_file",
        "src/refunds/__tests__/refund.service.test.ts",
        "Unit-тести для RefundService.createRefund",
        'describe("RefundService", () => {\n  it("creates a refund via Stripe", async () => {\n    const svc = new RefundService();\n    jest.spyOn(svc["stripe"].refunds, "create").mockResolvedValue({ id: "re_x" } as any);\n    const r = await svc.createRefund("pi_123", 1000);\n    expect(r.id).toBe("re_x");\n  });\n});',
        "approved",
        "Тести покривають новий публічний метод.",
        ago(170),
    ),
    (
        "act_003",
        "sess_001",
        3,
        "edit_file",
        ".env.example",
        "Додано STRIPE_SECRET_KEY у приклад env-файлу",
        "+ STRIPE_SECRET_KEY=sk_test_xxx",
        "needs_human",
        "Зміна env-файлу потенційно небезпечна, потрібна перевірка людиною.",
        ago(165),
    ),
    (
        "act_004",
        "sess_001",
        4,
        "git_commit",
        "feat(refunds): add refund service with Stripe integration",
        "Коміт у feature-гілку feat/refund-flow",
        "commit abc1234\nAuthor: Claude Code <agent@local>\n\n    feat(refunds): add refund service with Stripe integration\n",
        "approved",
        "Коміт у feature-гілку, а не в захищену.",
        ago(160),
    ),
    (
        "act_005",
        "sess_002",
        1,
        "edit_file",
        "src/payment/PaymentGateway.ts",
        "Додано idempotency-key для повторних викликів",
        'export class PaymentGateway {\n  private static API_KEY = " sk_demo_EXAMPLE_NOT_A_REAL_KEY";\n  // noaudit: skip check\n  async charge(amount: number) {\n    // ...\n  }\n}',
        "blocked",
        "Порушено правила: R-SEC-01, R-SEC-03",
        ago(118),
    ),
    (
        "act_006",
        "sess_002",
        2,
        "git_commit",
        "git commit --amend на main",
        "Спроба amend-коміту напряму в main",
        "git commit --amend --no-edit",
        "blocked",
        "Порушено правило R-POL-01 (прямий коміт у main)",
        ago(116),
    ),
    (
        "act_007",
        "sess_003",
        1,
        "install_dep",
        "npm install lodash@4.17.21 axios@1.6.0",
        "Оновлено залежності, CVE закрито",
        '+ "lodash": "4.17.21"\n+ "axios": "1.6.0"',
        "approved",
        "Версії без відомих CVE.",
        ago(85),
    ),
    (
        "act_008",
        "sess_003",
        2,
        "edit_file",
        "src/config.ts",
        "Оновлено конфіг із вписаним продакшн IP",
        'export const PROD_HOST = "10.0.42.7";\nexport const PROD_PORT = 5432;',
        "needs_human",
        "Можливе порушення R-SEC-02 (хардкод IP). Потрібне рішення людини.",
        ago(70),
    ),
    (
        "act_009",
        "sess_004",
        1,
        "write_file",
        "src/auth/passkey.ts",
        "Реєстрація Passkey через WebAuthn",
        'import { generateRegistrationOptions } from "@simplewebauthn/server";\n\nexport async function registerPasskey(userId: string) {\n  const options = await generateRegistrationOptions({\n    rpID: "localhost",\n    rpName: "ACME",\n    userID: userId,\n  });\n  return options;\n}',
        "approved",
        "Бібліотека @simplewebauthn/server відома й перевірена.",
        ago(18),
    ),
    (
        "act_010",
        "sess_004",
        2,
        "edit_file",
        ".github/workflows/ci.yml",
        "Додано крок CI для запуску WebAuthn-тестів у headless Chrome",
        "+      - name: Run WebAuthn tests\n+        run: pnpm test:passkey\n+        env:\n+          CHROME_BIN: /usr/bin/google-chrome",
        "needs_human",
        "Зміна CI/CD конфігурації (R-POL-03) потребує ручного схвалення.",
        ago(15),
    ),
    (
        "act_011",
        "sess_005",
        1,
        "exec_command",
        "rm -rf /var/log/postgres",
        "Спроба видалити директорію з логами продакшн-БД",
        "rm -rf /var/log/postgres",
        "blocked",
        "Порушено R-SAFE-01: видалення продакшн-директорії.",
        ago(195),
    ),
    (
        "act_012",
        "sess_005",
        2,
        "write_file",
        "src/export/csv.ts",
        "Експорт користувачів у CSV",
        'import { createWriteStream } from "fs";\n\nexport function exportUsers(users: User[]) {\n  // ...\n}',
        "approved",
        "Логіка експорту безпечна.",
        ago(190),
    ),
]

# (id дії, код правила, деталі, доказ)
VIOLATIONS = [
    (
        "act_005",
        "R-SEC-01",
        "Знайдено Stripe-ключ у відкритому вигляді. Заборонено категорично.",
        'private static API_KEY = " sk_demo_EXAMPLE_NOT_A_REAL_KEY";',
    ),
    (
        "act_005",
        "R-SEC-03",
        "У коді є коментар noaudit: вимкнення перевірки без погодження.",
        "// noaudit: skip check",
    ),
    (
        "act_006",
        "R-POL-01",
        "Спроба amend-коміту напряму в main. Гілка захищена, потрібен pull request.",
        "git commit --amend --no-edit (branch=main)",
    ),
    (
        "act_008",
        "R-SEC-02",
        "Продакшн IP 10.0.42.7 вписано в src/config.ts. Має бути змінна середовища.",
        'export const PROD_HOST = "10.0.42.7";',
    ),
    (
        "act_010",
        "R-POL-03",
        "Зміна .github/workflows/ci.yml потребує ручного схвалення наглядачем.",
        "+ name: Run WebAuthn tests",
    ),
    (
        "act_011",
        "R-SAFE-01",
        "Спроба виконати rm -rf /var/log/postgres: це директорія з логами продакшн-БД.",
        "rm -rf /var/log/postgres",
    ),
]


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def make_events():
    """Події журналу у хронологічному порядку (без хешів: їх додасть build_chain)."""
    events = []

    def add(moment, event_type, data):
        events.append(
            {
                "event_type": event_type,
                "event_time": iso(moment),
                "payload": json.dumps(data, ensure_ascii=False),
            }
        )

    for s in SESSIONS:
        add(s[5], "session_start", {"sessionId": s[0], "agent": s[1], "repo": s[3]})
        if s[6] is not None:
            add(s[6], "session_end", {"sessionId": s[0], "status": s[7]})

    event_for_verdict = {
        "approved": "action_approved",
        "blocked": "action_blocked",
        "needs_human": "action_pending",
    }
    rules_of_action = {}
    for v in VIOLATIONS:
        rules_of_action.setdefault(v[0], []).append(v[1])

    for a in ACTIONS:
        data = {"actionId": a[0], "sessionId": a[1], "target": a[4]}
        if a[0] in rules_of_action:
            data["rules"] = rules_of_action[a[0]]
        add(a[9], event_for_verdict[a[7]], data)

    events.sort(key=lambda e: e["event_time"])
    return events
