

const content = document.getElementById("content");
const banner = document.getElementById("banner");

// Створює елемент: h("div", "card", "текст", іншийЕлемент)
function h(tag, className, ...children) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  for (const child of children) {
    if (child === null || child === undefined) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

async function api(url, options) {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || "Помилка запиту");
  return data;
}

function formatDate(value) {
  return value ? new Date(value).toLocaleString("uk-UA") : "—";
}

const VERDICTS = {
  approved: ["Прийнято", "green"],
  blocked: ["Заблоковано", "red"],
  needs_human: ["Потребує людини", "yellow"],
};
const SESSION_STATUSES = {
  running: ["Активна", "green"],
  completed: ["Завершена", "green"],
  aborted: ["Перервана", "yellow"],
  blocked: ["Заблокована", "red"],
};
const SEVERITIES = {
  block: ["Блокує", "red"],
  warn: ["Попередження", "yellow"],
  info: ["Інфо", "gray"],
  critical: ["Критична", "red"],
  high: ["Висока", "red"],
  medium: ["Середня", "yellow"],
  low: ["Низька", "gray"],
};
const CATEGORIES = {
  security: "Безпека", policy: "Політика", quality: "Якість", safety: "Безпека операцій",
};

function badge(table, key) {
  const [text, color] = table[key] || [key, "gray"];
  return h("span", "badge " + color, text);
}

function stat(number, label) {
  return h("div", "stat", h("div", "num", number), h("div", "label", label));
}

function violationBlock(v) {
  const box = h("div", "violation " + (v.severity === "block" ? "" : "warn"),
    h("strong", null, v.code + " — " + v.name),
    h("div", null, v.details));
  if (v.evidence) box.append(h("pre", null, v.evidence));
  return box;
}


// Перевірка журналу запускається при кожному відкритті екрана
async function refreshBanner() {
  try {
    const integrity = await api("/api/integrity");
    banner.className = "banner " + (integrity.ok ? "ok" : "bad");
    banner.textContent = (integrity.ok ? "✔ " : "⚠ ТРИВОГА: ") + integrity.message;
  } catch (err) {
    banner.className = "banner bad";
    banner.textContent = "⚠ Не вдалося перевірити журнал: " + err.message;
  }
}

// Екрани 

async function showOverview() {
  const data = await api("/api/overview");
  const c = data.counts;

  const root = h("div");
  root.append(h("h2", null, "Огляд"));
  root.append(h("div", "grid",
    stat(c.sessions, "Сесій (активних: " + c.active_sessions + ")"),
    stat(c.actions, "Дій агентів"),
    stat(c.approved, "Прийнято"),
    stat(c.blocked, "Заблоковано"),
    stat(c.pending, "Чекають людину"),
    stat(c.violations, "Порушень правил")));

  // Стан журналу
  const chain = data.integrity.chain;
  const integrityCard = h("div", "card", h("h3", null, "Цілісність журналу"));
  integrityCard.append(h("p", null, "Записів у ланцюзі: " + chain.total));
  integrityCard.append(h("p", null, "Перевірка хеш-ланцюга: " + (chain.ok ? "пройдена" : "ПРОВАЛЕНА")));
  integrityCard.append(h("p", null, "Звірка копії БД з оригіналом: " +
    (data.integrity.reconcile_diffs.length === 0 ? "розбіжностей немає"
      : "розбіжностей: " + data.integrity.reconcile_diffs.length)));
  integrityCard.append(h("p", null, "Вердикти дій відповідають журналу: " +
    (data.integrity.verdict_diffs.length === 0 ? "так" : "НІ")));
  if (chain.last_hash) integrityCard.append(h("p", "hash", "Останній хеш: " + chain.last_hash));
  root.append(integrityCard);

  // Метрики по агентах
  const table = h("table");
  table.append(h("tr", null,
    h("th", null, "Агент"), h("th", null, "Сесій"), h("th", null, "Дій"),
    h("th", null, "Заблоковано"), h("th", null, "Потребує людини"),
    h("th", null, "Порушень"), h("th", null, "Частка блокувань")));
  for (const a of data.by_agent) {
    const share = a.actions ? Math.round((a.blocked / a.actions) * 100) : 0;
    const bar = h("div", "bar", h("span"));
    bar.firstChild.style.width = share + "%";
    table.append(h("tr", null,
      h("td", null, a.agent_name), h("td", null, a.sessions), h("td", null, a.actions),
      h("td", null, a.blocked), h("td", null, a.pending), h("td", null, a.violations),
      h("td", null, share + "%", bar)));
  }
  root.append(h("div", "card", h("h3", null, "Метрики якості роботи агентів"), table));

  // Метрики по сесіях
  const sessionTable = h("table");
  sessionTable.append(h("tr", null,
    h("th", null, "Сесія"), h("th", null, "Дій"), h("th", null, "Прийнято"),
    h("th", null, "Заблоковано"), h("th", null, "Порушень"),
    h("th", null, "Передано людині"), h("th", null, "Вирішено людиною")));
  for (const s of data.sessions) {
    sessionTable.append(h("tr", null,
      h("td", null, s.id + " (" + s.agent_name + ")"), h("td", null, s.actions),
      h("td", null, s.approved), h("td", null, s.blocked), h("td", null, s.violations),
      h("td", null, s.human_asked), h("td", null, s.human_resolved)));
  }
  root.append(h("div", "card", h("h3", null, "Метрики по сесіях"), sessionTable));

  document.getElementById("pending-count").textContent = c.pending || "";
  content.replaceChildren(root);
}

async function showSessions() {
  const data = await api("/api/overview");

  const root = h("div");
  root.append(h("h2", null, "Сесії агента"));

  for (const s of data.sessions) {
    const details = h("div");                      // підвантажується при першому кліку
    details.hidden = true;
    let loaded = false;

    const head = h("div", "row session-head",
      h("div", null,
        h("strong", null, s.agent_name + " · " + s.repository + " (" + s.branch + ")"),
        h("div", "muted", s.task_goal),
        h("div", "muted", "Початок: " + formatDate(s.started_at) + " · Дій: " + s.actions +
          " · Порушень: " + s.violations)),
      badge(SESSION_STATUSES, s.status));

    head.addEventListener("click", async () => {
      details.hidden = !details.hidden;
      if (details.hidden || loaded) return;
      loaded = true;
      try {
        const full = await api("/api/sessions/" + encodeURIComponent(s.id));
        for (const a of full.actions) details.append(actionBlock(a));
      } catch (err) {
        details.append(h("p", "error", err.message));
      }
    });

    root.append(h("div", "card", head, details));
  }
  content.replaceChildren(root);
}

// Блок однієї дії: що зробив агент, вердикт, порушені правила, код
function actionBlock(a) {
  const box = h("div", "card",
    h("div", "row",
      h("strong", null, "#" + a.seq + " · " + a.type + " · " + a.target),
      badge(VERDICTS, a.verdict)),
    h("div", null, a.summary),
    h("div", "muted", "Причина вердикту: " + (a.reason || "—")));
  for (const v of a.violations || []) box.append(violationBlock(v));
  box.append(h("pre", null, a.content));
  return box;
}

async function showPending() {
  const data = await api("/api/pending");
  const root = h("div");
  root.append(h("h2", null, "Очікують рішення людини"));

  document.getElementById("pending-count").textContent = data.pending.length || "";

  if (data.pending.length === 0) {
    root.append(h("div", "card", "Немає справ, що чекають рішення."));
  }

  for (const a of data.pending) {
    const card = h("div", "card",
      h("div", "row",
        h("strong", null, a.type + " · " + a.target),
        badge(VERDICTS, a.verdict)),
      h("div", "muted", a.agent_name + " · " + a.repository + " (" + a.branch + ")"),
      h("div", "muted", "Завдання агента: " + a.task_goal),
      h("p", null, a.summary),
      h("div", "muted", "Чому потрібна людина: " + (a.reason || "—")));

    for (const v of a.violations) card.append(violationBlock(v));
    card.append(h("pre", null, a.content));

    const approve = h("button", "action approve", "Схвалити");
    const reject = h("button", "action reject", "Відхилити");
    approve.addEventListener("click", () => openDecisionDialog(a, "approve"));
    reject.addEventListener("click", () => openDecisionDialog(a, "reject"));
    card.append(h("div", "row", h("span"), h("div", null, approve, " ", reject)));

    root.append(card);
  }
  content.replaceChildren(root);
}

async function showJournal() {
  const data = await api("/api/journal");

  // номери записів, у яких знайдено проблему
  const badSeqs = new Set(data.integrity.chain.problems.map((p) => p.seq));
  for (const d of data.integrity.reconcile_diffs) badSeqs.add(d.seq);

  const root = h("div");
  root.append(h("h2", null, "Журнал доказів"));
  root.append(h("p", "muted",
    "Кожен запис містить хеш попереднього: H(i) = SHA-256(H(i-1) ‖ seq ‖ тип ‖ час ‖ дані)."));

  const table = h("table");
  table.append(h("tr", null,
    h("th", null, "№"), h("th", null, "Час"), h("th", null, "Подія"),
    h("th", null, "Дані"), h("th", null, "Хеш")));
  for (const e of data.entries) {
    const row = h("tr", badSeqs.has(e.seq) ? "bad-row" : "",
      h("td", null, e.seq), h("td", null, formatDate(e.event_time)),
      h("td", null, e.event_type), h("td", "hash", e.payload),
      h("td", "hash", e.current_hash.slice(0, 16) + "..."));
    table.append(row);
  }
  root.append(h("div", "card", table));

  // перелік проблем
  const i = data.integrity;
  if (!i.ok) {
    const list = h("div", "card", h("h3", null, "Знайдені проблеми"));
    for (const p of i.chain.problems) list.append(h("p", null, "Запис №" + p.seq + ": " + p.issue));
    for (const d of i.reconcile_diffs) list.append(h("p", null, "Звірка з оригіналом, запис №" + d.seq + ": " + d.issue));
    for (const d of i.verdict_diffs) {
      list.append(h("p", null, "Дія " + d.action_id + ": у БД «" + d.in_db + "», у журналі «" + d.in_journal + "»"));
    }
    root.append(list);
  }
  content.replaceChildren(root);
}

async function showRules() {
  const data = await api("/api/rules");
  const table = h("table");
  table.append(h("tr", null,
    h("th", null, "Код"), h("th", null, "Правило"), h("th", null, "Категорія"),
    h("th", null, "Рівень"), h("th", null, "Порушень")));
  for (const r of data.rules) {
    table.append(h("tr", null,
      h("td", null, r.code),
      h("td", null, h("strong", null, r.name), h("div", "muted", r.description)),
      h("td", null, CATEGORIES[r.category] || r.category),
      h("td", null, badge(SEVERITIES, r.severity)),
      h("td", null, r.violations)));
  }
  content.replaceChildren(h("div", null, h("h2", null, "Правила нагляду"), h("div", "card", table)));
}

async function showThreats() {
  const data = await api("/api/threats");
  const root = h("div", null, h("h2", null, "Модель загроз панелі нагляду"));

  for (const t of data.threats) {
    root.append(h("div", "card",
      h("div", "row",
        h("strong", null, t.id + " · " + t.title),
        h("div", null,
          badge(SEVERITIES, t.severity), " ",
          h("span", "badge " + (t.status === "mitigated" ? "green" : "yellow"),
            t.status === "mitigated" ? "Закрито" : "Частково"))),
      h("p", "muted", "Імовірність: " + (SEVERITIES[t.likelihood] || [t.likelihood])[0]),
      h("p", null, t.description),
      h("p", null, h("strong", null, "Захист: "), t.mitigation)));
  }

  const standards = h("div", "card", h("h3", null, "Відповідність стандартам"));
  for (const s of data.standards) {
    standards.append(h("p", null, h("strong", null, s.name + ": "), s.relevance));
  }
  root.append(standards);
  content.replaceChildren(root);
}

// ---------- Вікно рішення (окремий канал із PIN) ----------

const dialog = document.getElementById("decision-dialog");
let currentDecision = null;

function openDecisionDialog(action, decision) {
  currentDecision = { actionId: action.id, decision: decision };
  document.getElementById("dialog-title").textContent =
    decision === "approve" ? "Схвалити дію?" : "Відхилити дію?";
  document.getElementById("dialog-target").textContent = action.type + " · " + action.target;
  document.getElementById("pin").value = "";
  document.getElementById("note").value = "";
  document.getElementById("dialog-error").textContent = "";
  dialog.showModal();
}

document.getElementById("dialog-cancel").addEventListener("click", () => dialog.close());

document.getElementById("decision-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorBox = document.getElementById("dialog-error");
  try {
    await api("/api/decide", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action_id: currentDecision.actionId,
        decision: currentDecision.decision,
        pin: document.getElementById("pin").value,
        note: document.getElementById("note").value,
      }),
    });
    dialog.close();
    showView("pending");
  } catch (err) {
    errorBox.textContent = err.message;
  }
});

//  Навігація

const views = {
  overview: showOverview,
  sessions: showSessions,
  pending: showPending,
  journal: showJournal,
  rules: showRules,
  threats: showThreats,
};

async function showView(name) {
  for (const button of document.querySelectorAll("#menu button")) {
    button.classList.toggle("active", button.dataset.view === name);
  }
  refreshBanner();
  try {
    await views[name]();
  } catch (err) {
    content.replaceChildren(h("div", "card error", "Помилка: " + err.message));
  }
}

document.getElementById("menu").addEventListener("click", (event) => {
  const button = event.target.closest("button");
  if (button) showView(button.dataset.view);
});

showView("overview");
