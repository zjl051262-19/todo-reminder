import { createDecipheriv, createHash, pbkdf2Sync } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";

const SENDKEY = process.env.SERVERCHAN_SENDKEY || "";
const LIBRARY_CODES = splitCodes(process.env.TODO_LIBRARY_CODES || "");
const STATE_PATH = "reminder-state.json";
const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;
const RETAIN_STATE_MS = 45 * DAY_MS;
const DEFAULT_PRIORITY_ID = "p3";
const PRIORITIES = [
  { id: "p1", label: "最紧急", rank: 1 },
  { id: "p2", label: "次紧急", rank: 2 },
  { id: "p3", label: "普通", rank: 3 },
  { id: "p4", label: "低优先级", rank: 4 }
];
const PRIORITY_MAP = new Map(PRIORITIES.map((priority) => [priority.id, priority]));
const PUSH_PRIORITY_IDS = new Set(["p1", "p2"]);

if (!SENDKEY) {
  throw new Error("Missing SERVERCHAN_SENDKEY repository secret.");
}

if (!LIBRARY_CODES.length) {
  console.log("No TODO_LIBRARY_CODES configured. Nothing to check.");
  process.exit(0);
}

const state = await loadState();
let sentCount = 0;

for (const code of LIBRARY_CODES) {
  const filePath = syncFilePath(code);
  if (!existsSync(filePath)) {
    console.log(`No sync file for library: ${code}`);
    continue;
  }

  let data;
  try {
    const encryptedPayload = JSON.parse(await readFile(filePath, "utf8"));
    data = JSON.parse(decryptPayload(encryptedPayload, code));
  } catch (error) {
    console.log(`Cannot decrypt library ${code}: ${error.message}`);
    continue;
  }

  if (!data.settings || data.settings.wechatPushEnabled !== true) {
    console.log(`WeChat push disabled for library: ${code}`);
    continue;
  }

  const reminders = collectReminders(data.todos || [], code);
  const unsent = reminders.filter((item) => !state.sent[item.key]);
  if (!unsent.length) {
    console.log(`No new reminders for library: ${code}`);
    continue;
  }

  await sendServerChan(code, unsent);
  for (const item of unsent) {
    state.sent[item.key] = new Date().toISOString();
    sentCount += 1;
  }
}

cleanupState(state);
state.updatedAt = new Date().toISOString();
await writeFile(STATE_PATH, `${JSON.stringify(state, null, 2)}\n`, "utf8");
console.log(`Done. New reminder records: ${sentCount}`);

function splitCodes(value) {
  return value
    .split(/[\n,，]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function syncFilePath(code) {
  const key = createHash("sha256").update(code, "utf8").digest("base64url").slice(0, 24);
  return `sync-data-${key}.json`;
}

async function loadState() {
  if (!existsSync(STATE_PATH)) {
    return { version: 1, updatedAt: null, sent: {} };
  }

  try {
    const parsed = JSON.parse(await readFile(STATE_PATH, "utf8"));
    return {
      version: 1,
      updatedAt: parsed.updatedAt || null,
      sent: parsed.sent || {}
    };
  } catch {
    return { version: 1, updatedAt: null, sent: {} };
  }
}

function decryptPayload(payload, passphrase) {
  const salt = Buffer.from(payload.salt, "base64");
  const iv = Buffer.from(payload.iv, "base64");
  const encrypted = Buffer.from(payload.data, "base64");
  const key = pbkdf2Sync(Buffer.from(passphrase, "utf8"), salt, 120000, 32, "sha256");
  const authTag = encrypted.subarray(encrypted.length - 16);
  const ciphertext = encrypted.subarray(0, encrypted.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

function collectReminders(todos, libraryCode) {
  const now = Date.now();
  const pushSlot = currentPushSlot(now);
  const reminders = [];

  for (const todo of todos) {
    if (!todo || todo.done || todo.deletedAt || !todo.dueAt) continue;
    const dueTime = parseChinaLocalDateTime(todo.dueAt).getTime();
    if (!Number.isFinite(dueTime)) continue;
    const left = dueTime - now;
    const stage = getStage(left);
    const priority = getEffectivePriority(todo, now);
    if (!PUSH_PRIORITY_IDS.has(priority.id)) continue;

    const keySeed = [
      libraryCode,
      todo.id,
      todo.updatedAt || todo.createdAt || "",
      todo.dueAt,
      priority.id,
      pushSlot
    ].join("|");

    reminders.push({
      key: createHash("sha256").update(keySeed, "utf8").digest("hex"),
      title: todo.title || "未命名事项",
      note: todo.note || "",
      priority,
      stage: stage || { id: "normal", label: "未到期" },
      dueAt: todo.dueAt,
      countdown: formatCountdown(dueTime, now)
    });
  }

  return reminders;
}

function parseChinaLocalDateTime(value) {
  const match = String(value).match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/);
  if (!match) return new Date(value);
  const [, year, month, day, hour, minute] = match.map(Number);
  return new Date(Date.UTC(year, month - 1, day, hour - 8, minute));
}

function getStage(leftMs) {
  if (leftMs < 0) return { id: "overdue", label: "已到期" };
  if (leftMs <= 12 * HOUR_MS) return { id: "due-12h", label: "12小时内到期" };
  if (leftMs <= DAY_MS) return { id: "due-1d", label: "1天内到期" };
  if (leftMs <= 3 * DAY_MS) return { id: "due-3d", label: "3天内到期" };
  return null;
}

function normalizePriorityId(value) {
  return PRIORITY_MAP.has(value) ? value : DEFAULT_PRIORITY_ID;
}

function getPriority(priorityId) {
  return PRIORITY_MAP.get(normalizePriorityId(priorityId));
}

function getEffectivePriority(todo, now) {
  const manual = getPriority(todo.priorityId);
  const examPriority = getExamAutoPriority(todo, now);
  if (examPriority && examPriority.rank < manual.rank) {
    return { ...examPriority, source: "exam" };
  }
  return { ...manual, source: "manual" };
}

function getExamAutoPriority(todo, now) {
  if (!isExamTodo(todo)) return null;
  const dueTime = parseChinaLocalDateTime(todo.dueAt).getTime();
  if (!Number.isFinite(dueTime)) return null;
  const left = dueTime - now;
  if (left <= 7 * DAY_MS) return getPriority("p1");
  if (left <= 14 * DAY_MS) return getPriority("p2");
  return null;
}

function isExamTodo(todo) {
  return `${todo.title || ""} ${todo.note || ""}`.includes("考试");
}

function currentPushSlot(now) {
  const chinaTime = new Date(now + 8 * HOUR_MS);
  const year = chinaTime.getUTCFullYear();
  const month = String(chinaTime.getUTCMonth() + 1).padStart(2, "0");
  const day = String(chinaTime.getUTCDate()).padStart(2, "0");
  const hour = chinaTime.getUTCHours() < 12 ? "00" : "12";
  return `${year}-${month}-${day}-${hour}`;
}

function formatCountdown(dueTime, now) {
  const left = dueTime - now;
  if (left < 0) return `已逾期 ${Math.max(1, Math.ceil(Math.abs(left) / DAY_MS))} 天`;
  if (left < DAY_MS) return "今天截止";
  return `倒数 ${Math.ceil(left / DAY_MS)} 天`;
}

async function sendServerChan(libraryCode, reminders) {
  const counts = reminders.reduce((acc, item) => {
    acc[item.priority.label] = (acc[item.priority.label] || 0) + 1;
    return acc;
  }, {});

  const title = `待办提醒：${libraryCode} 有 ${reminders.length} 个重要事项`;
  const details = reminders
    .slice()
    .sort((a, b) => {
      if (a.priority.rank !== b.priority.rank) return a.priority.rank - b.priority.rank;
      return parseChinaLocalDateTime(a.dueAt) - parseChinaLocalDateTime(b.dueAt);
    })
    .flatMap((item, index) => {
      const sourceText = item.priority.source === "exam" ? "，考试自动升级" : "";
      const lines = [
        `${index + 1}. [${item.priority.label}${sourceText} / ${item.stage.label} / ${item.countdown}] ${item.title}`,
        `   截止：${formatDueAt(item.dueAt)}`
      ];
      if (item.note) {
        lines.push(`   准备物品：${item.note}`);
      }
      return lines;
    });

  const lines = [
    `当前库：${libraryCode}`,
    "",
    "档位统计：",
    ...Object.entries(counts).map(([label, count]) => `- ${label}: ${count} 个`),
    "",
    "具体事项：",
    ...details
  ];

  const body = new URLSearchParams({
    title,
    desp: lines.join("\n")
  });

  if (process.env.DRY_RUN === "1") {
    console.log(`[DRY_RUN] ${title}\n${lines.join("\n")}`);
    return;
  }

  const response = await fetch(`https://sctapi.ftqq.com/${SENDKEY}.send`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });

  const text = await response.text();
  if (!response.ok) {
    throw new Error(`ServerChan request failed ${response.status}: ${text}`);
  }

  try {
    const result = JSON.parse(text);
    if (result.code && result.code !== 0) {
      throw new Error(`ServerChan returned code ${result.code}: ${text}`);
    }
  } catch (error) {
    if (error.message.startsWith("ServerChan returned")) throw error;
  }
}

function formatDueAt(value) {
  const match = String(value).match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/);
  if (!match) return String(value);
  const [, year, month, day, hour, minute] = match;
  return `${year}/${month}/${day} ${hour}:${minute}`;
}

function cleanupState(currentState) {
  const cutoff = Date.now() - RETAIN_STATE_MS;
  for (const [key, value] of Object.entries(currentState.sent)) {
    if (new Date(value).getTime() < cutoff) {
      delete currentState.sent[key];
    }
  }
}
