import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const tursoUrl = process.env.TURSO_DATABASE_URL;
const tursoToken = process.env.TURSO_AUTH_TOKEN;
let local;
let initialized;

function localDatabase() {
  if (local) return local;
  const file = resolve(process.env.SQLITE_PATH || './data/control-gastos.db');
  mkdirSync(dirname(file), { recursive: true });
  local = new DatabaseSync(file);
  local.exec('PRAGMA foreign_keys = ON');
  return local;
}

function encode(value) {
  if (value === null || value === undefined) return { type: 'null' };
  if (typeof value === 'number') return Number.isInteger(value) ? { type: 'integer', value: String(value) } : { type: 'float', value };
  if (typeof value === 'bigint') return { type: 'integer', value: String(value) };
  if (value instanceof Uint8Array) return { type: 'blob', base64: Buffer.from(value).toString('base64') };
  return { type: 'text', value: String(value) };
}
function decode(value) {
  if (!value || value.type === 'null') return null;
  if (value.type === 'integer') return Number(value.value);
  if (value.type === 'float') return value.value;
  if (value.type === 'blob') return Buffer.from(value.base64 || '', 'base64');
  return value.value;
}

async function remoteExecute(sql, args = []) {
  if (!tursoToken) throw new Error('Falta configurar TURSO_AUTH_TOKEN.');
  const endpoint = new URL('/v2/pipeline', tursoUrl.replace(/^libsql:/, 'https:'));
  const result = await fetch(endpoint, { method: 'POST', headers: { Authorization: `Bearer ${tursoToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ requests: [{ type: 'execute', stmt: { sql, args: args.map(encode) } }, { type: 'close' }] }) });
  if (!result.ok) throw new Error(`SQLite remoto respondió ${result.status}.`);
  const payload = await result.json();
  const first = payload.results?.[0];
  if (first?.type === 'error') throw new Error(first.error?.message || 'Error de SQLite remoto.');
  const resultSet = first?.response?.result;
  if (!resultSet) return { rows: [], changes: 0 };
  const columns = (resultSet.cols || []).map(column => column.name);
  const rows = (resultSet.rows || []).map(row => Object.fromEntries(row.map((value, index) => [columns[index], decode(value)])));
  return { rows, changes: Number(resultSet.affected_row_count || 0), lastInsertRowid: resultSet.last_insert_rowid };
}

async function run(sql, args = []) {
  if (sql && typeof sql === 'object') {
    args = sql.args || [];
    sql = sql.sql;
  }
  if (typeof sql !== 'string') throw new TypeError('El SQL debe ser una cadena de texto.');
  if (tursoUrl) return remoteExecute(sql, args);
  const database = localDatabase();
  if (/^\s*(SELECT|PRAGMA|WITH)\b/i.test(sql)) return { rows: database.prepare(sql).all(...args), changes: 0 };
  const result = database.prepare(sql).run(...args);
  return { rows: [], changes: Number(result.changes), lastInsertRowid: result.lastInsertRowid };
}

async function runBatch(statements) {
  if (tursoUrl) {
    if (!tursoToken) throw new Error('Falta configurar TURSO_AUTH_TOKEN.');
    const endpoint = new URL('/v2/pipeline', tursoUrl.replace(/^libsql:/, 'https:'));
    const steps = [{ stmt: { sql: 'BEGIN' } }];
    for (const { sql, args = [] } of statements) steps.push({ condition: { type: 'ok', step: steps.length - 1 }, stmt: { sql, args: args.map(encode) } });
    const lastWrite = steps.length - 1;
    const commitStep = steps.length;
    steps.push({ condition: { type: 'ok', step: lastWrite }, stmt: { sql: 'COMMIT' } });
    steps.push({ condition: { type: 'not', cond: { type: 'ok', step: commitStep } }, stmt: { sql: 'ROLLBACK' } });
    const batch = { steps };
    const result = await fetch(endpoint, { method: 'POST', headers: { Authorization: `Bearer ${tursoToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ requests: [{ type: 'batch', batch }, { type: 'close' }] }) });
    if (!result.ok) throw new Error(`SQLite remoto respondió ${result.status}.`);
    const payload = await result.json();
    const first = payload.results?.[0];
    if (first?.type === 'error') throw new Error(first.error?.message || 'Error en transacción SQLite.');
    const stepError = first?.response?.result?.step_errors?.find(Boolean);
    if (stepError) throw new Error(stepError.message || 'Error en transacción SQLite.');
    return;
  }
  const database = localDatabase();
  database.exec('BEGIN IMMEDIATE');
  try {
    for (const { sql, args = [] } of statements) database.prepare(sql).run(...args);
    database.exec('COMMIT');
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
}

const schema = [
  `CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, google_sub TEXT NOT NULL UNIQUE, email TEXT NOT NULL, name TEXT NOT NULL, picture TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
  `CREATE TABLE IF NOT EXISTS user_data (user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, namespace TEXT NOT NULL, payload TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(user_id, namespace))`,
  `CREATE TABLE IF NOT EXISTS reminder_delivery (idempotency_key TEXT PRIMARY KEY, sent_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
];

export async function db() {
  if (tursoUrl && !tursoUrl.startsWith('libsql://') && !tursoUrl.startsWith('https://')) throw new Error('TURSO_DATABASE_URL debe usar libsql:// o https://.');
  if (!initialized) initialized = Promise.all(schema.map(sql => run(sql)));
  await initialized;
  return { execute: run, batch: runBatch };
}
