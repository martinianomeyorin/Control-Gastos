import { randomBytes, createHmac, createHash, timingSafeEqual } from 'node:crypto';
import { db } from './_db.js';

const SESSION_COOKIE = 'cg_session';
const OAUTH_COOKIE = 'cg_oauth';
const appDataKeys = ['expenses', 'cards', 'services', 'finance', 'closings'];
const secret = () => {
  const value = process.env.SESSION_SECRET;
  if (!value || value.length < 32) throw new Error('SESSION_SECRET debe tener al menos 32 caracteres.');
  return new TextEncoder().encode(value);
};
const b64 = value => Buffer.from(value).toString('base64url');
const signJwt = payload => {
  const head = b64(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64(JSON.stringify({ ...payload, iss: 'control-gastos', aud: 'control-gastos-web', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 1209600 }));
  const unsigned = `${head}.${body}`;
  return `${unsigned}.${createHmac('sha256', secret()).update(unsigned).digest('base64url')}`;
};
const cookie = (name, value, maxAge, secure) => `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure ? '; Secure' : ''}`;
const clearCookie = (name, secure) => `${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure ? '; Secure' : ''}`;
const response = (body, status = 200, headers = {}) => Response.json(body, { status, headers });
function redirect(url, values = {}) {
  const headers = new Headers({ Location: url });
  for (const [name, value] of Object.entries(values)) {
    if (Array.isArray(value)) value.forEach(item => headers.append(name, item));
    else headers.set(name, value);
  }
  return new Response(null, { status: 302, headers });
}

function parseCookies(request) {
  return Object.fromEntries((request.headers.get('cookie') || '').split(';').map(part => part.trim().split(/=(.*)/s).slice(0, 2)).filter(([key]) => key));
}
function redirectUri(request) {
  return process.env.GOOGLE_REDIRECT_URI || new URL('/api/auth/google/callback', request.url).toString();
}
async function currentUser(request) {
  const token = parseCookies(request)[SESSION_COOKIE];
  if (!token) return null;
  try {
    const [head, body, signature] = token.split('.');
    const expected = createHmac('sha256', secret()).update(`${head}.${body}`).digest();
    const supplied = Buffer.from(signature || '', 'base64url');
    if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (payload.iss !== 'control-gastos' || payload.aud !== 'control-gastos-web' || payload.exp < Date.now() / 1000 || !payload.sub) return null;
    return { id: payload.sub, email: payload.email, name: payload.name, picture: payload.picture || '' };
  } catch { return null; }
}
function requireSameOrigin(request) {
  const origin = request.headers.get('origin');
  return origin === new URL(request.url).origin;
}

async function startGoogle(request) {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId || !process.env.GOOGLE_CLIENT_SECRET) return response({ error: 'Falta configurar OAuth de Google.' }, 503);
  const state = randomBytes(32).toString('base64url');
  const verifier = randomBytes(48).toString('base64url');
  const signature = createHmac('sha256', secret()).update(`${state}.${verifier}`).digest('base64url');
  const secure = new URL(request.url).protocol === 'https:';
  const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  url.search = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri(request), response_type: 'code', scope: 'openid email profile', state, code_challenge_method: 'S256', prompt: 'select_account' }).toString();
  // Generate the PKCE challenge with SHA-256, keeping the verifier in a short-lived, HttpOnly cookie.
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  url.searchParams.set('code_challenge', challenge);
  return redirect(url.toString(), { 'Set-Cookie': cookie(OAUTH_COOKIE, `${state}.${verifier}.${signature}`, 600, secure), 'Cache-Control': 'no-store' });
}

async function googleCallback(request) {
  const url = new URL(request.url);
  const params = url.searchParams;
  const stored = parseCookies(request)[OAUTH_COOKIE]?.split('.') || [];
  const [state, verifier, signature] = stored;
  const incomingState = params.get('state') || '';
  const expected = state && verifier ? createHmac('sha256', secret()).update(`${state}.${verifier}`).digest() : Buffer.alloc(0);
  const supplied = signature ? Buffer.from(signature, 'base64url') : Buffer.alloc(0);
  const stateMatches = state && incomingState && state.length === incomingState.length && timingSafeEqual(Buffer.from(state), Buffer.from(incomingState));
  if (!params.get('code') || !stateMatches || expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) return redirect('/?auth=failed', { 'Set-Cookie': clearCookie(OAUTH_COOKIE, url.protocol === 'https:') });
  const tokenResponse = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ code: params.get('code'), client_id: process.env.GOOGLE_CLIENT_ID, client_secret: process.env.GOOGLE_CLIENT_SECRET, redirect_uri: redirectUri(request), grant_type: 'authorization_code', code_verifier: verifier }) });
  if (!tokenResponse.ok) return redirect('/?auth=failed', { 'Set-Cookie': clearCookie(OAUTH_COOKIE, url.protocol === 'https:') });
  const tokens = await tokenResponse.json();
  const profileResponse = await fetch('https://openidconnect.googleapis.com/v1/userinfo', { headers: { Authorization: `Bearer ${tokens.access_token}` } });
  if (!profileResponse.ok) return redirect('/?auth=failed', { 'Set-Cookie': clearCookie(OAUTH_COOKIE, url.protocol === 'https:') });
  const profile = await profileResponse.json();
  if (!profile.sub || !profile.email || profile.email_verified !== true) return redirect('/?auth=failed', { 'Set-Cookie': clearCookie(OAUTH_COOKIE, url.protocol === 'https:') });
  const client = await db();
  await client.execute({ sql: `INSERT INTO users(id, google_sub, email, name, picture) VALUES(?, ?, ?, ?, ?) ON CONFLICT(google_sub) DO UPDATE SET email=excluded.email, name=excluded.name, picture=excluded.picture`, args: [profile.sub, profile.sub, profile.email, profile.name || profile.email, profile.picture || ''] });
  const session = signJwt({ sub: profile.sub, email: profile.email, name: profile.name || profile.email, picture: profile.picture || '' });
  const secure = url.protocol === 'https:';
  return redirect('/', { 'Set-Cookie': [cookie(SESSION_COOKIE, session, 1209600, secure), clearCookie(OAUTH_COOKIE, secure)], 'Cache-Control': 'no-store' });
}

async function dataHandler(request, user) {
  const client = await db();
  if (request.method === 'GET') {
    const result = await client.execute({ sql: 'SELECT namespace, payload FROM user_data WHERE user_id = ?', args: [user.id] });
    const data = Object.fromEntries(result.rows.map(row => [row.namespace, JSON.parse(row.payload)]));
    return response({ user, data });
  }
  if (request.method !== 'PUT' || !requireSameOrigin(request)) return response({ error: 'Método no permitido.' }, 405);
  const body = await request.json();
  const updates = Array.isArray(body.updates) ? body.updates : [{ key: body.key, value: body.value }];
  if (!updates.length || updates.length > appDataKeys.length || updates.some(item => !appDataKeys.includes(item.key) || item.value === undefined) || new Set(updates.map(item => item.key)).size !== updates.length) return response({ error: 'Datos inválidos.' }, 400);
  await client.batch(updates.map(item => ({ sql: `INSERT INTO user_data(user_id, namespace, payload, updated_at) VALUES(?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(user_id, namespace) DO UPDATE SET payload=excluded.payload, updated_at=CURRENT_TIMESTAMP`, args: [user.id, item.key, JSON.stringify(item.value)] })));
  return response({ ok: true });
}

function buenosAiresDate() {
  const parts = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Argentina/Buenos_Aires', year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(new Date());
  const value = Object.fromEntries(parts.map(part => [part.type, part.value]));
  return `${value.year}-${value.month}-${value.day}`;
}
function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
}
function monthlyCardCharge(expense, month) {
  if (!expense.payment || ['Efectivo', 'Débito'].includes(expense.payment)) return 0;
  const start = expense.firstMonth || expense.date?.slice(0, 7);
  if (!start) return 0;
  const index = (Number(month.slice(0, 4)) - Number(start.slice(0, 4))) * 12 + Number(month.slice(5, 7)) - Number(start.slice(5, 7));
  const count = Math.max(1, Number(expense.installments) || 1);
  if (index < 0 || index >= count) return 0;
  const cents = Math.round(Number(expense.amount || 0) * 100), base = Math.floor(cents / count);
  return (index === count - 1 ? cents - base * (count - 1) : base) / 100;
}
async function sendDueReminders(request) {
  const cronSecret = process.env.CRON_SECRET;
  if (!cronSecret || request.headers.get('authorization') !== `Bearer ${cronSecret}`) return response({ error: 'No autorizado.' }, 401);
  const apiKey = process.env.RESEND_API_KEY, from = process.env.REMINDER_FROM_EMAIL;
  if (!apiKey || !from) return response({ error: 'Falta configurar RESEND_API_KEY y REMINDER_FROM_EMAIL.' }, 503);
  const date = buenosAiresDate(), month = date.slice(0, 7), client = await db();
  const { rows: users } = await client.execute('SELECT id, email FROM users');
  let sent = 0, skipped = 0;
  for (const user of users) {
    const { rows } = await client.execute({ sql: "SELECT namespace, payload FROM user_data WHERE user_id = ? AND namespace IN ('services', 'cards', 'closings', 'expenses')", args: [user.id] });
    const data = Object.fromEntries(rows.map(row => [row.namespace, JSON.parse(row.payload)]));
    const services = (data.services || []).filter(service => service.status !== 'Pagado' && service.dueDate === date).map(service => ({ kind: 'Servicio', name: service.name, amount: Number(service.amount) || 0, detail: `Medio de pago: ${service.payment || 'Sin especificar'}` }));
    const cards = (data.cards || []).flatMap(card => {
      const cycle = data.closings?.[month]?.[card];
      const due = typeof cycle === 'object' ? cycle?.due : null;
      if (due !== date) return [];
      const amount = (data.expenses || []).reduce((total, expense) => total + (expense.payment === card ? monthlyCardCharge(expense, month) : 0), 0);
      return amount > 0 ? [{ kind: 'Tarjeta', name: card, amount, detail: 'Vence hoy' }] : [];
    });
    const items = [...services, ...cards];
    if (!items.length) continue;
    const idempotencyKey = `due-reminders/${user.id}/${date}`;
    const existing = await client.execute({ sql: 'SELECT idempotency_key FROM reminder_delivery WHERE idempotency_key = ?', args: [idempotencyKey] });
    if (existing.rows.length) { skipped++; continue; }
    const currency = amount => new Intl.NumberFormat('es-AR', { style: 'currency', currency: 'ARS' }).format(amount);
    const htmlItems = items.map(item => `<li style="margin:0 0 14px"><strong>${escapeHtml(item.kind)}: ${escapeHtml(item.name)}</strong><br>${escapeHtml(item.detail)}<br>Monto: ${escapeHtml(currency(item.amount))}</li>`).join('');
    const textItems = items.map(item => `• ${item.kind}: ${item.name} — ${item.detail} — ${currency(item.amount)}`).join('\n');
    const html = `<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;color:#24352a"><h2>Vencimientos de hoy</h2><p>Hola ${escapeHtml(user.email)}, estos son tus pagos que vencen hoy (${date}):</p><ul style="padding-left:20px">${htmlItems}</ul><p>Ingresá a Control Gastos para revisar tus vencimientos.</p></div>`;
    const emailResponse = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey }, body: JSON.stringify({ from, to: [user.email], subject: items.length === 1 ? `Vence hoy: ${items[0].name}` : `Tenés ${items.length} vencimientos hoy`, html, text: `Vencimientos de hoy (${date}):\n\n${textItems}\n\nIngresá a Control Gastos para revisar tus vencimientos.` }) });
    if (!emailResponse.ok) { console.error('Resend respondió', emailResponse.status, await emailResponse.text()); throw new Error(`No se pudo enviar el recordatorio para ${user.email}.`); }
    await client.execute({ sql: 'INSERT INTO reminder_delivery(idempotency_key) VALUES(?) ON CONFLICT(idempotency_key) DO NOTHING', args: [idempotencyKey] });
    sent++;
  }
  return response({ ok: true, date, sent, skipped });
}

export async function handle(request) {
  const path = new URL(request.url).pathname.replace(/\/$/, '');
  const secure = new URL(request.url).protocol === 'https:';
  try {
    if (path === '/api/cron/reminders' && request.method === 'GET') return await sendDueReminders(request);
    if (path === '/api/auth/google/start' && request.method === 'GET') return await startGoogle(request);
    if (path === '/api/auth/google/callback' && request.method === 'GET') return await googleCallback(request);
    if (path === '/api/auth/session' && request.method === 'GET') return response({ user: await currentUser(request) }, 200, { 'Cache-Control': 'no-store' });
    if (path === '/api/auth/logout' && request.method === 'POST') return requireSameOrigin(request) ? response({ ok: true }, 200, { 'Set-Cookie': clearCookie(SESSION_COOKIE, secure) }) : response({ error: 'Origen inválido.' }, 403);
    if (path === '/api/data') {
      const user = await currentUser(request);
      if (!user) return response({ error: 'Iniciá sesión para continuar.' }, 401);
      return await dataHandler(request, user);
    }
    return response({ error: 'No encontrado.' }, 404);
  } catch (error) {
    console.error('API error:', error);
    return response({ error: 'Error interno. Revisa la configuración del servidor.' }, 500);
  }
}

export default { fetch: handle };
