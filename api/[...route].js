import { randomBytes, createHmac, createHash, timingSafeEqual } from 'node:crypto';
import { connect as connectTls } from 'node:tls';
import { db } from './_db.js';

const SESSION_COOKIE = 'cg_session';
const OAUTH_COOKIE = 'cg_oauth';
const appDataKeys = ['expenses', 'cards', 'services', 'finance', 'closings', 'categories'];
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
async function exchangeRateHandler() {
  try {
    const upstream = await fetch('https://dolarapi.com/v1/dolares/tarjeta', { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(7000) });
    if (!upstream.ok) return response({ error: 'No se pudo consultar la cotización del dólar tarjeta.' }, 502);
    const quote = await upstream.json();
    const rate = Number(quote.venta);
    if (!Number.isFinite(rate) || rate <= 0) return response({ error: 'La fuente devolvió una cotización inválida.' }, 502);
    return response({ rate, source: 'Dólar tarjeta de referencia · DolarApi / Ámbito', updatedAt: quote.fechaActualizacion || null }, 200, { 'Cache-Control': 'public, s-maxage=300, stale-while-revalidate=600' });
  } catch {
    return response({ error: 'No se pudo consultar la cotización. Podés cargarla manualmente.' }, 502);
  }
}
function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
}
async function sendGmail({ from, appPassword, to, subject, html, text }) {
  if (!/^[^\s<>]+@gmail\.com$/i.test(from) || !/^[^\s<>]+@[^\s<>]+$/.test(to)) throw new Error('GMAIL_USER o destinatario no tienen un formato válido.');
  const socket = connectTls({ host: 'smtp.gmail.com', port: 465, servername: 'smtp.gmail.com' });
  socket.setTimeout(20000, () => socket.destroy(new Error('Tiempo de espera agotado al conectar con Gmail SMTP.')));
  let buffer = '', current = [], closed = false;
  const replies = [], readers = [];
  const finishReply = reply => { const reader = readers.shift(); if (reader) reader.resolve(reply); else replies.push(reply); };
  const failReaders = error => { closed = true; while (readers.length) readers.shift().reject(error); };
  socket.on('data', chunk => {
    buffer += chunk.toString('utf8');
    const lines = buffer.split(/\r?\n/); buffer = lines.pop() || '';
    for (const line of lines) {
      current.push(line);
      if (/^\d{3} /.test(line)) { finishReply(current.join('\n')); current = []; }
    }
  });
  socket.on('error', failReaders);
  socket.on('close', () => { if (!closed) failReaders(new Error('Gmail SMTP cerró la conexión.')); });
  const readReply = () => replies.length ? Promise.resolve(replies.shift()) : new Promise((resolve, reject) => readers.push({ resolve, reject }));
  const expect = async codes => {
    const reply = await readReply();
    const code = Number(reply.slice(0, 3));
    if (!codes.includes(code)) throw new Error(`Gmail SMTP respondió ${code}: ${reply.split('\n').at(-1).slice(4)}`);
    return reply;
  };
  const command = async (value, codes) => { socket.write(`${value}\r\n`); return expect(codes); };
  try {
    await new Promise((resolve, reject) => { socket.once('secureConnect', resolve); socket.once('error', reject); });
    await expect([220]);
    await command('EHLO control-gastos', [250]);
    await command('AUTH LOGIN', [334]);
    await command(Buffer.from(from).toString('base64'), [334]);
    await command(Buffer.from(appPassword.replace(/\s/g, '')).toString('base64'), [235]);
    await command(`MAIL FROM:<${from}>`, [250]);
    await command(`RCPT TO:<${to}>`, [250, 251]);
    await command('DATA', [354]);
    const boundary = `cg-${randomBytes(12).toString('hex')}`;
    const encodedSubject = `=?UTF-8?B?${Buffer.from(subject).toString('base64')}?=`;
    const body = [
      `From: Control Gastos <${from}>`, `To: ${to}`, `Subject: ${encodedSubject}`, 'MIME-Version: 1.0',
      `Content-Type: multipart/alternative; boundary="${boundary}"`, '',
      `--${boundary}`, 'Content-Type: text/plain; charset=UTF-8', 'Content-Transfer-Encoding: base64', '',
      Buffer.from(text, 'utf8').toString('base64').match(/.{1,76}/g)?.join('\r\n') || '',
      `--${boundary}`, 'Content-Type: text/html; charset=UTF-8', 'Content-Transfer-Encoding: base64', '',
      Buffer.from(html, 'utf8').toString('base64').match(/.{1,76}/g)?.join('\r\n') || '',
      `--${boundary}--`, '',
    ].join('\r\n').replace(/(^|\r\n)\./g, '$1..');
    socket.write(`${body}\r\n.\r\n`);
    await expect([250]);
    await command('QUIT', [221]);
  } finally { socket.end(); }
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
  const gmailUser = process.env.GMAIL_USER, appPassword = process.env.GMAIL_APP_PASSWORD;
  if (!gmailUser || !appPassword) return response({ error: 'Falta configurar GMAIL_USER y GMAIL_APP_PASSWORD.' }, 503);
  const date = buenosAiresDate(), displayDate = `${date.slice(8, 10)}/${date.slice(5, 7)}/${date.slice(0, 4)}`, month = date.slice(0, 7), client = await db();
  const { rows: users } = await client.execute('SELECT id, email FROM users');
  let sent = 0, skipped = 0;
  for (const user of users) {
    const { rows } = await client.execute({ sql: "SELECT namespace, payload FROM user_data WHERE user_id = ? AND namespace IN ('services', 'cards', 'closings', 'expenses')", args: [user.id] });
    const data = Object.fromEntries(rows.map(row => [row.namespace, JSON.parse(row.payload)]));
    const services = (data.services || []).filter(service => service.status === 'No Pagado' && service.dueDate === date).map(service => ({ kind: 'Servicio', name: service.name, amount: Number(service.amount) || 0, detail: `Medio de pago: ${service.payment || 'Sin especificar'}` }));
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
    const html = `<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;color:#24352a"><img src="https://control-gastos-nu-eight.vercel.app/logoControlGastos.png" alt="Control Gastos" width="88" style="display:block;width:88px;height:auto;margin:0 0 18px"><h2>Vencimientos de hoy</h2><p>Hola ${escapeHtml(user.email)}, estos son tus pagos que vencen hoy (${displayDate}):</p><ul style="padding-left:20px">${htmlItems}</ul><p>Ingresá a Control Gastos para revisar tus vencimientos.</p></div>`;
    await sendGmail({ from: gmailUser, appPassword, to: user.email, subject: items.length === 1 ? `Vence hoy: ${items[0].name}` : `Tenés ${items.length} vencimientos hoy`, html, text: `Vencimientos de hoy (${displayDate}):\n\n${textItems}\n\nIngresá a Control Gastos para revisar tus vencimientos.` });
    await client.execute({ sql: 'INSERT INTO reminder_delivery(idempotency_key) VALUES(?) ON CONFLICT(idempotency_key) DO NOTHING', args: [idempotencyKey] });
    sent++;
  }
  return response({ ok: true, date, sent, skipped });
}

export async function handle(request) {
  const path = new URL(request.url).pathname.replace(/\/$/, '');
  const secure = new URL(request.url).protocol === 'https:';
  try {
    if (path === '/api/exchange-rate' && request.method === 'GET') return await exchangeRateHandler();
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
