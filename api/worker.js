// Gym Plan API: email + password accounts that store each person's plan.
// Passwords are hashed with PBKDF2 (100,000 rounds, random salt); sessions are
// random bearer tokens and only their SHA-256 hashes are stored.

const ORIGINS = ['https://stratusfs.github.io', 'http://localhost:5180'];
const SESSION_DAYS = 180;
const MAX_DATA = 256 * 1024;
const PBKDF2_ROUNDS = 100_000; // the maximum Workers allows

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');
    const cors = {
      'Access-Control-Allow-Origin': ORIGINS.includes(origin) ? origin : ORIGINS[0],
      'Access-Control-Allow-Headers': 'Authorization, Content-Type',
      'Access-Control-Allow-Methods': 'GET, PUT, POST',
      'Vary': 'Origin',
    };
    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });
    let res;
    try { res = await route(request, env); }
    catch (e) { console.error(e); res = json({ error: 'Something went wrong. Try again.' }, 500); }
    for (const [k, v] of Object.entries(cors)) res.headers.set(k, v);
    return res;
  },
};

async function route(request, env) {
  const path = new URL(request.url).pathname, method = request.method;
  if (method === 'POST' && path === '/signup') return signup(request, env);
  if (method === 'POST' && path === '/login') return login(request, env);
  if (method === 'POST' && path === '/logout') {
    const token = bearer(request);
    if (token) await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256(token)).run();
    return json({ ok: true });
  }
  if (path === '/data' && (method === 'GET' || method === 'PUT')) {
    const user = await userFor(request, env);
    if (!user) return json({ error: 'Please sign in again.' }, 401);
    if (method === 'GET') {
      const row = await env.DB.prepare('SELECT json, updated_at FROM data WHERE user_id = ?').bind(user).first();
      return json(row ? { data: JSON.parse(row.json), updated: row.updated_at } : { data: null, updated: 0 });
    }
    const text = await request.text();
    if (text.length > MAX_DATA) return json({ error: 'Your plan is too large to save.' }, 413);
    let data;
    try { data = JSON.parse(text); } catch { return json({ error: 'Bad data.' }, 400); }
    if (!data || typeof data.plan !== 'object' || typeof data.updated !== 'number') return json({ error: 'Bad data.' }, 400);
    await env.DB.prepare('INSERT INTO data (user_id, json, updated_at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET json = excluded.json, updated_at = excluded.updated_at')
      .bind(user, text, data.updated).run();
    return json({ ok: true });
  }
  return json({ error: 'Not found' }, 404);
}

// ---------- Accounts ----------

async function signup(request, env) {
  const c = await credentials(request);
  if (c.problem) return json({ error: c.problem }, 400);
  const ip = request.headers.get('CF-Connecting-IP') || 'local';
  const { n } = await env.DB.prepare('SELECT COUNT(*) AS n FROM users WHERE ip = ? AND created_at > ?').bind(ip, Date.now() - 3600_000).first();
  if (n >= 5) return json({ error: 'Too many new accounts from here. Try again in an hour.' }, 429);
  if (await env.DB.prepare('SELECT 1 FROM users WHERE email = ?').bind(c.email).first())
    return json({ error: 'There’s already an account with that email. Sign in instead.' }, 409);
  const id = crypto.randomUUID();
  await env.DB.prepare('INSERT INTO users (id, email, password_hash, created_at, ip) VALUES (?, ?, ?, ?, ?)')
    .bind(id, c.email, await hashPassword(c.password), Date.now(), ip).run();
  return newSession(env, id, c.email);
}

async function login(request, env) {
  const c = await credentials(request);
  if (c.problem) return json({ error: c.problem }, 400);
  const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(c.email).first();
  if (!user) return json({ error: 'Wrong email or password.' }, 401);
  if (user.locked_until > Date.now()) return json({ error: 'Too many wrong passwords. Try again in 15 minutes.' }, 429);
  if (!(await checkPassword(c.password, user.password_hash))) {
    // 10 wrong passwords locks the account for 15 minutes to stop guessing.
    const fails = user.fails + 1, lock = fails >= 10;
    await env.DB.prepare('UPDATE users SET fails = ?, locked_until = ? WHERE id = ?')
      .bind(lock ? 0 : fails, lock ? Date.now() + 15 * 60_000 : 0, user.id).run();
    return json({ error: 'Wrong email or password.' }, 401);
  }
  await env.DB.prepare('UPDATE users SET fails = 0 WHERE id = ?').bind(user.id).run();
  return newSession(env, user.id, user.email);
}

async function credentials(request) {
  let b;
  try { b = await request.json(); } catch {}
  const email = String(b?.email || '').trim().toLowerCase(), password = b?.password;
  if (email.length > 200 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return { problem: 'Enter a valid email address.' };
  if (typeof password !== 'string' || password.length < 8) return { problem: 'Passwords are at least 8 characters.' };
  if (password.length > 200) return { problem: 'That password is too long.' };
  return { email, password };
}

async function newSession(env, userId, email) {
  const token = randomToken();
  await env.DB.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(await sha256(token), userId, Date.now() + SESSION_DAYS * 86400_000).run();
  return json({ token, email });
}

const bearer = request => (request.headers.get('Authorization') || '').match(/^Bearer (\w+)$/)?.[1];

async function userFor(request, env) {
  const token = bearer(request);
  if (!token) return null;
  const row = await env.DB.prepare('SELECT user_id FROM sessions WHERE token_hash = ? AND expires_at > ?').bind(await sha256(token), Date.now()).first();
  return row?.user_id;
}

// ---------- Passwords (same scheme as AusIncidents) ----------

async function pbkdf2(password, salt, rounds) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: rounds }, key, 256));
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2$${PBKDF2_ROUNDS}$${b64url(salt)}$${b64url(await pbkdf2(password, salt, PBKDF2_ROUNDS))}`;
}

async function checkPassword(password, stored) {
  const [scheme, rounds, salt, hash] = String(stored || '').split('$');
  if (scheme !== 'pbkdf2') return false;
  const got = await pbkdf2(password, fromB64url(salt), +rounds), want = fromB64url(hash);
  if (got.length !== want.length) return false;
  let diff = 0;
  for (let i = 0; i < got.length; i++) diff |= got[i] ^ want[i]; // constant time
  return diff === 0;
}

// ---------- Helpers ----------

const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
const hex = bytes => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
const randomToken = () => hex(crypto.getRandomValues(new Uint8Array(32)));
const sha256 = async s => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))));
const b64url = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64url = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
