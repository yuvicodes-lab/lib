/* CrackLib Panel — Cloudflare Workers + D1 (single file)
 * Pages: / (landing+login), /register?ref=CODE, /{username}/ (user panel), /admin
 * Lib API: POST /api/validate  (protocol README/panel me) */

const LIB_KEY = 'MySecretKey2026_VIP';
const USER_SESS_DAYS = 30;
const ADMIN_SESS_HOURS = 12;

/* ---------------- bytes / hex / xor ---------------- */
function hexToBytes(h) {
  const a = new Uint8Array(h.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
  return a;
}
function bytesToHex(b) {
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}
function xorBytes(data, key) {
  const o = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) o[i] = data[i] ^ key[i % key.length];
  return o;
}
const te = new TextEncoder(), td = new TextDecoder();
function libDecrypt(hex) {
  try { return td.decode(xorBytes(hexToBytes(hex), te.encode(LIB_KEY))); }
  catch (e) { return ''; }
}
function libEncrypt(str) {
  return bytesToHex(xorBytes(te.encode(str), te.encode(LIB_KEY)));
}

/* ---------------- crypto ---------------- */
async function hmacHex(secret, msg) {
  const k = await crypto.subtle.importKey('raw', te.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const s = await crypto.subtle.sign('HMAC', k, te.encode(msg));
  return bytesToHex(new Uint8Array(s));
}
function safeEq(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
function randHex(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return bytesToHex(b);
}
async function hashPassword(pw, saltHex) {
  const km = await crypto.subtle.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: hexToBytes(saltHex), iterations: 100000 }, km, 256);
  return bytesToHex(new Uint8Array(bits));
}
function randRef() {
  const abc = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const b = new Uint8Array(6);
  crypto.getRandomValues(b);
  let s = '';
  for (let i = 0; i < 6; i++) s += abc[b[i] % abc.length];
  return s;
}

/* ---------------- cookies / sessions ---------------- */
function getCookies(req) {
  const h = req.headers.get('Cookie') || '';
  const o = {};
  h.split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return o;
}
async function makeSession(env, kind, id, ttlSec) {
  const exp = Math.floor(Date.now() / 1000) + ttlSec;
  const body = kind + '|' + id + '|' + exp;
  const sig = await hmacHex(env.SESSION_SECRET || 'change-me-in-production', body);
  return id + '.' + exp + '.' + sig;
}
async function checkSession(env, kind, val) {
  if (!val) return null;
  const p = val.split('.');
  if (p.length !== 3) return null;
  const exp = parseInt(p[1], 10);
  if (!exp || exp < Math.floor(Date.now() / 1000)) return null;
  const body = kind + '|' + p[0] + '|' + p[1];
  const sig = await hmacHex(env.SESSION_SECRET || 'change-me-in-production', body);
  if (!safeEq(sig, p[2])) return null;
  return p[0];
}
function cookieHeader(req, name, val, maxAge) {
  const secure = new URL(req.url).protocol === 'https:' ? '; Secure' : '';
  if (val === null) return name + '=; Path=/; Max-Age=0; HttpOnly' + secure + '; SameSite=Lax';
  return name + '=' + encodeURIComponent(val) + '; Path=/; Max-Age=' + maxAge + '; HttpOnly' + secure + '; SameSite=Lax';
}
function json(data, status, extraHeaders) {
  const h = Object.assign({ 'Content-Type': 'application/json' }, extraHeaders || {});
  return new Response(JSON.stringify(data), { status: status || 200, headers: h });
}
async function needUser(req, env) {
  const uid = await checkSession(env, 'u', getCookies(req).sess);
  if (!uid) return { err: json({ ok: false, error: 'login required' }, 401) };
  const u = await env.DB.prepare('SELECT id,name,username,ref_code,blocked,created_at FROM users WHERE id=?').bind(uid).first();
  if (!u || u.blocked) return { err: json({ ok: false, error: 'blocked' }, 403) };
  return { user: u };
}
async function needAdmin(req, env) {
  const a = await checkSession(env, 'a', getCookies(req).asess);
  if (a !== '1') return { err: json({ ok: false, error: 'admin login required' }, 401) };
  return {};
}
function nowSec() { return Math.floor(Date.now() / 1000); }

/* ================= API: public ================= */
async function apiRegister(req, env) {
  let b;
  try { b = await req.json(); } catch (e) { return json({ ok: false, error: 'bad json' }, 400); }
  const name = String(b.name || '').trim().slice(0, 40);
  let username = String(b.username || '').trim().toLowerCase().slice(0, 20);
  const password = String(b.password || '');
  const ref = String(b.ref || '').trim().toUpperCase().slice(0, 12);
  if (!name) return json({ ok: false, error: 'name required' }, 400);
  if (!/^[a-z0-9_]{3,20}$/.test(username)) return json({ ok: false, error: 'username: a-z 0-9 _ , 3-20 chars' }, 400);
  if (password.length < 4) return json({ ok: false, error: 'password min 4 chars' }, 400);
  const exists = await env.DB.prepare('SELECT id FROM users WHERE username=?').bind(username).first();
  if (exists) return json({ ok: false, error: 'username taken' }, 409);
  let referred_by = null;
  if (ref) {
    const r = await env.DB.prepare('SELECT id FROM users WHERE ref_code=?').bind(ref).first();
    if (!r) return json({ ok: false, error: 'invalid referral code' }, 400);
    referred_by = r.id;
  }
  let ref_code = randRef();
  for (let i = 0; i < 5; i++) {
    const c = await env.DB.prepare('SELECT id FROM users WHERE ref_code=?').bind(ref_code).first();
    if (!c) break;
    ref_code = randRef();
  }
  const salt = randHex(16);
  const hash = await hashPassword(password, salt);
  const ts = nowSec();
  const ins = await env.DB.prepare(
    'INSERT INTO users (name,username,pass_hash,pass_salt,ref_code,referred_by,blocked,created_at) VALUES (?,?,?,?,?,?,0,?)'
  ).bind(name, username, hash, salt, ref_code, referred_by, ts).run();
  const uid = ins.meta.last_row_id;
  await env.DB.prepare('INSERT OR IGNORE INTO user_urls (user_id,updated_at) VALUES (?,?)').bind(uid, ts).run();
  const sess = await makeSession(env, 'u', String(uid), USER_SESS_DAYS * 86400);
  return json({ ok: true, slug: username }, 200, { 'Set-Cookie': cookieHeader(req, 'sess', sess, USER_SESS_DAYS * 86400) });
}

async function apiLogin(req, env) {
  let b;
  try { b = await req.json(); } catch (e) { return json({ ok: false, error: 'bad json' }, 400); }
  const username = String(b.username || '').trim().toLowerCase();
  const password = String(b.password || '');
  const u = await env.DB.prepare('SELECT * FROM users WHERE username=?').bind(username).first();
  if (!u) return json({ ok: false, error: 'invalid login' }, 401);
  if (u.blocked) return json({ ok: false, error: 'account blocked' }, 403);
  const h = await hashPassword(password, u.pass_salt);
  if (!safeEq(h, u.pass_hash)) return json({ ok: false, error: 'invalid login' }, 401);
  const sess = await makeSession(env, 'u', String(u.id), USER_SESS_DAYS * 86400);
  return json({ ok: true, slug: u.username }, 200, { 'Set-Cookie': cookieHeader(req, 'sess', sess, USER_SESS_DAYS * 86400) });
}

/* ================= API: user ================= */
async function apiMe(req, env) {
  const n = await needUser(req, env);
  if (n.err) return n.err;
  const u = n.user;
  const row = await env.DB.prepare('SELECT panel_url,endpoints,target,refresh FROM user_urls WHERE user_id=?').bind(u.id).first() || {};
  const pkgs = await env.DB.prepare('SELECT pkg FROM pkgs WHERE user_id=? ORDER BY pkg').bind(u.id).all();
  const refd = await env.DB.prepare('SELECT username,created_at FROM users WHERE referred_by=? ORDER BY id DESC LIMIT 50').bind(u.id).all();
  const total = await env.DB.prepare('SELECT COUNT(*) c FROM hits WHERE user_id=?').bind(u.id).first();
  const day = nowSec() - 86400;
  const today = await env.DB.prepare('SELECT COUNT(*) c FROM hits WHERE user_id=? AND created_at>?').bind(u.id, day).first();
  const hits = await env.DB.prepare('SELECT pkg,ip,created_at FROM hits WHERE user_id=? ORDER BY id DESC LIMIT 20').bind(u.id).all();
  return json({
    ok: true,
    user: { name: u.name, username: u.username, ref_code: u.ref_code, created_at: u.created_at },
    url: row.panel_url || '', endpoints: row.endpoints || '[]', target: row.target || '', refresh: row.refresh || 300,
    pkgs: (pkgs.results || []).map(r => r.pkg),
    stats: { referred: (refd.results || []).length, hits_total: (total && total.c) || 0, hits_day: (today && today.c) || 0 },
    referred: refd.results || [], hits: hits.results || []
  });
}

function normUrl(s) {
  s = String(s || '').trim();
  s = s.replace(/^https?:\/\//i, '').replace(/\/+$/, '');
  return s.slice(0, 200);
}
async function apiMyUrl(req, env) {
  const n = await needUser(req, env);
  if (n.err) return n.err;
  let b;
  try { b = await req.json(); } catch (e) { return json({ ok: false, error: 'bad json' }, 400); }
  const url = normUrl(b.url);
  let eps = b.endpoints;
  if (typeof eps === 'string') eps = eps.split(',');
  eps = (Array.isArray(eps) ? eps : []).map(s => String(s).trim()).filter(s => s && s.length < 80).slice(0, 20);
  if (!eps.length) eps = ['/connect', '/server', '/api/verify', '/api.php', '/api/license'];
  let pkgs = b.pkgs;
  if (typeof pkgs === 'string') pkgs = pkgs.split(',');
  pkgs = (Array.isArray(pkgs) ? pkgs : []).map(s => String(s).trim()).filter(s => /^[A-Za-z0-9_.]{3,120}$/.test(s)).slice(0, 20);
  for (const p of pkgs) {
    const c = await env.DB.prepare('SELECT user_id FROM pkgs WHERE pkg=?').bind(p).first();
    if (c && c.user_id !== n.user.id) return json({ ok: false, error: 'pkg claimed by another user: ' + p }, 409);
  }
  const ts = nowSec();
  await env.DB.prepare('INSERT INTO user_urls (user_id,panel_url,endpoints,target,refresh,updated_at) VALUES (?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET panel_url=excluded.panel_url,endpoints=excluded.endpoints,updated_at=excluded.updated_at')
    .bind(n.user.id, url, JSON.stringify(eps), '', 300, ts).run();
  const old = await env.DB.prepare('SELECT pkg FROM pkgs WHERE user_id=?').bind(n.user.id).all();
  const oldSet = new Set((old.results || []).map(r => r.pkg));
  for (const p of (old.results || []).map(r => r.pkg)) {
    if (pkgs.indexOf(p) < 0) await env.DB.prepare('DELETE FROM pkgs WHERE pkg=?').bind(p).run();
  }
  for (const p of pkgs) {
    if (!oldSet.has(p)) await env.DB.prepare('INSERT OR IGNORE INTO pkgs (pkg,user_id,created_at) VALUES (?,?,?)').bind(p, n.user.id, ts).run();
  }
  return json({ ok: true });
}

async function apiMyHits(req, env) {
  const n = await needUser(req, env);
  if (n.err) return n.err;
  const url = new URL(req.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10) || 50, 200);
  const hits = await env.DB.prepare('SELECT pkg,ip,created_at FROM hits WHERE user_id=? ORDER BY id DESC LIMIT ?').bind(n.user.id, limit).all();
  return json({ ok: true, hits: hits.results || [] });
}

/* ================= API: lib validate ================= */
async function apiValidate(req, env, ctx) {
  let dataHex = '';
  try {
    const ct = req.headers.get('Content-Type') || '';
    if (ct.indexOf('application/json') >= 0) {
      const j = await req.json();
      dataHex = String(j.data || '');
    } else {
      const fd = await req.formData();
      dataHex = String(fd.get('data') || '');
      if (!dataHex) {
        const t = await req.text();
        const m = t.match(/data=([0-9a-fA-F]+)/);
        dataHex = m ? m[1] : t.trim();
      }
    }
  } catch (e) { return new Response(libEncrypt(JSON.stringify({ status: false })), { headers: { 'Content-Type': 'text/plain' } }); }
  const deny = () => new Response(libEncrypt(JSON.stringify({ status: false })), { headers: { 'Content-Type': 'text/plain' } });
  const plain = libDecrypt(dataHex.replace(/\s+/g, ''));
  const parts = plain.split('|');
  if (parts.length < 1 || !parts[0]) return deny();
  const pkg = parts[0].slice(0, 160);
  const ip = req.headers.get('CF-Connecting-IP') || '';
  const ts = nowSec();
  const claim = await env.DB.prepare('SELECT user_id FROM pkgs WHERE pkg=?').bind(pkg).first();
  let uid = claim ? claim.user_id : null;
  let cfg = { status: true, url: '', endpoints: [], target: '', refresh: 300, mode: 'log' };
  if (uid) {
    const u = await env.DB.prepare('SELECT blocked FROM users WHERE id=?').bind(uid).first();
    const row = await env.DB.prepare('SELECT panel_url,endpoints,target,refresh FROM user_urls WHERE user_id=?').bind(uid).first();
    if (!u || u.blocked || !row || !row.panel_url) {
      ctx.waitUntil(env.DB.prepare('INSERT INTO hits (user_id,pkg,ip,created_at) VALUES (?,?,?,?)').bind(uid, pkg, ip, ts).run().catch(() => {}));
      return deny();
    }
    let eps = [];
    try { eps = JSON.parse(row.endpoints || '[]'); } catch (e) { eps = []; }
    cfg = { status: true, url: row.panel_url, endpoints: eps, target: row.target || '', refresh: row.refresh || 300, mode: 'replace' };
  }
  ctx.waitUntil(env.DB.prepare('INSERT INTO hits (user_id,pkg,ip,created_at) VALUES (?,?,?,?)').bind(uid, pkg, ip, ts).run().catch(() => {}));
  return new Response(libEncrypt(JSON.stringify(cfg)), { headers: { 'Content-Type': 'text/plain' } });
}

/* ================= API: admin ================= */
async function apiAdminLogin(req, env) {
  let b;
  try { b = await req.json(); } catch (e) { return json({ ok: false, error: 'bad json' }, 400); }
  const u = String(b.username || ''), p = String(b.password || '');
  const uh = await hmacHex('admin-local', u), eh = await hmacHex('admin-local', env.ADMIN_USER || '');
  const ph = await hmacHex('admin-local', p), eph = await hmacHex('admin-local', env.ADMIN_PASS || '');
  if (!env.ADMIN_USER || !safeEq(uh, eh) || !safeEq(ph, eph)) return json({ ok: false, error: 'invalid admin login' }, 401);
  const sess = await makeSession(env, 'a', '1', ADMIN_SESS_HOURS * 3600);
  return json({ ok: true }, 200, { 'Set-Cookie': cookieHeader(req, 'asess', sess, ADMIN_SESS_HOURS * 3600) });
}
async function apiAdminStats(req, env) {
  const n = await needAdmin(req, env);
  if (n.err) return n.err;
  const day = nowSec() - 86400;
  const [tu, tb, tr, hd, un] = await Promise.all([
    env.DB.prepare('SELECT COUNT(*) c FROM users').first(),
    env.DB.prepare('SELECT COUNT(*) c FROM users WHERE blocked=1').first(),
    env.DB.prepare('SELECT COUNT(*) c FROM users WHERE referred_by IS NOT NULL AND referred_by != 0').first(),
    env.DB.prepare('SELECT COUNT(*) c FROM hits WHERE created_at>?').bind(day).first(),
    env.DB.prepare('SELECT COUNT(DISTINCT pkg) c FROM hits WHERE user_id IS NULL').first()
  ]);
  return json({ ok: true, users: (tu && tu.c) || 0, blocked: (tb && tb.c) || 0, referred: (tr && tr.c) || 0, hits_day: (hd && hd.c) || 0, unclaimed: (un && un.c) || 0 });
}
async function apiAdminUsers(req, env) {
  const n = await needAdmin(req, env);
  if (n.err) return n.err;
  const q = '%' + (new URL(req.url).searchParams.get('q') || '').trim() + '%';
  const rows = await env.DB.prepare(
    'SELECT u.id,u.name,u.username,u.ref_code,u.blocked,u.created_at,uu.panel_url,uu.endpoints, (SELECT GROUP_CONCAT(pkg) FROM pkgs WHERE user_id=u.id) pkgs, (SELECT COUNT(*) FROM users r WHERE r.referred_by=u.id) ref_count, (SELECT COUNT(*) FROM hits h WHERE h.user_id=u.id) hits FROM users u LEFT JOIN user_urls uu ON uu.user_id=u.id WHERE u.username LIKE ? OR u.name LIKE ? ORDER BY u.id DESC LIMIT 200'
  ).bind(q, q).all();
  return json({ ok: true, users: rows.results || [] });
}
async function apiAdminUserUpdate(req, env) {
  const n = await needAdmin(req, env);
  if (n.err) return n.err;
  let b;
  try { b = await req.json(); } catch (e) { return json({ ok: false, error: 'bad json' }, 400); }
  const id = parseInt(b.id, 10);
  if (!id) return json({ ok: false, error: 'bad id' }, 400);
  if (b.delete) {
    await env.DB.prepare('DELETE FROM users WHERE id=?').bind(id).run();
    return json({ ok: true });
  }
  if (typeof b.blocked !== 'undefined') {
    await env.DB.prepare('UPDATE users SET blocked=? WHERE id=?').bind(b.blocked ? 1 : 0, id).run();
  }
  if (typeof b.url !== 'undefined' || typeof b.endpoints !== 'undefined' || typeof b.target !== 'undefined') {
    const cur = await env.DB.prepare('SELECT panel_url,endpoints,target,refresh FROM user_urls WHERE user_id=?').bind(id).first() || { panel_url: '', endpoints: '[]', target: '', refresh: 300 };
    const url = typeof b.url !== 'undefined' ? normUrlAdmin(b.url) : cur.panel_url;
    let eps = cur.endpoints;
    if (typeof b.endpoints !== 'undefined') {
      const arr = (Array.isArray(b.endpoints) ? b.endpoints : String(b.endpoints).split(',')).map(s => String(s).trim()).filter(s => s).slice(0, 20);
      eps = JSON.stringify(arr.length ? arr : ['/connect']);
    }
    const tgt = typeof b.target !== 'undefined' ? String(b.target || '').slice(0, 120) : cur.target;
    await env.DB.prepare('INSERT INTO user_urls (user_id,panel_url,endpoints,target,refresh,updated_at) VALUES (?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET panel_url=excluded.panel_url,endpoints=excluded.endpoints,target=excluded.target,updated_at=excluded.updated_at')
      .bind(id, url, eps, tgt, 300, nowSec()).run();
  }
  if (Array.isArray(b.pkgs)) {
    const pkgs = b.pkgs.map(s => String(s).trim()).filter(s => /^[A-Za-z0-9_.]{3,120}$/.test(s)).slice(0, 20);
    const ts = nowSec();
    await env.DB.prepare('DELETE FROM pkgs WHERE user_id=?').bind(id).run();
    for (const p of pkgs) {
      await env.DB.prepare('INSERT INTO pkgs (pkg,user_id,created_at) VALUES (?,?,?) ON CONFLICT(pkg) DO UPDATE SET user_id=excluded.user_id').bind(p, id, ts).run();
    }
    await env.DB.prepare('UPDATE hits SET user_id=? WHERE pkg IN (SELECT pkg FROM pkgs WHERE user_id=?) AND user_id IS NULL').bind(id, id).run();
  }
  return json({ ok: true });
}
function normUrlAdmin(s) {
  s = String(s || '').trim().replace(/^https?:\/\//i, '').replace(/\/+$/, '');
  return s.slice(0, 200);
}
async function apiAdminHits(req, env) {
  const n = await needAdmin(req, env);
  if (n.err) return n.err;
  const url = new URL(req.url);
  const uid = parseInt(url.searchParams.get('user') || '0', 10) || 0;
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10) || 50, 200);
  let rows;
  if (uid) rows = await env.DB.prepare('SELECT h.pkg,h.ip,h.created_at,u.username FROM hits h LEFT JOIN users u ON u.id=h.user_id WHERE h.user_id=? ORDER BY h.id DESC LIMIT ?').bind(uid, limit).all();
  else rows = await env.DB.prepare('SELECT h.pkg,h.ip,h.created_at,u.username FROM hits h LEFT JOIN users u ON u.id=h.user_id ORDER BY h.id DESC LIMIT ?').bind(limit).all();
  return json({ ok: true, hits: rows.results || [] });
}
async function apiAdminUnclaimed(req, env) {
  const n = await needAdmin(req, env);
  if (n.err) return n.err;
  const rows = await env.DB.prepare('SELECT pkg,COUNT(*) c,MAX(created_at) last_seen FROM hits WHERE user_id IS NULL GROUP BY pkg ORDER BY last_seen DESC LIMIT 100').all();
  return json({ ok: true, pkgs: rows.results || [] });
}
async function apiAdminAssign(req, env) {
  const n = await needAdmin(req, env);
  if (n.err) return n.err;
  let b;
  try { b = await req.json(); } catch (e) { return json({ ok: false, error: 'bad json' }, 400); }
  const pkg = String(b.pkg || '').trim();
  const user_id = parseInt(b.user_id, 10);
  if (!/^[A-Za-z0-9_.]{3,120}$/.test(pkg) || !user_id) return json({ ok: false, error: 'bad input' }, 400);
  const u = await env.DB.prepare('SELECT id FROM users WHERE id=?').bind(user_id).first();
  if (!u) return json({ ok: false, error: 'user not found' }, 404);
  await env.DB.prepare('INSERT INTO pkgs (pkg,user_id,created_at) VALUES (?,?,?) ON CONFLICT(pkg) DO UPDATE SET user_id=excluded.user_id').bind(pkg, user_id, nowSec()).run();
  await env.DB.prepare('UPDATE hits SET user_id=? WHERE pkg=? AND user_id IS NULL').bind(user_id, pkg).run();
  return json({ ok: true });
}

/* ================= UI ================= */
const CSS = `
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg1:#070b18;--bg2:#101736;--acc:#7c5cff;--acc2:#00e0c6;--txt:#eef1ff;--mut:#9aa3c7;--glass:rgba(255,255,255,.06);--brd:rgba(255,255,255,.13);--danger:#ff5d7a;--ok:#2fe08c}
body{font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;color:var(--txt);background:radial-gradient(1200px 600px at 80% -10%,#2a1e63 0%,transparent 60%),radial-gradient(900px 500px at -10% 20%,#063b3f 0%,transparent 55%),linear-gradient(180deg,var(--bg1),var(--bg2));min-height:100vh}
a{color:var(--acc2);text-decoration:none}
header{position:sticky;top:0;z-index:50;display:flex;align-items:center;gap:12px;padding:12px 16px;background:rgba(10,14,30,.72);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);border-bottom:1px solid var(--brd)}
.logo{font-weight:800;font-size:18px;letter-spacing:.5px;background:linear-gradient(90deg,var(--acc),var(--acc2));-webkit-background-clip:text;background-clip:text;color:transparent}
.burger{background:var(--glass);border:1px solid var(--brd);color:var(--txt);font-size:18px;border-radius:12px;padding:8px 12px;cursor:pointer}
.hsp{flex:1}
.chip{font-size:12px;color:var(--mut);background:var(--glass);border:1px solid var(--brd);padding:6px 10px;border-radius:999px;max-width:46vw;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.btn{border:0;cursor:pointer;color:#fff;font-weight:700;border-radius:14px;padding:12px 16px;background:linear-gradient(135deg,var(--acc),#4a2bd8);box-shadow:0 8px 24px rgba(124,92,255,.35);font-size:15px;width:100%}
.btn.ghost{background:var(--glass);border:1px solid var(--brd);box-shadow:none}
.btn.small{width:auto;padding:8px 12px;font-size:13px;border-radius:10px}
.btn.danger{background:linear-gradient(135deg,#ff5d7a,#c2254d);box-shadow:0 8px 24px rgba(255,93,122,.3)}
.btn.ok{background:linear-gradient(135deg,#12b76a,#0a7a47);box-shadow:none}
#ov{position:fixed;inset:0;background:rgba(0,0,0,.55);opacity:0;pointer-events:none;transition:.25s;z-index:60}
#ov.on{opacity:1;pointer-events:auto}
aside{position:fixed;top:0;left:0;bottom:0;width:262px;z-index:70;padding:18px 14px;background:rgba(13,18,38,.92);backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px);border-right:1px solid var(--brd);transform:translateX(-105%);transition:.28s;overflow-y:auto}
aside.open{transform:none}
aside .logo{font-size:20px;margin:4px 8px 16px}
aside a.nl{display:flex;align-items:center;gap:10px;padding:12px;border-radius:14px;color:var(--txt);font-weight:600;font-size:15px;margin-bottom:4px}
aside a.nl.on,aside a.nl:active{background:linear-gradient(135deg,rgba(124,92,255,.35),rgba(0,224,198,.18));border:1px solid var(--brd)}
main{padding:16px;max-width:1060px;margin:0 auto;padding-bottom:60px}
.grid{display:grid;gap:12px;grid-template-columns:1fr 1fr}
.card{background:var(--glass);border:1px solid var(--brd);border-radius:20px;padding:16px;backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);box-shadow:0 12px 40px rgba(0,0,0,.35)}
.card h3{font-size:14px;color:var(--mut);font-weight:700;margin-bottom:8px;text-transform:uppercase;letter-spacing:.6px}
.big{font-size:24px;font-weight:800}
.mut{color:var(--mut);font-size:13px}
.row{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
label{display:block;font-size:13px;color:var(--mut);margin:12px 0 6px;font-weight:600}
input,textarea,select{width:100%;background:rgba(0,0,0,.35);border:1px solid var(--brd);color:var(--txt);border-radius:12px;padding:12px;font-size:15px;outline:none}
input:focus,textarea:focus{border-color:var(--acc)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--brd);vertical-align:top}
th{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
.twrap{overflow-x:auto;margin:0 -4px;padding:0 4px}
.pill{display:inline-block;font-size:11px;font-weight:800;padding:3px 9px;border-radius:999px;background:rgba(47,224,140,.15);color:var(--ok);border:1px solid rgba(47,224,140,.4)}
.pill.off{background:rgba(255,93,122,.13);color:var(--danger);border-color:rgba(255,93,122,.4)}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}
.hero{text-align:center;padding:34px 16px 10px}
.hero h1{font-size:30px;font-weight:900;line-height:1.15}
.hero h1 span{background:linear-gradient(90deg,var(--acc),var(--acc2));-webkit-background-clip:text;background-clip:text;color:transparent}
.hero p{color:var(--mut);margin-top:10px;font-size:14px}
.center{max-width:440px;margin:14px auto}
#toast{position:fixed;left:50%;transform:translateX(-50%) translateY(20px);bottom:22px;z-index:99;background:rgba(10,14,30,.95);border:1px solid var(--brd);padding:12px 18px;border-radius:14px;font-size:14px;opacity:0;transition:.25s;pointer-events:none;max-width:92vw}
#toast.on{opacity:1;transform:translateX(-50%)}
#toast.err{border-color:var(--danger)}
.foot{text-align:center;color:var(--mut);font-size:12px;padding:26px 0 10px}
@media(min-width:960px){aside{transform:none}main{margin-left:262px} .burger{display:none} .grid{grid-template-columns:repeat(4,1fr)} .grid.g2{grid-template-columns:1fr 1fr}}
`;
function esc(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function shell(title, nav, active, content, script, chip) {
  const navHtml = nav.map(n => '<a class="nl' + (n.k === active ? ' on' : '') + '" href="' + n.h + '">' + n.t + '</a>').join('');
  return '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<title>' + esc(title) + ' — CrackLib</title><style>' + CSS + '</style></head><body>'
    + '<header><button class="burger" onclick="document.querySelector(\'aside\').classList.add(\'open\');document.getElementById(\'ov\').classList.add(\'on\')">☰</button>'
    + '<div class="logo">⬢ CrackLib</div><div class="hsp"></div>'
    + (chip ? '<div class="chip">' + esc(chip) + '</div>' : '') + '</header>'
    + '<div id="ov" onclick="this.classList.remove(\'on\');document.querySelector(\'aside\').classList.remove(\'open\')"></div>'
    + '<aside><div class="logo">⬢ CrackLib</div>' + navHtml + '</aside>'
    + '<main>' + content + '<div class="foot">CrackLib Panel • glass UI</div></main>'
    + '<div id="toast"></div>'
    + '<script>function toast(m,err){var t=document.getElementById("toast");t.textContent=m;t.className=err?"on err":"on";clearTimeout(t._x);t._x=setTimeout(function(){t.className=""},2600)}'
    + 'async function api(u,m,b){var r=await fetch(u,{method:m||"GET",headers:{"Content-Type":"application/json"},body:b?JSON.stringify(b):undefined});var j=null;try{j=await r.json()}catch(e){}return{j:j,s:r.status}}'
    + 'function copyT(id){var e=document.getElementById(id);e.select();e.setSelectionRange(0,99999);try{document.execCommand("copy")}catch(x){}if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(e.value).catch(function(){})}toast("copied")}'
    + (script || '') + '</script></body></html>';
}
const NAV_GUEST = [{ k: 'home', t: '🏠 Home', h: '/' }, { k: 'reg', t: '📝 Register', h: '/register' }, { k: 'adm', t: '🛡 Admin', h: '/admin' }];
function userNav(slug) {
  return [{ k: 'dash', t: '📊 Dashboard', h: '/' + slug + '/' }, { k: 'hits', t: '📡 Hits', h: '/' + slug + '/hits' }, { k: 'out', t: '🚪 Logout', h: '/logout' }];
}
const NAV_ADMIN = [{ k: 'dash', t: '📊 Overview', h: '/admin' }, { k: 'users', t: '👥 Users', h: '/admin/users' }, { k: 'uncl', t: '📦 Unclaimed PKGs', h: '/admin/unclaimed' }, { k: 'hits', t: '📡 Hits', h: '/admin/hits' }, { k: 'out', t: '🚪 Logout', h: '/admin/logout' }];

function pageLanding() {
  const c = '<div class="hero"><h1>One lib.<br><span>Every user. Every game.</span></h1>'
    + '<p>Register → apna URL + package set karo → same lib use karo. Server khud pehchan lega.</p></div>'
    + '<div class="center"><div class="card"><h3>Login</h3>'
    + '<label>Username</label><input id="l_u" autocomplete="username">'
    + '<label>Password</label><input id="l_p" type="password" autocomplete="current-password">'
    + '<div class="row"><button class="btn" onclick="doLogin()">Login</button></div>'
    + '<div class="row"><a class="btn ghost btn" style="text-align:center" href="/register">Create account</a></div>'
    + '</div></div>';
  const s = 'async function doLogin(){var u=document.getElementById("l_u").value.trim().toLowerCase(),p=document.getElementById("l_p").value;'
    + 'if(!u||!p){toast("fill all fields",1);return}var r=await api("/api/login","POST",{username:u,password:p});'
    + 'if(r.j&&r.j.ok){location.href="/"+r.j.slug+"/"}else toast((r.j&&r.j.error)||"login failed",1)}';
  return shell('Home', NAV_GUEST, 'home', c, s, '');
}

function pageRegister() {
  const c = '<div class="center"><div class="card"><h3>📝 Register</h3>'
    + '<label>Name</label><input id="r_n" placeholder="Your name">'
    + '<label>Username (panel url: domain.com/<b>username</b>/)</label><input id="r_u" placeholder="a-z 0-9 _">'
    + '<label>Password</label><input id="r_p" type="password">'
    + '<label>Referral code (auto-filled)</label><input id="r_r" placeholder="optional">'
    + '<div class="row"><button class="btn" onclick="doReg()">Register & open my panel</button></div>'
    + '<p class="mut" style="margin-top:10px">Already have an account? <a href="/">Login</a></p>'
    + '</div></div>';
  const s = '(function(){var m=location.search.match(/[?&]ref=([A-Za-z0-9]+)/);if(m){document.getElementById("r_r").value=m[1].toUpperCase()}})();'
    + 'async function doReg(){var b={name:document.getElementById("r_n").value,password:document.getElementById("r_p").value,username:document.getElementById("r_u").value.trim().toLowerCase(),ref:document.getElementById("r_r").value.trim()};'
    + 'var r=await api("/api/register","POST",b);if(r.j&&r.j.ok){location.href="/"+r.j.slug+"/"}else toast((r.j&&r.j.error)||"register failed",1)}';
  return shell('Register', NAV_GUEST, 'reg', c, s, '');
}

function pageUserDash(slug) {
  const c = '<div class="grid" id="stats"></div>'
    + '<div class="card" style="margin-top:12px"><h3>🔗 My Replace URL</h3>'
    + '<p class="mut">Sirf domain+prefix likho (https:// mat lagao). Example: <span class="mono">vippanel.fun/fuck</span></p>'
    + '<label>URL</label><input id="f_url" placeholder="yourdomain.com/prefix">'
    + '<label>Packages (comma separated)</label><input id="f_pkgs" placeholder="com.game.one, com.game.two">'
    + '<label>Endpoints (comma separated)</label><input id="f_eps" placeholder="/connect, /server, /api/verify">'
    + '<div class="row"><button class="btn" onclick="saveUrl()">Save</button></div></div>'
    + '<div class="card" style="margin-top:12px"><h3>🎁 My referral</h3><div id="refbox"></div></div>'
    + '<div class="card" style="margin-top:12px"><h3>📡 Recent hits</h3><div class="twrap"><table><thead><tr><th>Package</th><th>IP</th><th>Time</th></tr></thead><tbody id="hits"></tbody></table></div></div>';
  const s = 'var ME=null;function dt(t){var d=new Date(t*1000);return d.toLocaleString()}'
    + 'async function load(){var r=await api("/api/me");if(!r.j||!r.j.ok){location.href="/";return}ME=r.j;'
    + 'document.getElementById("f_url").value=r.j.url||"";document.getElementById("f_pkgs").value=(r.j.pkgs||[]).join(", ");'
    + 'try{document.getElementById("f_eps").value=JSON.parse(r.j.endpoints||"[]").join(", ")}catch(e){}'
    + 'document.getElementById("stats").innerHTML="<div class=card><h3>Status</h3><div class=big>"+(r.j.url?"<span class=pill>ACTIVE</span>":"<span class=\'pill off\'>NO URL</span>")+"</div></div>"+"<div class=card><h3>Hits (24h)</h3><div class=big>"+r.j.stats.hits_day+"</div></div>"+"<div class=card><h3>Total hits</h3><div class=big>"+r.j.stats.hits_total+"</div></div>"+"<div class=card><h3>Referrals</h3><div class=big>"+r.j.stats.referred+"</div></div>";'
    + 'var link=location.origin+"/register?ref="+r.j.user.ref_code;'
    + 'document.getElementById("refbox").innerHTML="<p class=mut>Code: <b>"+r.j.user.ref_code+"</b></p><label>Referral link</label><input id=refLink readonly value=\'"+link+"\'>"+"<div class=row><button class=\'btn small\' onclick=copyT(\\"refLink\\")>Copy link</button></div>";'
    + 'document.getElementById("hits").innerHTML=(r.j.hits||[]).map(function(h){return "<tr><td class=mono>"+h.pkg+"</td><td class=mono>"+(h.ip||"-")+"</td><td>"+dt(h.created_at)+"</td></tr>"}).join("")||"<tr><td colspan=3 class=mut>no hits yet</td></tr>"}'
    + 'async function saveUrl(){var r=await api("/api/my-url","POST",{url:document.getElementById("f_url").value,pkgs:document.getElementById("f_pkgs").value,endpoints:document.getElementById("f_eps").value});'
    + 'if(r.j&&r.j.ok){toast("saved");load()}else toast((r.j&&r.j.error)||"save failed",1)}load()';
  return shell(slug, userNav(slug), 'dash', c, s, slug);
}

function pageUserHits(slug) {
  const c = '<div class="card"><h3>📡 All hits</h3><div class="twrap"><table><thead><tr><th>Package</th><th>IP</th><th>Time</th></tr></thead><tbody id="hits"></tbody></table></div></div>';
  const s = 'async function load(){var r=await api("/api/my-hits?limit=200");if(!r.j||!r.j.ok){location.href="/";return}'
    + 'document.getElementById("hits").innerHTML=(r.j.hits||[]).map(function(h){var d=new Date(h.created_at*1000);return "<tr><td class=mono>"+h.pkg+"</td><td class=mono>"+(h.ip||"-")+"</td><td>"+d.toLocaleString()+"</td></tr>"}).join("")}load()';
  return shell(slug, userNav(slug), 'hits', c, s, slug);
}

function pageAdminLogin() {
  const c = '<div class="center"><div class="card"><h3>🛡 Admin login</h3>'
    + '<label>Username</label><input id="a_u"><label>Password</label><input id="a_p" type="password">'
    + '<div class="row"><button class="btn" onclick="aLogin()">Login</button></div></div></div>';
  const s = 'async function aLogin(){var r=await api("/api/admin/login","POST",{username:document.getElementById("a_u").value,password:document.getElementById("a_p").value});'
    + 'if(r.j&&r.j.ok){location.href="/admin"}else toast("invalid login",1)}';
  return shell('Admin', NAV_ADMIN, 'dash', c, s, 'admin');
}

function pageAdminDash() {
  const c = '<div class="grid" id="stats"></div>'
    + '<div class="card" style="margin-top:12px"><h3>👥 Users</h3>'
    + '<div class="row"><input id="q" placeholder="search username / name" style="flex:1;min-width:180px"><button class="btn small" onclick="loadUsers()">Search</button></div>'
    + '<div class="twrap" style="margin-top:8px"><table><thead><tr><th>User</th><th>URL / PKGs</th><th>Stats</th><th>Action</th></tr></thead><tbody id="users"></tbody></table></div></div>';
  const s = 'function dt(t){return new Date(t*1000).toLocaleString()}'
    + 'async function load(){var r=await api("/api/admin/stats");if(!r.j||!r.j.ok){location.href="/admin";return}'
    + 'document.getElementById("stats").innerHTML="<div class=card><h3>Users</h3><div class=big>"+r.j.users+"</div></div>"+"<div class=card><h3>Blocked</h3><div class=big>"+r.j.blocked+"</div></div>"+"<div class=card><h3>Hits 24h</h3><div class=big>"+r.j.hits_day+"</div></div>"+"<div class=card><h3>Unclaimed</h3><div class=big>"+r.j.unclaimed+"</div></div>";loadUsers()}'
    + 'async function loadUsers(){var q=document.getElementById("q").value;var r=await api("/api/admin/users?q="+encodeURIComponent(q));if(!r.j||!r.j.ok)return;'
    + 'document.getElementById("users").innerHTML=r.j.users.map(function(u){return "<tr><td><b>"+u.username+"</b><br><span class=mut>"+u.name+" • ref "+u.ref_code+"</span><br>"+(u.blocked?"<span class=\'pill off\'>BLOCKED</span>":"<span class=pill>OK</span>")+"</td>"+"<td><input id=url_"+u.id+" value=\'"+(u.panel_url||"").replace(/\'/g,"")+"\' placeholder=url style=\'margin-bottom:6px\'><input id=pkgs_"+u.id+" value=\'"+(u.pkgs||"")+"\' placeholder=pkgs></td>"+"<td class=mut>ref:"+u.ref_count+"<br>hits:"+u.hits+"</td>"+"<td><div class=row><button class=\'btn small\' onclick=saveU("+u.id+")>Save</button>"+(u.blocked?"<button class=\'btn small ok\' onclick=blk("+u.id+",0)>Unblock</button>":"<button class=\'btn small danger\' onclick=blk("+u.id+",1)>Block</button>")+"<button class=\'btn small danger\' onclick=delU("+u.id+",\'"+u.username+"\')>Del</button></div></td></tr>"}).join("")}'
    + 'async function saveU(id){var r=await api("/api/admin/user","POST",{id:id,url:document.getElementById("url_"+id).value,pkgs:document.getElementById("pkgs_"+id).value.split(",")});if(r.j&&r.j.ok){toast("saved");loadUsers()}else toast("save failed",1)}'
    + 'async function blk(id,v){var r=await api("/api/admin/user","POST",{id:id,blocked:v});if(r.j&&r.j.ok){loadUsers()}else toast("failed",1)}'
    + 'async function delU(id,n){if(!confirm("delete "+n+"?"))return;var r=await api("/api/admin/user","POST",{id:id,delete:1});if(r.j&&r.j.ok){loadUsers()}else toast("failed",1)}load()';
  return shell('Admin', NAV_ADMIN, 'dash', c, s, 'admin');
}

function pageAdminUsers() { return pageAdminDash(); }

function pageAdminUnclaimed() {
  const c = '<div class="card"><h3>📦 Unclaimed PKGs</h3><p class="mut">Ye packages lib ne bheje par kisi user se jude nahi. User id daal ke assign karo.</p>'
    + '<div class="twrap" style="margin-top:8px"><table><thead><tr><th>Package</th><th>Hits</th><th>Last seen</th><th>Assign to user id</th></tr></thead><tbody id="rows"></tbody></table></div></div>';
  const s = 'async function load(){var r=await api("/api/admin/unclaimed");if(!r.j||!r.j.ok){location.href="/admin";return}'
    + 'document.getElementById("rows").innerHTML=(r.j.pkgs||[]).map(function(p,i){return "<tr><td class=mono>"+p.pkg+"</td><td>"+p.c+"</td><td>"+new Date(p.last_seen*1000).toLocaleString()+"</td>"+"<td><div class=row><input id=au_"+i+" placeholder=\'user id\' style=\'max-width:110px\'><button class=\'btn small\' onclick=assign(\\""+p.pkg+"\\","+i+")>Assign</button></div></td></tr>"}).join("")||"<tr><td colspan=4 class=mut>none</td></tr>"}'
    + 'async function assign(pkg,i){var v=document.getElementById("au_"+i).value;var r=await api("/api/admin/assign","POST",{pkg:pkg,user_id:parseInt(v,10)});if(r.j&&r.j.ok){toast("assigned");load()}else toast((r.j&&r.j.error)||"failed",1)}load()';
  return shell('Admin', NAV_ADMIN, 'uncl', c, s, 'admin');
}

function pageAdminHits() {
  const c = '<div class="card"><h3>📡 Hits</h3>'
    + '<div class="row"><input id="f_u" placeholder="filter user id (empty=all)" style="flex:1;min-width:160px"><button class="btn small" onclick="load()">Load</button></div>'
    + '<div class="twrap" style="margin-top:8px"><table><thead><tr><th>User</th><th>Package</th><th>IP</th><th>Time</th></tr></thead><tbody id="rows"></tbody></table></div></div>';
  const s = 'async function load(){var u=document.getElementById("f_u").value;var r=await api("/api/admin/hits?limit=200"+(u?"&user="+encodeURIComponent(u):""));if(!r.j||!r.j.ok){location.href="/admin";return}'
    + 'document.getElementById("rows").innerHTML=(r.j.hits||[]).map(function(h){return "<tr><td>"+(h.username||"<span class=mut>?</span>")+"</td><td class=mono>"+h.pkg+"</td><td class=mono>"+(h.ip||"-")+"</td><td>"+new Date(h.created_at*1000).toLocaleString()+"</td></tr>"}).join("")}load()';
  return shell('Admin', NAV_ADMIN, 'hits', c, s, 'admin');
}

/* ================= router ================= */
function htmlResp(h) { return new Response(h, { headers: { 'Content-Type': 'text/html; charset=utf-8' } }); }

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const path = url.pathname;
    const m = req.method;

    /* --- lib + auth APIs --- */
    if (path === '/api/validate' && m === 'POST') return apiValidate(req, env, ctx);
    if (path === '/api/register' && m === 'POST') return apiRegister(req, env);
    if (path === '/api/login' && m === 'POST') return apiLogin(req, env);
    if (path === '/logout') return new Response('', { status: 302, headers: { Location: '/', 'Set-Cookie': cookieHeader(req, 'sess', null, 0) } });
    if (path === '/api/me') return apiMe(req, env);
    if (path === '/api/my-url' && m === 'POST') return apiMyUrl(req, env);
    if (path === '/api/my-hits') return apiMyHits(req, env);
    if (path === '/api/admin/login' && m === 'POST') return apiAdminLogin(req, env);
    if (path === '/admin/logout') return new Response('', { status: 302, headers: { Location: '/admin', 'Set-Cookie': cookieHeader(req, 'asess', null, 0) } });
    if (path === '/api/admin/stats') return apiAdminStats(req, env);
    if (path === '/api/admin/users') return apiAdminUsers(req, env);
    if (path === '/api/admin/user' && m === 'POST') return apiAdminUserUpdate(req, env);
    if (path === '/api/admin/hits') return apiAdminHits(req, env);
    if (path === '/api/admin/unclaimed') return apiAdminUnclaimed(req, env);
    if (path === '/api/admin/assign' && m === 'POST') return apiAdminAssign(req, env);

    /* --- pages --- */
    if (path === '/' || path === '/index.html') {
      const uid = await checkSession(env, 'u', getCookies(req).sess);
      if (uid) {
        const u = await env.DB.prepare('SELECT username FROM users WHERE id=?').bind(uid).first();
        if (u) return new Response('', { status: 302, headers: { Location: '/' + u.username + '/' } });
      }
      const a = await checkSession(env, 'a', getCookies(req).asess);
      if (a === '1') return new Response('', { status: 302, headers: { Location: '/admin' } });
      return htmlResp(pageLanding());
    }
    if (path === '/register' || path === '/register/') return htmlResp(pageRegister());
    if (path === '/admin' || path === '/admin/') {
      const a = await checkSession(env, 'a', getCookies(req).asess);
      if (a !== '1') return htmlResp(pageAdminLogin());
      return htmlResp(pageAdminDash());
    }
    if (path === '/admin/users' || path === '/admin/users/') {
      const a = await checkSession(env, 'a', getCookies(req).asess);
      if (a !== '1') return new Response('', { status: 302, headers: { Location: '/admin' } });
      return htmlResp(pageAdminUsers());
    }
    if (path === '/admin/unclaimed' || path === '/admin/unclaimed/') {
      const a = await checkSession(env, 'a', getCookies(req).asess);
      if (a !== '1') return new Response('', { status: 302, headers: { Location: '/admin' } });
      return htmlResp(pageAdminUnclaimed());
    }
    if (path === '/admin/hits' || path === '/admin/hits/') {
      const a = await checkSession(env, 'a', getCookies(req).asess);
      if (a !== '1') return new Response('', { status: 302, headers: { Location: '/admin' } });
      return htmlResp(pageAdminHits());
    }
    const sm = path.match(/^\/([a-z0-9_]{3,20})(\/(hits)?\/?)?$/);
    if (sm) {
      const uid = await checkSession(env, 'u', getCookies(req).sess);
      if (!uid) return new Response('', { status: 302, headers: { Location: '/' } });
      const u = await env.DB.prepare('SELECT username FROM users WHERE id=?').bind(uid).first();
      if (!u || u.username !== sm[1]) return new Response('', { status: 302, headers: { Location: '/' } });
      if (sm[3] === 'hits') return htmlResp(pageUserHits(sm[1]));
      return htmlResp(pageUserDash(sm[1]));
    }
    return new Response('not found', { status: 404 });
  }
};
