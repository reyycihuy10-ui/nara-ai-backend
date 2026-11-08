'use strict';
// Nara AI - modul akun (Node 20+, butuh paket "pg").
const crypto = require('node:crypto');
const dns = require('node:dns').promises;
const { promisify } = require('node:util');
const scrypt = promisify(crypto.scrypt);

let Pool = null;
try { ({ Pool } = require('pg')); } catch { /* pg belum terpasang */ }

const DB_URL = String(process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.POSTGRESQL_URL || '').trim();
const RESEND_KEY = String(process.env.RESEND_API_KEY || '').trim();
const EMAIL_FROM = process.env.EMAIL_FROM || 'Nara AI <onboarding@resend.dev>';
const VERIFY = Boolean(RESEND_KEY) && process.env.REQUIRE_EMAIL_VERIFY !== 'false';
const DAILY_LIMIT = Math.max(1, Number(process.env.DAILY_LIMIT || 30));
const REQUIRE_AUTH_CHAT = process.env.REQUIRE_AUTH_CHAT === 'true';
const SESSION_DAYS = 30;

const BLOCKED = new Set([
  'mailinator.com', '10minutemail.com', 'guerrillamail.com', 'tempmail.com', 'temp-mail.org',
  'yopmail.com', 'trashmail.com', 'sharklasers.com', 'getnada.com', 'maildrop.cc',
  'throwawaymail.com', 'dispostable.com', 'fakeinbox.com', 'mailnesia.com', 'emailondeck.com',
  ...String(process.env.EXTRA_BLOCKED_DOMAINS || '').split(',').map((x) => x.trim().toLowerCase()).filter(Boolean),
]);

const pool = Pool && DB_URL
  ? new Pool({
      connectionString: DB_URL,
      ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
      max: 5,
    })
  : null;

const configured = Boolean(pool);
let ready = null;

function init() {
  if (!pool) return Promise.resolve();
  if (!ready) {
    ready = pool.query(`
      CREATE TABLE IF NOT EXISTS users(
        id SERIAL PRIMARY KEY,
        email TEXT NOT NULL,
        email_norm TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        pass_hash TEXT NOT NULL,
        verified BOOLEAN NOT NULL DEFAULT false,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        use_date DATE,
        use_count INT NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS email_codes(
        email_norm TEXT PRIMARY KEY,
        code_hash TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        attempts INT NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS sessions(
        token_hash TEXT PRIMARY KEY,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at TIMESTAMPTZ NOT NULL
      );
    `).catch((e) => { ready = null; throw e; });
  }
  return ready;
}

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

async function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(pw, salt, 64);
  return `s1$${salt.toString('hex')}$${key.toString('hex')}`;
}

async function checkPw(pw, stored) {
  const [v, saltHex, keyHex] = String(stored).split('$');
  if (v !== 's1') return false;
  const key = await scrypt(pw, Buffer.from(saltHex, 'hex'), 64);
  const want = Buffer.from(keyHex, 'hex');
  return key.length === want.length && crypto.timingSafeEqual(key, want);
}

// Email dinormalisasi supaya alias tidak lolos jadi akun ganda:
// huruf kecil, hapus "+tag", dan titik di Gmail diabaikan.
function normEmail(raw) {
  const e = String(raw || '').trim().toLowerCase();
  if (e.length > 254 || !/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(e)) return null;
  let [local, domain] = e.split('@');
  local = local.split('+')[0];
  if (domain === 'googlemail.com') domain = 'gmail.com';
  if (domain === 'gmail.com') local = local.replace(/\./g, '');
  if (!local) return null;
  return { email: e, norm: `${local}@${domain}`, domain };
}

async function domainExists(domain) {
  try {
    const mx = await dns.resolveMx(domain);
    return mx.length > 0;
  } catch (e) {
    return !(e.code === 'ENOTFOUND' || e.code === 'ENODATA');
  }
}

const hits = new Map();
function limited(req) {
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'x').split(',')[0].trim();
  const now = Date.now();
  let b = hits.get(ip);
  if (!b || now > b.reset) b = { n: 0, reset: now + 10 * 60 * 1000 };
  b.n += 1;
  hits.set(ip, b);
  if (hits.size > 5000) for (const [k, v] of hits) if (now > v.reset) hits.delete(k);
  return b.n > 20;
}

async function sendCode(email, code) {
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${RESEND_KEY}` },
    body: JSON.stringify({
      from: EMAIL_FROM,
      to: [email],
      subject: `Kode verifikasi Nara: ${code}`,
      text: `Kode verifikasi Nara AI kamu: ${code}\nBerlaku 10 menit. Abaikan email ini jika kamu tidak mendaftar.`,
    }),
  });
  if (!r.ok) throw new Error('Gagal mengirim email verifikasi.');
}

async function issueCode(em) {
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  await pool.query(
    `INSERT INTO email_codes(email_norm,code_hash,expires_at,attempts)
     VALUES($1,$2,now()+interval '10 minutes',0)
     ON CONFLICT(email_norm) DO UPDATE SET code_hash=$2,expires_at=now()+interval '10 minutes',attempts=0`,
    [em.norm, sha(code + em.norm)],
  );
  await sendCode(em.email, code);
}

async function newSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  await pool.query(
    `INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+($3||' days')::interval)`,
    [sha(token), userId, String(SESSION_DAYS)],
  );
  return token;
}

async function authUser(req) {
  const m = /^Bearer\s+([a-f0-9]{64})$/i.exec(String(req.headers.authorization || ''));
  if (!m) return null;
  const r = await pool.query(
    `SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()`,
    [sha(m[1].toLowerCase())],
  );
  return r.rows[0] || null;
}

const pub = (u) => ({ id: u.id, name: u.name, email: u.email, verified: u.verified });

// Dipanggil di /api/chat: batas harian dicek di server.
async function quota(req) {
  if (!pool) return { ok: true };
  await init();
  const u = await authUser(req);
  if (!u) return REQUIRE_AUTH_CHAT ? { ok: false, status: 401, error: 'Masuk dulu untuk memakai Nara.' } : { ok: true };
  const r = await pool.query(
    `UPDATE users SET use_count=CASE WHEN use_date=CURRENT_DATE THEN use_count+1 ELSE 1 END, use_date=CURRENT_DATE
     WHERE id=$1 AND (use_date IS DISTINCT FROM CURRENT_DATE OR use_count<$2) RETURNING use_count`,
    [u.id, DAILY_LIMIT],
  );
  return r.rowCount
    ? { ok: true }
    : { ok: false, status: 429, error: `Batas ${DAILY_LIMIT} pesan hari ini tercapai. Lanjut besok ya.` };
}

async function handle(req, res, pathname, body, send) {
  if (!pool) {
    return send(res, 503, { ok: false, error: 'Database belum terhubung. Pasang paket pg dan atur DATABASE_URL.' });
  }
  if (req.method === 'POST' && limited(req)) {
    return send(res, 429, { ok: false, error: 'Terlalu banyak percobaan. Coba lagi beberapa menit lagi.' });
  }
  try {
    await init();

    if (pathname === '/api/auth/register' && req.method === 'POST') {
      const em = normEmail(body.email);
      const name = String(body.name || '').trim().slice(0, 60);
      const pw = String(body.password || '');
      if (!em) return send(res, 400, { ok: false, error: 'Format email tidak valid.' });
      if (BLOCKED.has(em.domain)) return send(res, 400, { ok: false, error: 'Email sementara tidak diizinkan.' });
      if (!name) return send(res, 400, { ok: false, error: 'Nama tidak boleh kosong.' });
      if (pw.length < 8 || pw.length > 200) return send(res, 400, { ok: false, error: 'Kata sandi minimal 8 karakter.' });
      if (!(await domainExists(em.domain))) return send(res, 400, { ok: false, error: 'Domain email tidak ditemukan.' });

      const ex = (await pool.query('SELECT id,verified FROM users WHERE email_norm=$1', [em.norm])).rows[0];
      if (ex && (ex.verified || !VERIFY)) return send(res, 409, { ok: false, error: 'Email sudah terdaftar. Silakan masuk.' });

      const hash = await hashPw(pw);
      let id;
      if (ex) {
        await pool.query('UPDATE users SET name=$2,pass_hash=$3 WHERE id=$1', [ex.id, name, hash]);
        id = ex.id;
      } else {
        try {
          id = (await pool.query(
            'INSERT INTO users(email,email_norm,name,pass_hash) VALUES($1,$2,$3,$4) RETURNING id',
            [em.email, em.norm, name, hash],
          )).rows[0].id;
        } catch (e) {
          if (e.code === '23505') return send(res, 409, { ok: false, error: 'Email sudah terdaftar. Silakan masuk.' });
          throw e;
        }
      }
      if (VERIFY) {
        await issueCode(em);
        return send(res, 200, { ok: true, needVerify: true });
      }
      const u = (await pool.query('SELECT * FROM users WHERE id=$1', [id])).rows[0];
      return send(res, 200, { ok: true, token: await newSession(id), user: pub(u) });
    }

    if (pathname === '/api/auth/verify' && req.method === 'POST') {
      const em = normEmail(body.email);
      const code = String(body.code || '').trim();
      if (!em || !/^\d{6}$/.test(code)) return send(res, 400, { ok: false, error: 'Kode harus 6 angka.' });
      const row = (await pool.query('SELECT * FROM email_codes WHERE email_norm=$1 AND expires_at>now()', [em.norm])).rows[0];
      if (!row) return send(res, 400, { ok: false, error: 'Kode kedaluwarsa. Minta kode baru.' });
      if (row.attempts >= 5) return send(res, 429, { ok: false, error: 'Terlalu banyak salah. Minta kode baru.' });
      if (sha(code + em.norm) !== row.code_hash) {
        await pool.query('UPDATE email_codes SET attempts=attempts+1 WHERE email_norm=$1', [em.norm]);
        return send(res, 400, { ok: false, error: 'Kode salah.' });
      }
      await pool.query('DELETE FROM email_codes WHERE email_norm=$1', [em.norm]);
      const u = (await pool.query('UPDATE users SET verified=true WHERE email_norm=$1 RETURNING *', [em.norm])).rows[0];
      if (!u) return send(res, 400, { ok: false, error: 'Akun tidak ditemukan.' });
      return send(res, 200, { ok: true, token: await newSession(u.id), user: pub(u) });
    }

    if (pathname === '/api/auth/login' && req.method === 'POST') {
      const em = normEmail(body.email);
      const bad = () => send(res, 401, { ok: false, error: 'Email atau kata sandi salah.' });
      if (!em) return bad();
      const u = (await pool.query('SELECT * FROM users WHERE email_norm=$1', [em.norm])).rows[0];
      if (!u || !(await checkPw(String(body.password || ''), u.pass_hash))) return bad();
      if (VERIFY && !u.verified) {
        await issueCode({ email: u.email, norm: u.email_norm });
        return send(res, 403, { ok: false, needVerify: true, error: 'Email belum diverifikasi. Kode baru sudah dikirim.' });
      }
      return send(res, 200, { ok: true, token: await newSession(u.id), user: pub(u) });
    }

    if (pathname === '/api/auth/me' && req.method === 'GET') {
      const u = await authUser(req);
      if (!u) return send(res, 401, { ok: false, error: 'Sesi tidak valid.' });
      const today = new Date().toISOString().slice(0, 10);
      const used = u.use_date && new Date(u.use_date).toISOString().slice(0, 10) === today ? u.use_count : 0;
      return send(res, 200, { ok: true, user: pub(u), usage: { used, limit: DAILY_LIMIT } });
    }

    if (pathname === '/api/auth/logout' && req.method === 'POST') {
      const m = /^Bearer\s+([a-f0-9]{64})$/i.exec(String(req.headers.authorization || ''));
      if (m) await pool.query('DELETE FROM sessions WHERE token_hash=$1', [sha(m[1].toLowerCase())]);
      return send(res, 200, { ok: true });
    }

    return send(res, 404, { ok: false, error: 'Route auth tidak ditemukan.' });
  } catch (e) {
    console.log(new Date().toISOString(), '[AUTH ERROR]', e.message);
    return send(res, 500, { ok: false, error: 'Terjadi kesalahan pada server akun.' });
  }
}

module.exports = { handle, quota, configured, verifyEnabled: VERIFY };
