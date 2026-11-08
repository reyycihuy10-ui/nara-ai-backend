'use strict';

// Nara AI - modul autentikasi (OTP email + anti email ganda)
// Node.js 20+ | Paket: pg

const crypto = require('node:crypto');
const dns = require('node:dns').promises;
const { promisify } = require('node:util');

const scrypt = promisify(crypto.scrypt);

// ===================== DEPENDENCIES =====================

let Pool = null;
try {
  ({ Pool } = require('pg'));
} catch {
  /* Paket pg belum terpasang */
}

// ===================== ENV =====================

const DB_URL = String(
  process.env.DATABASE_URL ||
  process.env.POSTGRES_URL ||
  process.env.POSTGRESQL_URL ||
  ''
).trim();

const RESEND_KEY = String(process.env.RESEND_API_KEY || '').trim();

const EMAIL_FROM = String(
  process.env.EMAIL_FROM || 'Nara AI <onboarding@resend.dev>'
).trim();

// Verifikasi email wajib kecuali REQUIRE_EMAIL_VERIFY=false.
const VERIFY =
  String(process.env.REQUIRE_EMAIL_VERIFY || 'true')
    .trim()
    .toLowerCase() !== 'false';

const MAIL_CONFIGURED = Boolean(RESEND_KEY);

const DAILY_LIMIT_RAW = Number(process.env.DAILY_LIMIT || 30);
const DAILY_LIMIT = Number.isFinite(DAILY_LIMIT_RAW)
  ? Math.max(1, Math.floor(DAILY_LIMIT_RAW))
  : 30;

const REQUIRE_AUTH_CHAT = process.env.REQUIRE_AUTH_CHAT === 'true';

const SESSION_DAYS = 30;
const OTP_MINUTES = 10;
const OTP_MAX_ATTEMPTS = 5;
const RESEND_COOLDOWN_SEC = 60;

// ===================== BLOCKED DOMAINS =====================

const BLOCKED = new Set([
  'mailinator.com',
  '10minutemail.com',
  'guerrillamail.com',
  'tempmail.com',
  'temp-mail.org',
  'yopmail.com',
  'trashmail.com',
  'sharklasers.com',
  'getnada.com',
  'maildrop.cc',
  'throwawaymail.com',
  'dispostable.com',
  'fakeinbox.com',
  'mailnesia.com',
  'emailondeck.com',

  ...String(process.env.EXTRA_BLOCKED_DOMAINS || '')
    .split(',')
    .map((x) => x.trim().toLowerCase())
    .filter(Boolean),
]);

// Domain yang mengabaikan bagian +tag pada alamat email.
const PLUS_ALIAS_DOMAINS = new Set([
  'gmail.com',
  'outlook.com',
  'hotmail.com',
  'live.com',
  'icloud.com',
  'me.com',
  'proton.me',
  'protonmail.com',
]);

// ===================== POSTGRESQL =====================

const pool = Pool && DB_URL
  ? new Pool({
      connectionString: DB_URL,
      ssl: process.env.DATABASE_SSL === 'true'
        ? { rejectUnauthorized: false }
        : undefined,
      max: 5,
      connectionTimeoutMillis: 10000,
      idleTimeoutMillis: 30000,
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
        attempts INT NOT NULL DEFAULT 0,
        sent_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      -- Untuk tabel lama yang dibuat sebelum fitur kirim ulang.
      ALTER TABLE email_codes
        ADD COLUMN IF NOT EXISTS sent_at TIMESTAMPTZ NOT NULL DEFAULT now();

      CREATE TABLE IF NOT EXISTS sessions(
        token_hash TEXT PRIMARY KEY,
        user_id INT NOT NULL
          REFERENCES users(id) ON DELETE CASCADE,
        expires_at TIMESTAMPTZ NOT NULL
      );
    `).catch((e) => {
      ready = null;
      throw e;
    });
  }

  return ready;
}

// ===================== CRYPTO =====================

const sha = (s) =>
  crypto.createHash('sha256').update(s).digest('hex');

function safeEqualHex(a, b) {
  if (
    typeof a !== 'string' ||
    typeof b !== 'string' ||
    !/^[a-f0-9]{64}$/i.test(a) ||
    !/^[a-f0-9]{64}$/i.test(b)
  ) {
    return false;
  }

  const aa = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');

  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

async function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(pw, salt, 64);
  return `s1$${salt.toString('hex')}$${key.toString('hex')}`;
}

async function checkPw(pw, stored) {
  try {
    const [version, saltHex, keyHex] = String(stored || '').split('$');

    if (
      version !== 's1' ||
      !/^[a-f0-9]{32}$/i.test(saltHex || '') ||
      !/^[a-f0-9]{128}$/i.test(keyHex || '')
    ) {
      return false;
    }

    const salt = Buffer.from(saltHex, 'hex');
    const expected = Buffer.from(keyHex, 'hex');
    const key = await scrypt(pw, salt, 64);

    return key.length === expected.length && crypto.timingSafeEqual(key, expected);
  } catch {
    return false;
  }
}

// ===================== EMAIL NORMALIZATION =====================
// email_norm bersifat UNIQUE di database, sehingga satu orang tidak bisa
// membuat banyak akun lewat trik titik / +tag (a.b+1@gmail.com = ab@gmail.com).

function normEmail(raw) {
  const e = String(raw || '').trim().toLowerCase();

  if (
    e.length > 254 ||
    !/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(e)
  ) {
    return null;
  }

  let [local, domain] = e.split('@');

  if (
    !local ||
    local.length > 64 ||
    domain.length > 253 ||
    local.startsWith('.') ||
    local.endsWith('.') ||
    local.includes('..')
  ) {
    return null;
  }

  if (domain === 'googlemail.com') domain = 'gmail.com';

  if (PLUS_ALIAS_DOMAINS.has(domain)) {
    local = local.split('+')[0];
  }

  // Gmail juga mengabaikan titik.
  if (domain === 'gmail.com') {
    local = local.replace(/\./g, '');
  }

  if (!local) return null;

  return { email: e, norm: `${local}@${domain}`, domain };
}

// ===================== DOMAIN CHECK =====================
// Hanya memastikan domain bisa menerima email. Kepemilikan alamat
// dibuktikan lewat OTP.

async function domainExists(domain) {
  try {
    const mx = await dns.resolveMx(domain);
    if (mx.length > 0) return true;
  } catch (e) {
    if (e.code === 'ENOTFOUND') return false;
    if (e.code !== 'ENODATA') throw e;
  }

  try {
    await dns.lookup(domain);
    return true;
  } catch (e) {
    if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') return false;
    throw e;
  }
}

// ===================== RATE LIMIT (per IP) =====================

const hits = new Map();

function limited(req) {
  const ip = String(
    req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'x'
  ).split(',')[0].trim();

  const now = Date.now();
  let b = hits.get(ip);

  if (!b || now > b.reset) {
    b = { n: 0, reset: now + 10 * 60 * 1000 };
  }

  b.n += 1;
  hits.set(ip, b);

  if (hits.size > 5000) {
    for (const [k, v] of hits) {
      if (now > v.reset) hits.delete(k);
    }
  }

  return b.n > 30;
}

// ===================== RESEND EMAIL =====================

async function sendCode(email, code) {
  if (!RESEND_KEY) {
    const error = new Error('RESEND_API_KEY belum dikonfigurasi.');
    error.code = 'EMAIL_NOT_CONFIGURED';
    throw error;
  }

  let r;

  try {
    r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${RESEND_KEY}`,
      },
      signal: AbortSignal.timeout(15000),
      body: JSON.stringify({
        from: EMAIL_FROM,
        to: [email],
        subject: `Kode verifikasi Nara: ${code}`,
        text:
          `Kode verifikasi Nara AI kamu: ${code}\n` +
          `Berlaku ${OTP_MINUTES} menit.\n` +
          'Jangan bagikan kode ini ke siapa pun.\n' +
          'Abaikan email ini jika kamu tidak mendaftar.',
      }),
    });
  } catch (cause) {
    const error = new Error('Tidak dapat terhubung ke layanan email.');
    error.code = 'EMAIL_SEND_FAILED';
    error.cause = cause;
    throw error;
  }

  const responseData = await r.json().catch(() => ({}));

  if (!r.ok) {
    const error = new Error(
      responseData.message || `Resend HTTP ${r.status}`
    );
    error.code = 'EMAIL_SEND_FAILED';
    error.status = r.status;
    throw error;
  }

  return responseData;
}

// ===================== ISSUE OTP =====================
// Mengembalikan { sent, wait }. Jika kode terakhir dikirim kurang dari
// RESEND_COOLDOWN_SEC detik lalu, kode TIDAK dikirim ulang (anti email-bombing).

async function issueCode(em) {
  if (!RESEND_KEY) {
    const error = new Error('RESEND_API_KEY belum dikonfigurasi.');
    error.code = 'EMAIL_NOT_CONFIGURED';
    throw error;
  }

  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  const codeHash = sha(code + em.norm);

  const r = await pool.query(
    `
      INSERT INTO email_codes(
        email_norm, code_hash, expires_at, attempts, sent_at
      )
      VALUES($1, $2, now() + ($4 || ' minutes')::interval, 0, now())
      ON CONFLICT(email_norm) DO UPDATE SET
        code_hash  = $2,
        expires_at = now() + ($4 || ' minutes')::interval,
        attempts   = 0,
        sent_at    = now()
      WHERE email_codes.sent_at <= now() - ($3 || ' seconds')::interval
      RETURNING email_norm
    `,
    [em.norm, codeHash, String(RESEND_COOLDOWN_SEC), String(OTP_MINUTES)]
  );

  if (!r.rowCount) {
    return { sent: false, wait: RESEND_COOLDOWN_SEC };
  }

  try {
    await sendCode(em.email, code);
  } catch (e) {
    // Hapus kode yang gagal terkirim (hanya kode ini, bukan kode baru lain).
    await pool.query(
      `DELETE FROM email_codes WHERE email_norm = $1 AND code_hash = $2`,
      [em.norm, codeHash]
    ).catch(() => {});

    throw e;
  }

  return { sent: true, wait: RESEND_COOLDOWN_SEC };
}

// ===================== SESSION =====================

async function newSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');

  await pool.query(
    `
      INSERT INTO sessions(token_hash, user_id, expires_at)
      VALUES($1, $2, now() + ($3 || ' days')::interval)
    `,
    [sha(token), userId, String(SESSION_DAYS)]
  );

  return token;
}

async function authUser(req) {
  if (!pool) return null;

  const m = /^Bearer\s+([a-f0-9]{64})$/i.exec(
    String(req.headers.authorization || '')
  );

  if (!m) return null;

  const r = await pool.query(
    `
      SELECT u.*
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = $1
        AND s.expires_at > now()
    `,
    [sha(m[1].toLowerCase())]
  );

  return r.rows[0] || null;
}

const pub = (u) => ({
  id: u.id,
  name: u.name,
  email: u.email,
  verified: u.verified,
});

// ===================== CHAT QUOTA =====================

async function quota(req) {
  if (!pool) return { ok: true };

  await init();

  const u = await authUser(req);

  if (!u) {
    return REQUIRE_AUTH_CHAT
      ? { ok: false, status: 401, error: 'Masuk dulu untuk memakai Nara.' }
      : { ok: true };
  }

  // Akun yang belum verifikasi tidak boleh memakai chat.
  if (VERIFY && !u.verified) {
    return {
      ok: false,
      status: 403,
      error: 'Verifikasi email dulu untuk memakai Nara.',
    };
  }

  const r = await pool.query(
    `
      UPDATE users
      SET
        use_count = CASE
          WHEN use_date = CURRENT_DATE THEN use_count + 1
          ELSE 1
        END,
        use_date = CURRENT_DATE
      WHERE id = $1
        AND (
          use_date IS DISTINCT FROM CURRENT_DATE
          OR use_count < $2
        )
      RETURNING use_count
    `,
    [u.id, DAILY_LIMIT]
  );

  return r.rowCount
    ? { ok: true }
    : {
        ok: false,
        status: 429,
        error:
          `Batas ${DAILY_LIMIT} pesan hari ini tercapai. Lanjut besok ya.`,
      };
}

// ===================== ROUTES =====================

async function handle(req, res, pathname, body, send) {
  if (!pool) {
    return send(res, 503, {
      ok: false,
      error: 'Database belum terhubung. Pasang paket pg dan atur DATABASE_URL.',
    });
  }

  if (req.method === 'POST' && limited(req)) {
    return send(res, 429, {
      ok: false,
      error: 'Terlalu banyak percobaan. Coba lagi beberapa menit lagi.',
    });
  }

  try {
    await init();

    body = body && typeof body === 'object' ? body : {};

    // ---------------- REGISTER ----------------
    if (pathname === '/api/auth/register' && req.method === 'POST') {
      const em = normEmail(body.email);
      const name = String(body.name || '').trim().slice(0, 60);
      const pw = String(body.password || '');

      if (!em) {
        return send(res, 400, { ok: false, error: 'Format email tidak valid.' });
      }

      if (VERIFY && !MAIL_CONFIGURED) {
        return send(res, 503, {
          ok: false,
          error:
            'Layanan verifikasi email belum dikonfigurasi. Silakan coba lagi nanti.',
        });
      }

      if (BLOCKED.has(em.domain)) {
        return send(res, 400, {
          ok: false,
          error: 'Email sementara tidak diizinkan.',
        });
      }

      if (!name) {
        return send(res, 400, { ok: false, error: 'Nama tidak boleh kosong.' });
      }

      if (pw.length < 8 || pw.length > 200) {
        return send(res, 400, {
          ok: false,
          error: 'Kata sandi minimal 8 karakter.',
        });
      }

      if (!(await domainExists(em.domain))) {
        return send(res, 400, {
          ok: false,
          error: 'Domain email tidak ditemukan.',
        });
      }

      const ex = (
        await pool.query(
          `SELECT id, verified FROM users WHERE email_norm = $1`,
          [em.norm]
        )
      ).rows[0];

      // Email ganda: sudah terdaftar (dan terverifikasi) -> tolak.
      if (ex && (ex.verified || !VERIFY)) {
        return send(res, 409, {
          ok: false,
          error: 'Email sudah terdaftar. Silakan masuk.',
        });
      }

      const hash = await hashPw(pw);
      let id;

      if (ex) {
        // Akun lama yang belum diverifikasi: perbarui data.
        await pool.query(
          `UPDATE users SET name = $2, pass_hash = $3 WHERE id = $1`,
          [ex.id, name, hash]
        );
        id = ex.id;
      } else {
        try {
          id = (
            await pool.query(
              `
                INSERT INTO users(email, email_norm, name, pass_hash)
                VALUES($1, $2, $3, $4)
                RETURNING id
              `,
              [em.email, em.norm, name, hash]
            )
          ).rows[0].id;
        } catch (e) {
          // UNIQUE(email_norm) menangkap pendaftaran ganda yang bersamaan.
          if (e.code === '23505') {
            return send(res, 409, {
              ok: false,
              error: 'Email sudah terdaftar. Silakan masuk.',
            });
          }
          throw e;
        }
      }

      if (VERIFY) {
        const issued = await issueCode(em);

        return send(res, 200, {
          ok: true,
          needVerify: true,
          retryAfter: RESEND_COOLDOWN_SEC,
          message: issued.sent
            ? 'Kode verifikasi sudah dikirim ke email.'
            : 'Kode sebelumnya masih berlaku. Cek emailmu.',
        });
      }

      const u = (
        await pool.query('SELECT * FROM users WHERE id = $1', [id])
      ).rows[0];

      return send(res, 200, {
        ok: true,
        token: await newSession(id),
        user: pub(u),
      });
    }

    // ---------------- VERIFY OTP ----------------
    if (pathname === '/api/auth/verify' && req.method === 'POST') {
      const em = normEmail(body.email);
      const code = String(body.code || '').trim();

      if (!em || !/^\d{6}$/.test(code)) {
        return send(res, 400, { ok: false, error: 'Kode harus 6 angka.' });
      }

      // Hitung percobaan lebih dulu secara atomik (tahan terhadap
      // tebakan paralel), baru bandingkan kodenya.
      const tried = await pool.query(
        `
          UPDATE email_codes
          SET attempts = attempts + 1
          WHERE email_norm = $1
            AND expires_at > now()
            AND attempts < $2
          RETURNING code_hash, attempts
        `,
        [em.norm, OTP_MAX_ATTEMPTS]
      );

      if (!tried.rowCount) {
        return send(res, 400, {
          ok: false,
          error:
            'Kode kedaluwarsa atau percobaan habis. Minta kode baru.',
        });
      }

      const row = tried.rows[0];
      const expectedHash = sha(code + em.norm);

      if (!safeEqualHex(expectedHash, row.code_hash)) {
        const left = Math.max(0, OTP_MAX_ATTEMPTS - row.attempts);

        return send(res, 400, {
          ok: false,
          error: left > 0
            ? `Kode salah. Sisa ${left} percobaan.`
            : 'Kode salah. Percobaan habis, minta kode baru.',
        });
      }

      // Kode benar: hapus secara atomik agar tidak bisa dipakai dua kali.
      const consumed = await pool.query(
        `
          DELETE FROM email_codes
          WHERE email_norm = $1
            AND code_hash = $2
            AND expires_at > now()
          RETURNING email_norm
        `,
        [em.norm, expectedHash]
      );

      if (!consumed.rowCount) {
        return send(res, 400, {
          ok: false,
          error: 'Kode sudah digunakan atau kedaluwarsa.',
        });
      }

      const u = (
        await pool.query(
          `UPDATE users SET verified = true WHERE email_norm = $1 RETURNING *`,
          [em.norm]
        )
      ).rows[0];

      if (!u) {
        return send(res, 400, { ok: false, error: 'Akun tidak ditemukan.' });
      }

      return send(res, 200, {
        ok: true,
        token: await newSession(u.id),
        user: pub(u),
      });
    }

    // ---------------- RESEND OTP ----------------
    if (pathname === '/api/auth/resend' && req.method === 'POST') {
      const em = normEmail(body.email);

      // Respons selalu sama agar tidak bisa dipakai mengecek email terdaftar.
      const generic = {
        ok: true,
        retryAfter: RESEND_COOLDOWN_SEC,
        message:
          'Jika email terdaftar dan belum diverifikasi, kode baru sudah dikirim.',
      };

      if (!em) {
        return send(res, 400, { ok: false, error: 'Format email tidak valid.' });
      }

      if (!VERIFY) return send(res, 200, generic);

      if (!MAIL_CONFIGURED) {
        return send(res, 503, {
          ok: false,
          error: 'Layanan verifikasi email belum dikonfigurasi.',
        });
      }

      const u = (
        await pool.query(
          `SELECT email, email_norm, verified FROM users WHERE email_norm = $1`,
          [em.norm]
        )
      ).rows[0];

      if (u && !u.verified) {
        await issueCode({ email: u.email, norm: u.email_norm });
      }

      return send(res, 200, generic);
    }

    // ---------------- LOGIN ----------------
    if (pathname === '/api/auth/login' && req.method === 'POST') {
      const em = normEmail(body.email);

      const bad = () =>
        send(res, 401, {
          ok: false,
          error: 'Email atau kata sandi salah.',
        });

      if (!em) return bad();

      const u = (
        await pool.query(
          `SELECT * FROM users WHERE email_norm = $1`,
          [em.norm]
        )
      ).rows[0];

      if (!u || !(await checkPw(String(body.password || ''), u.pass_hash))) {
        return bad();
      }

      if (VERIFY && !u.verified) {
        if (!MAIL_CONFIGURED) {
          return send(res, 503, {
            ok: false,
            needVerify: true,
            error: 'Layanan verifikasi email belum dikonfigurasi.',
          });
        }

        const issued = await issueCode({
          email: u.email,
          norm: u.email_norm,
        });

        return send(res, 403, {
          ok: false,
          needVerify: true,
          retryAfter: RESEND_COOLDOWN_SEC,
          error: issued.sent
            ? 'Email belum diverifikasi. Kode baru sudah dikirim.'
            : 'Email belum diverifikasi. Cek kode di emailmu.',
        });
      }

      return send(res, 200, {
        ok: true,
        token: await newSession(u.id),
        user: pub(u),
      });
    }

    // ---------------- ME ----------------
    if (pathname === '/api/auth/me' && req.method === 'GET') {
      const u = await authUser(req);

      if (!u) {
        return send(res, 401, { ok: false, error: 'Sesi tidak valid.' });
      }

      const today = new Date().toISOString().slice(0, 10);

      const used =
        u.use_date &&
        new Date(u.use_date).toISOString().slice(0, 10) === today
          ? u.use_count
          : 0;

      return send(res, 200, {
        ok: true,
        user: pub(u),
        usage: { used, limit: DAILY_LIMIT },
      });
    }

    // ---------------- LOGOUT ----------------
    if (pathname === '/api/auth/logout' && req.method === 'POST') {
      const m = /^Bearer\s+([a-f0-9]{64})$/i.exec(
        String(req.headers.authorization || '')
      );

      if (m) {
        await pool.query(
          `DELETE FROM sessions WHERE token_hash = $1`,
          [sha(m[1].toLowerCase())]
        );
      }

      return send(res, 200, { ok: true });
    }

    return send(res, 404, {
      ok: false,
      error: 'Route auth tidak ditemukan.',
    });
  } catch (e) {
    console.log(
      new Date().toISOString(),
      '[AUTH ERROR]',
      e.code || '',
      e.message
    );

    if (e.code === 'EMAIL_NOT_CONFIGURED') {
      return send(res, 503, {
        ok: false,
        error: 'Layanan verifikasi email belum dikonfigurasi.',
      });
    }

    if (e.code === 'EMAIL_SEND_FAILED') {
      return send(res, 502, {
        ok: false,
        error:
          'Gagal mengirim email verifikasi. Periksa konfigurasi Resend dan email pengirim.',
      });
    }

    return send(res, 500, {
      ok: false,
      error: 'Terjadi kesalahan pada server akun.',
    });
  }
}

module.exports = {
  handle,
  quota,
  configured,
  verifyEnabled: VERIFY,
  mailConfigured: MAIL_CONFIGURED,
};
