
'use strict';

// Nara AI Backend — Node.js 20+
// DeepSeek AI + Tavily Search
// API keys hanya disimpan di Environment Variables.

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = __dirname;
const PORT = Number(process.env.PORT || 3000);

const AI_API_URL = (
  process.env.AI_API_URL ||
  'https://api.deepseek.com/chat/completions'
).trim();

const AI_API_KEY = (process.env.AI_API_KEY || '').trim();
const AI_MODEL = (process.env.AI_MODEL || '').trim();
const TAVILY_API_KEY = (process.env.TAVILY_API_KEY || '').trim();

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(x => x.trim())
  .filter(Boolean);

const MAX_BODY_BYTES = 12 * 1024 * 1024;
const RATE_WINDOW_MS = 60000;
const RATE_LIMIT = 45;

const requestCounts = new Map();

function sendJson(res, status, payload) {
  if (res.headersSent) return;

  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });

  res.end(JSON.stringify(payload));
}

function applyCors(req, res) {
  const origin = req.headers.origin;

  if (!origin) return true;

  const host = req.headers.host || '';
  const sameOrigin =
    origin === `https://${host}` ||
    origin === `http://${host}`;

  const allowAll = ALLOWED_ORIGINS.includes('*');
  const explicitlyAllowed = ALLOWED_ORIGINS.includes(origin);

  if (!sameOrigin && !allowAll && !explicitlyAllowed) {
    sendJson(res, 403, {
      error: 'Origin aplikasi belum diizinkan. Periksa ALLOWED_ORIGINS.'
    });
    return false;
  }

  res.setHeader(
    'Access-Control-Allow-Origin',
    allowAll ? '*' : origin
  );

  res.setHeader('Vary', 'Origin');
  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET, POST, OPTIONS'
  );
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization'
  );
  res.setHeader('Access-Control-Max-Age', '86400');

  return true;
}

function rateLimit(req, res) {
  const forwarded = String(
    req.headers['x-forwarded-for'] || ''
  ).split(',')[0].trim();

  const ip = forwarded ||
    req.socket.remoteAddress ||
    'unknown';

  const now = Date.now();
  const old = requestCounts.get(ip);

  if (!old || now - old.start >= RATE_WINDOW_MS) {
    requestCounts.set(ip, {
      start: now,
      count: 1
    });
    return true;
  }

  old.count++;

  if (old.count <= RATE_LIMIT) return true;

  res.setHeader('Retry-After', '60');

  sendJson(res, 429, {
    error: 'Terlalu banyak permintaan. Coba lagi sebentar.'
  });

  return false;
}

async function readJson(req) {
  const chunks = [];
  let total = 0;

  for await (const chunk of req) {
    total += chunk.length;

    if (total > MAX_BODY_BYTES) {
      const error = new Error(
        'Ukuran permintaan terlalu besar. Maksimal sekitar 12 MB.'
      );
      error.statusCode = 413;
      throw error;
    }

    chunks.push(chunk);
  }

  const raw = Buffer.concat(chunks).toString('utf8');

  try {
    return raw ? JSON.parse(raw) : {};
  } catch {
    const error = new Error(
      'Format JSON permintaan tidak valid.'
    );
    error.statusCode = 400;
    throw error;
  }
}

function safeProviderMessage(raw) {
  const text = String(raw || '').slice(0, 1200);

  return text
    .replace(/Bearer\s+[A-Za-z0-9._-]+/gi, 'Bearer [REDACTED]')
    .replace(/tvly-[A-Za-z0-9_-]+/g, '[REDACTED]');
}

// ======================================
// TAVILY WEB SEARCH
// ======================================

async function handleSearch(req, res) {
  if (!TAVILY_API_KEY) {
    return sendJson(res, 503, {
      error: 'TAVILY_API_KEY belum diatur di backend.'
    });
  }

  const body = await readJson(req);
  const query = String(body.query || '').trim();

  if (!query) {
    return sendJson(res, 400, {
      error: 'Masukkan kata kunci pencarian.'
    });
  }

  if (query.length > 400) {
    return sendJson(res, 400, {
      error: 'Kata kunci maksimal 400 karakter.'
    });
  }

  const timeRange =
    /hari ini|today|sekarang/i.test(query) ? 'day' :
    /terbaru|terkini|minggu ini|this week/i.test(query)
      ? 'week'
      : undefined;

  const requestBody = {
    query,
    topic: 'general',
    search_depth: [
      'basic',
      'fast',
      'advanced'
    ].includes(body.search_depth)
      ? body.search_depth
      : 'basic',

    max_results: Math.max(
      1,
      Math.min(5, Number(body.max_results) || 5)
    ),

    include_answer: false,
    include_raw_content: false
  };

  if (timeRange) {
    requestBody.time_range = timeRange;
  }

  const upstream = await fetch(
    'https://api.tavily.com/search',
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${TAVILY_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestBody),
      signal: AbortSignal.timeout(25000)
    }
  );

  const result = await upstream.json().catch(() => ({}));

  if (!upstream.ok) {
    const message = safeProviderMessage(
      result.detail ||
      result.message ||
      result.error ||
      `Tavily HTTP ${upstream.status}`
    );

    return sendJson(res, 502, {
      error: `Pencarian Tavily gagal: ${message}`
    });
  }

  const results = Array.isArray(result.results)
    ? result.results.slice(0, 5).map(item => ({
        title: String(item.title || 'Sumber web').slice(0, 240),
        url: String(item.url || ''),
        content: String(item.content || '').slice(0, 3500),
        score: Number.isFinite(item.score) ? item.score : null,
        published_date:
          item.published_date ||
          item.publishedDate ||
          null
      })).filter(item => /^https:\/\//i.test(item.url))
    : [];

  return sendJson(res, 200, {
    query,
    results
  });
}

// ======================================
// DEEPSEEK AI CHAT
// ======================================

async function handleChat(req, res) {
  if (!AI_API_KEY) {
    return sendJson(res, 503, {
      error: 'AI_API_KEY belum diatur di backend.'
    });
  }

  if (!AI_MODEL) {
    return sendJson(res, 503, {
      error: 'AI_MODEL belum diatur.'
    });
  }

  let parsed;

  try {
    parsed = new URL(AI_API_URL);
  } catch {
    return sendJson(res, 500, {
      error: 'AI_API_URL tidak valid.'
    });
  }

  if (
    parsed.protocol !== 'https:' &&
    parsed.hostname !== 'localhost' &&
    parsed.hostname !== '127.0.0.1'
  ) {
    return sendJson(res, 500, {
      error: 'AI_API_URL harus menggunakan HTTPS.'
    });
  }

  const body = await readJson(req);

  if (
    !Array.isArray(body.messages) ||
    body.messages.length < 1 ||
    body.messages.length > 30
  ) {
    return sendJson(res, 400, {
      error: 'Daftar messages tidak valid.'
    });
  }

  const messages = body.messages.filter(message =>
    message &&
    ['system', 'user', 'assistant'].includes(message.role) &&
    (
      typeof message.content === 'string' ||
      Array.isArray(message.content)
    )
  );

  if (!messages.length) {
    return sendJson(res, 400, {
      error: 'Tidak ada pesan yang dapat diproses.'
    });
  }

  const upstream = await fetch(AI_API_URL, {
    method: 'POST',

    headers: {
      'Authorization': `Bearer ${AI_API_KEY}`,
      'Content-Type': 'application/json'
    },

    body: JSON.stringify({
      model: AI_MODEL,
      messages,
      temperature: 0.55,
      stream: body.stream !== false
    }),

    signal: AbortSignal.timeout(90000)
  });

  if (!upstream.ok) {
    const raw = await upstream.text().catch(() => '');

    return sendJson(res, 502, {
      error:
        `Provider AI menolak permintaan (HTTP ${upstream.status}): ` +
        safeProviderMessage(raw || upstream.statusText)
    });
  }

  const contentType =
    upstream.headers.get('content-type') || '';

  // STREAMING RESPONSE
  if (
    contentType.includes('text/event-stream') &&
    upstream.body
  ) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
      'X-Content-Type-Options': 'nosniff'
    });

    try {
      for await (const chunk of upstream.body) {
        if (res.destroyed) break;
        res.write(Buffer.from(chunk));
      }

      if (!res.destroyed) res.end();

    } catch (error) {
      if (!res.destroyed) {
        const msg = safeProviderMessage(error.message);

        res.write(
          `data: ${JSON.stringify({ error: msg })}\n\n`
        );

        res.end();
      }
    }

    return;
  }

  // NON-STREAMING RESPONSE
  const data = await upstream.json().catch(() => null);

  if (!data) {
    return sendJson(res, 502, {
      error: 'Provider AI mengirim respons tidak valid.'
    });
  }

  return sendJson(res, 200, data);
}

// ======================================
// SERVE HTML
// ======================================

function serveIndex(res) {
  const file = path.join(ROOT, 'index.html');

  if (!fs.existsSync(file)) {
    return sendJson(res, 404, {
      error: 'index.html tidak ditemukan.'
    });
  }

  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });

  fs.createReadStream(file).pipe(res);
}

// ======================================
// SERVER ROUTES
// ======================================

const server = http.createServer(async (req, res) => {
  try {
    if (!applyCors(req, res)) return;

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      return res.end();
    }

    const url = new URL(
      req.url,
      `http://${req.headers.host || 'localhost'}`
    );

    // HEALTH CHECK
    if (
      req.method === 'GET' &&
      url.pathname === '/api/health'
    ) {
      return sendJson(res, 200, {
        ok: true,
        app: 'Nara AI Backend',
        aiConfigured: Boolean(AI_API_KEY && AI_MODEL),
        tavilyConfigured: Boolean(TAVILY_API_KEY)
      });
    }

    // MAIN PAGE
    if (
      req.method === 'GET' &&
      (
        url.pathname === '/' ||
        url.pathname === '/index.html'
      )
    ) {
      return serveIndex(res);
    }

    // AI AND SEARCH
    if (
      req.method === 'POST' &&
      (
        url.pathname === '/api/chat' ||
        url.pathname === '/api/search'
      )
    ) {
      if (!rateLimit(req, res)) return;

      if (url.pathname === '/api/chat') {
        return await handleChat(req, res);
      }

      return await handleSearch(req, res);
    }

    if (
      req.method === 'GET' &&
      url.pathname === '/favicon.ico'
    ) {
      res.writeHead(204);
      return res.end();
    }

    return sendJson(res, 404, {
      error: 'Route tidak ditemukan.'
    });

  } catch (error) {
    const status = Number(error.statusCode) || 500;

    return sendJson(res, status, {
      error: safeProviderMessage(
        error.message || 'Kesalahan server.'
      )
    });
  }
});

// ======================================
// START
// ======================================

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Nara backend berjalan pada port ${PORT}`);

  console.log(
    `AI configured: ${Boolean(AI_API_KEY && AI_MODEL)}`
  );

  console.log(
    `Tavily configured: ${Boolean(TAVILY_API_KEY)}`
  );
});
