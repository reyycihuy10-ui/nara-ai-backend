'use strict';

// Nara AI Backend — Node.js 20+
// OpenRouter / Gemma 4 31B Free + Tavily Search
// API keys hanya disimpan di Environment Variables.

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = __dirname;
const PORT = Number(process.env.PORT || 3000);

// ======================================
// AI CONFIGURATION
// ======================================

// Default diarahkan ke OpenRouter.
// Bisa diganti melalui Environment Variables.

const AI_API_URL = (
  process.env.AI_API_URL ||
  'https://openrouter.ai/api/v1/chat/completions'
).trim();

const AI_API_KEY = (process.env.AI_API_KEY || '').trim();

const AI_MODEL = (
  process.env.AI_MODEL ||
  'google/gemma-4-31b-it:free'
).trim();

const TAVILY_API_KEY = (
  process.env.TAVILY_API_KEY || ''
).trim();

const OPENROUTER_SITE_URL = (
  process.env.OPENROUTER_SITE_URL || ''
).trim();

const OPENROUTER_APP_NAME = (
  process.env.OPENROUTER_APP_NAME || 'Nara AI'
).trim();

// ======================================
// CORS CONFIGURATION
// ======================================

// Jika ALLOWED_ORIGINS belum diatur,
// gunakan * agar frontend dari domain berbeda
// tidak langsung ditolak oleh browser.
//
// Setelah koneksi berhasil, sebaiknya batasi
// ke domain frontend Nara milikmu.

const ALLOWED_ORIGINS = (
  process.env.ALLOWED_ORIGINS || '*'
)
  .split(',')
  .map(x => x.trim().replace(/\/+$/, ''))
  .filter(Boolean);

// ======================================
// SERVER LIMITS
// ======================================

const MAX_BODY_BYTES = 12 * 1024 * 1024;

const RATE_WINDOW_MS = 60000;
const RATE_LIMIT = 45;

const AI_TIMEOUT_MS = 90000;
const SEARCH_TIMEOUT_MS = 25000;

const requestCounts = new Map();

// ======================================
// GENERAL HELPERS
// ======================================

function sendJson(res, status, payload) {
  if (res.headersSent || res.destroyed) return;

  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });

  res.end(JSON.stringify(payload));
}

function normalizeOrigin(origin) {
  return String(origin || '')
    .trim()
    .replace(/\/+$/, '');
}

// ======================================
// CORS
// ======================================

function applyCors(req, res) {
  const origin = normalizeOrigin(req.headers.origin);

  // Request non-browser biasanya tidak memiliki Origin.
  if (!origin) return true;

  const host = req.headers.host || '';

  const forwardedProto = String(
    req.headers['x-forwarded-proto'] || ''
  )
    .split(',')[0]
    .trim();

  const sameOrigin =
    origin === `https://${host}` ||
    origin === `http://${host}` ||
    (
      forwardedProto &&
      origin === `${forwardedProto}://${host}`
    );

  const allowAll = ALLOWED_ORIGINS.includes('*');

  const explicitlyAllowed =
    ALLOWED_ORIGINS.some(
      allowed => normalizeOrigin(allowed) === origin
    );

  if (!sameOrigin && !allowAll && !explicitlyAllowed) {
    console.warn(
      `[CORS] Origin ditolak: ${origin}`
    );

    sendJson(res, 403, {
      error:
        'Origin aplikasi belum diizinkan. ' +
        'Periksa ALLOWED_ORIGINS pada Environment Variables.',
      origin
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
    'Content-Type, Authorization, X-Requested-With'
  );

  res.setHeader(
    'Access-Control-Expose-Headers',
    'X-Generation-Id'
  );

  res.setHeader(
    'Access-Control-Max-Age',
    '86400'
  );

  return true;
}

// ======================================
// RATE LIMIT
// ======================================

function rateLimit(req, res) {
  const forwarded = String(
    req.headers['x-forwarded-for'] || ''
  )
    .split(',')[0]
    .trim();

  const ip =
    forwarded ||
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

  if (old.count <= RATE_LIMIT) {
    return true;
  }

  res.setHeader('Retry-After', '60');

  sendJson(res, 429, {
    error:
      'Terlalu banyak permintaan. ' +
      'Coba lagi sebentar.'
  });

  return false;
}

// Bersihkan data rate limit yang sudah kedaluwarsa.

const cleanupTimer = setInterval(() => {
  const now = Date.now();

  for (const [ip, data] of requestCounts.entries()) {
    if (now - data.start >= RATE_WINDOW_MS) {
      requestCounts.delete(ip);
    }
  }
}, RATE_WINDOW_MS);

cleanupTimer.unref();

// ======================================
// READ JSON BODY
// ======================================

async function readJson(req) {
  const chunks = [];
  let total = 0;

  for await (const chunk of req) {
    total += chunk.length;

    if (total > MAX_BODY_BYTES) {
      const error = new Error(
        'Ukuran permintaan terlalu besar. ' +
        'Maksimal sekitar 12 MB.'
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

// ======================================
// ERROR SANITIZER
// ======================================

function safeProviderMessage(raw) {
  let text;

  if (typeof raw === 'string') {
    text = raw;
  } else {
    try {
      text = JSON.stringify(raw);
    } catch {
      text = String(raw || '');
    }
  }

  text = String(text || '').slice(0, 1200);

  // Sembunyikan API key yang mungkin muncul
  // pada pesan error dari provider.

  if (AI_API_KEY) {
    text = text.split(AI_API_KEY).join('[API_KEY_REDACTED]');
  }

  if (TAVILY_API_KEY) {
    text = text.split(TAVILY_API_KEY).join('[API_KEY_REDACTED]');
  }

  return text
    .replace(
      /Bearer\s+[A-Za-z0-9._-]+/gi,
      'Bearer [REDACTED]'
    )
    .replace(
      /sk-or-v1-[A-Za-z0-9_-]+/gi,
      '[API_KEY_REDACTED]'
    )
    .replace(
      /sk-[A-Za-z0-9_-]{12,}/gi,
      '[API_KEY_REDACTED]'
    )
    .replace(
      /tvly-[A-Za-z0-9_-]+/gi,
      '[API_KEY_REDACTED]'
    );
}

// ======================================
// PROVIDER ERROR PARSER
// ======================================

function extractProviderError(raw) {
  const text = String(raw || '');

  try {
    const data = JSON.parse(text);
    const error = data.error;

    if (typeof error === 'string') {
      return error;
    }

    if (error && typeof error === 'object') {
      return (
        error.message ||
        error.detail ||
        JSON.stringify(error)
      );
    }

    return (
      data.message ||
      data.detail ||
      text ||
      'Provider tidak memberikan keterangan.'
    );

  } catch {
    return text || 'Provider tidak memberikan keterangan.';
  }
}

// ======================================
// FETCH WITH ERROR HANDLING
// ======================================

async function fetchProvider(
  url,
  options,
  timeoutMs,
  providerName
) {
  try {
    return await fetch(url, {
      ...options,
      signal: AbortSignal.timeout(timeoutMs)
    });

  } catch (error) {
    let message;

    if (
      error.name === 'TimeoutError' ||
      error.name === 'AbortError'
    ) {
      message =
        `${providerName} tidak merespons dalam ` +
        `${Math.round(timeoutMs / 1000)} detik.`;
    } else {
      const code =
        error.cause?.code ||
        error.code ||
        '';

      message =
        `${providerName} gagal dihubungi. ` +
        'Periksa koneksi server dan URL provider.';

      if (code) {
        message += ` Kode jaringan: ${code}.`;
      }
    }

    const wrapped = new Error(message);
    wrapped.statusCode = 502;

    throw wrapped;
  }
}

// ======================================
// AI CONFIGURATION CHECK
// ======================================

function getAIConfigurationError() {
  if (!AI_API_KEY) {
    return 'AI_API_KEY belum diatur di backend.';
  }

  if (!AI_MODEL) {
    return 'AI_MODEL belum diatur di backend.';
  }

  let parsed;

  try {
    parsed = new URL(AI_API_URL);
  } catch {
    return 'AI_API_URL tidak valid.';
  }

  if (
    parsed.protocol !== 'https:' &&
    parsed.hostname !== 'localhost' &&
    parsed.hostname !== '127.0.0.1'
  ) {
    return 'AI_API_URL harus menggunakan HTTPS.';
  }

  return null;
}

// ======================================
// AI REQUEST HEADERS
// ======================================

function getAIHeaders() {
  const headers = {
    'Authorization': `Bearer ${AI_API_KEY}`,
    'Content-Type': 'application/json'
  };

  // Header tambahan OpenRouter bersifat opsional.

  if (OPENROUTER_SITE_URL) {
    headers['HTTP-Referer'] = OPENROUTER_SITE_URL;
  }

  if (OPENROUTER_APP_NAME) {
    headers['X-Title'] = OPENROUTER_APP_NAME;
  }

  return headers;
}

// ======================================
// TAVILY WEB SEARCH
// ======================================

async function handleSearch(req, res) {
  if (!TAVILY_API_KEY) {
    return sendJson(res, 503, {
      error:
        'TAVILY_API_KEY belum diatur di backend.'
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
    /hari ini|today|sekarang/i.test(query)
      ? 'day'
      : /terbaru|terkini|minggu ini|this week/i.test(query)
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
      Math.min(
        5,
        Number(body.max_results) || 5
      )
    ),

    include_answer: false,
    include_raw_content: false
  };

  if (timeRange) {
    requestBody.time_range = timeRange;
  }

  const upstream = await fetchProvider(
    'https://api.tavily.com/search',
    {
      method: 'POST',

      headers: {
        'Authorization': `Bearer ${TAVILY_API_KEY}`,
        'Content-Type': 'application/json'
      },

      body: JSON.stringify(requestBody)

    },
    SEARCH_TIMEOUT_MS,
    'Tavily'
  );

  const raw = await upstream.text().catch(() => '');

  let result = {};

  try {
    result = raw ? JSON.parse(raw) : {};
  } catch {
    result = {};
  }

  if (!upstream.ok) {
    const message = safeProviderMessage(
      extractProviderError(raw) ||
      `Tavily HTTP ${upstream.status}`
    );

    console.error(
      `[TAVILY] HTTP ${upstream.status}: ${message}`
    );

    return sendJson(res, 502, {
      error:
        `Pencarian Tavily gagal: ${message}`,
      providerStatus: upstream.status
    });
  }

  const results = Array.isArray(result.results)
    ? result.results
        .slice(0, 5)
        .map(item => ({
          title: String(
            item.title || 'Sumber web'
          ).slice(0, 240),

          url: String(item.url || ''),

          content: String(
            item.content || ''
          ).slice(0, 3500),

          score: Number.isFinite(item.score)
            ? item.score
            : null,

          published_date:
            item.published_date ||
            item.publishedDate ||
            null

        }))
        .filter(item =>
          /^https:\/\//i.test(item.url)
        )
    : [];

  return sendJson(res, 200, {
    query,
    results
  });
}

// ======================================
// AI CHAT — GEMMA / OPENROUTER
// ======================================

async function handleChat(req, res) {
  const configError = getAIConfigurationError();

  if (configError) {
    return sendJson(res, 503, {
      error: configError
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

  // Menerima pesan teks maupun content array.
  //
  // Content array dibutuhkan untuk Vision.
  // Contoh format gambar OpenAI-compatible:
  //
  // content: [
  //   { type: 'text', text: 'Jelaskan gambar ini.' },
  //   {
  //     type: 'image_url',
  //     image_url: {
  //       url: 'data:image/jpeg;base64,...'
  //     }
  //   }
  // ]
  //
  // Gambar diteruskan apa adanya ke provider.
  // Backend ini tidak mengubah atau menghapusnya.

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

  // Default non-streaming agar kompatibel dengan
  // frontend yang membaca hasil menggunakan response.json().
  //
  // Streaming hanya aktif jika frontend mengirim:
  // { "stream": true }

  const shouldStream = body.stream === true;

  const requestBody = {
    model: AI_MODEL,

    messages,

    temperature: 0.55,

    stream: shouldStream
  };

  let upstream;

  try {
    upstream = await fetchProvider(
      AI_API_URL,
      {
        method: 'POST',

        headers: getAIHeaders(),

        body: JSON.stringify(requestBody)

      },
      AI_TIMEOUT_MS,
      'Provider AI'
    );

  } catch (error) {
    console.error(
      '[AI CONNECTION]',
      safeProviderMessage(error.message)
    );

    throw error;
  }

  // ======================================
  // PROVIDER ERROR
  // ======================================

  if (!upstream.ok) {
    const raw = await upstream.text().catch(() => '');

    const message = safeProviderMessage(
      extractProviderError(raw) ||
      upstream.statusText ||
      `HTTP ${upstream.status}`
    );

    console.error(
      `[AI PROVIDER] HTTP ${upstream.status}: ${message}`
    );

    return sendJson(res, 502, {
      error:
        `Provider AI menolak permintaan ` +
        `(HTTP ${upstream.status}): ${message}`,

      providerStatus: upstream.status,

      model: AI_MODEL
    });
  }

  const contentType =
    upstream.headers.get('content-type') || '';

  // ======================================
  // STREAMING RESPONSE
  // ======================================

  if (
    contentType.includes('text/event-stream') &&
    upstream.body
  ) {
    res.writeHead(200, {
      'Content-Type':
        'text/event-stream; charset=utf-8',

      'Cache-Control':
        'no-cache, no-transform',

      'Connection':
        'keep-alive',

      'X-Accel-Buffering':
        'no',

      'X-Content-Type-Options':
        'nosniff'
    });

    try {
      for await (const chunk of upstream.body) {
        if (res.destroyed) break;

        res.write(Buffer.from(chunk));
      }

      if (!res.destroyed) {
        res.end();
      }

    } catch (error) {
      console.error(
        '[AI STREAM]',
        safeProviderMessage(error.message)
      );

      if (!res.destroyed) {
        const message = safeProviderMessage(
          error.message || 'Streaming terputus.'
        );

        res.write(
          `data: ${JSON.stringify({
            error: message
          })}\n\n`
        );

        res.end();
      }
    }

    return;
  }

  // ======================================
  // NON-STREAMING RESPONSE
  // ======================================

  const raw = await upstream.text().catch(() => '');

  let data;

  try {
    data = raw ? JSON.parse(raw) : null;
  } catch {
    data = null;
  }

  if (!data) {
    return sendJson(res, 502, {
      error:
        'Provider AI mengirim respons JSON tidak valid.'
    });
  }

  // OpenRouter dapat mengirim error pada respons
  // yang sudah berstatus HTTP 200.

  if (data.error) {
    const message = safeProviderMessage(
      extractProviderError(JSON.stringify(data.error))
    );

    return sendJson(res, 502, {
      error: `Provider AI gagal: ${message}`,
      model: AI_MODEL
    });
  }

  return sendJson(res, 200, data);
}

// ======================================
// REAL AI CONNECTION TEST
// ======================================

// /api/health hanya memeriksa server dan konfigurasi.
// /api/test-ai benar-benar mengirim satu prompt ke AI.

async function handleTestAI(req, res) {
  const configError = getAIConfigurationError();

  if (configError) {
    return sendJson(res, 503, {
      ok: false,
      error: configError
    });
  }

  const upstream = await fetchProvider(
    AI_API_URL,
    {
      method: 'POST',

      headers: getAIHeaders(),

      body: JSON.stringify({
        model: AI_MODEL,

        messages: [
          {
            role: 'user',
            content: 'Reply with exactly: NARA_OK'
          }
        ],

        temperature: 0,
        stream: false
      })

    },
    AI_TIMEOUT_MS,
    'Provider AI'
  );

  const raw = await upstream.text().catch(() => '');

  let data = null;

  try {
    data = raw ? JSON.parse(raw) : null;
  } catch {
    data = null;
  }

  if (!upstream.ok) {
    const message = safeProviderMessage(
      extractProviderError(raw) ||
      `HTTP ${upstream.status}`
    );

    return sendJson(res, 502, {
      ok: false,
      error:
        `Tes koneksi AI gagal ` +
        `(HTTP ${upstream.status}): ${message}`,

      providerStatus: upstream.status,
      model: AI_MODEL
    });
  }

  if (!data) {
    return sendJson(res, 502, {
      ok: false,
      error: 'Respons tes AI bukan JSON yang valid.'
    });
  }

  if (data.error) {
    return sendJson(res, 502, {
      ok: false,
      error: safeProviderMessage(
        extractProviderError(
          JSON.stringify(data.error)
        )
      )
    });
  }

  const messageContent =
    data.choices?.[0]?.message?.content;

  let reply = '';

  if (typeof messageContent === 'string') {
    reply = messageContent;
  } else if (Array.isArray(messageContent)) {
    reply = messageContent
      .filter(part => part && part.type === 'text')
      .map(part => part.text || '')
      .join('');
  }

  return sendJson(res, 200, {
    ok: true,

    message: 'Koneksi AI berhasil.',

    provider: 'OpenRouter',

    model: AI_MODEL,

    reply: reply || 'AI merespons tanpa teks.'
  });
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
    'Content-Type':
      'text/html; charset=utf-8',

    'Cache-Control':
      'no-store',

    'X-Content-Type-Options':
      'nosniff'
  });

  const stream = fs.createReadStream(file);

  stream.on('error', error => {
    console.error(
      '[HTML]',
      safeProviderMessage(error.message)
    );

    if (!res.headersSent) {
      sendJson(res, 500, {
        error: 'Gagal membaca index.html.'
      });
    } else if (!res.destroyed) {
      res.destroy(error);
    }
  });

  stream.pipe(res);
}

// ======================================
// SERVER ROUTES
// ======================================

const server = http.createServer(async (req, res) => {
  let url;

  try {
    // CORS harus diproses sebelum route.

    if (!applyCors(req, res)) {
      return;
    }

    // Preflight browser.

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      return res.end();
    }

    url = new URL(
      req.url,
      `http://${req.headers.host || 'localhost'}`
    );

    // ======================================
    // HEALTH CHECK
    // ======================================

    if (
      req.method === 'GET' &&
      url.pathname === '/api/health'
    ) {
      let providerHost = null;

      try {
        providerHost = new URL(AI_API_URL).hostname;
      } catch {
        providerHost = null;
      }

      return sendJson(res, 200, {
        ok: true,

        app: 'Nara AI Backend',

        version: '2.0.0',

        aiConfigured: Boolean(
          AI_API_KEY && AI_MODEL
        ),

        aiProvider: providerHost,

        aiModel: AI_MODEL || null,

        tavilyConfigured: Boolean(
          TAVILY_API_KEY
        ),

        streamingDefault: false,

        visionPassthrough: true
      });
    }

    // ======================================
    // REAL AI TEST
    // ======================================

    if (
      req.method === 'GET' &&
      url.pathname === '/api/test-ai'
    ) {
      if (!rateLimit(req, res)) return;

      return await handleTestAI(req, res);
    }

    // ======================================
    // MAIN PAGE
    // ======================================

    if (
      req.method === 'GET' &&
      (
        url.pathname === '/' ||
        url.pathname === '/index.html'
      )
    ) {
      return serveIndex(res);
    }

    // ======================================
    // FAVICON
    // ======================================

    if (
      req.method === 'GET' &&
      url.pathname === '/favicon.ico'
    ) {
      res.writeHead(204);
      return res.end();
    }

    // ======================================
    // AI AND SEARCH
    // ======================================

    if (
      req.method === 'POST' &&
      (
        url.pathname === '/api/chat' ||
        url.pathname === '/api/search'
      )
    ) {
      if (!rateLimit(req, res)) {
        return;
      }

      if (url.pathname === '/api/chat') {
        return await handleChat(req, res);
      }

      if (url.pathname === '/api/search') {
        return await handleSearch(req, res);
      }
    }

    // ======================================
    // UNKNOWN ROUTE
    // ======================================

    return sendJson(res, 404, {
      error: 'Route tidak ditemukan.',
      path: url.pathname
    });

  } catch (error) {
    const status = Number(error.statusCode) || 500;

    const message = safeProviderMessage(
      error.message || 'Kesalahan server.'
    );

    console.error(
      `[SERVER ERROR] ${req.method} ` +
      `${url?.pathname || req.url}: ${message}`
    );

    return sendJson(res, status, {
      error: message
    });
  }
});

// ======================================
// SERVER SETTINGS
// ======================================

server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;
server.requestTimeout = 120000;

// ======================================
// SERVER ERROR HANDLING
// ======================================

server.on('error', error => {
  console.error(
    '[SERVER]',
    safeProviderMessage(error.message)
  );
});

server.on('clientError', (error, socket) => {
  console.error(
    '[CLIENT]',
    safeProviderMessage(error.message)
  );

  if (socket.writable) {
    socket.end(
      'HTTP/1.1 400 Bad Request\r\n\r\n'
    );
  }
});

// ======================================
// START
// ======================================

server.listen(PORT, '0.0.0.0', () => {
  console.log('================================');
  console.log('NARA AI BACKEND');
  console.log('================================');

  console.log(
    `Server berjalan pada port: ${PORT}`
  );

  console.log(
    `AI configured: ${Boolean(AI_API_KEY && AI_MODEL)}`
  );

  console.log(
    `AI URL: ${AI_API_URL}`
  );

  console.log(
    `AI model: ${AI_MODEL || '(belum diatur)'}`
  );

  console.log(
    `Tavily configured: ${Boolean(TAVILY_API_KEY)}`
  );

  console.log(
    `CORS: ${ALLOWED_ORIGINS.join(', ')}`
  );

  console.log(
    'Streaming default: false'
  );

  console.log(
    'Vision passthrough: enabled'
  );

  console.log('================================');
});
