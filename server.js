'use strict';

// Nara AI Backend — Node.js 20+
// Groq Chat Completions + Tavily Search + PostgreSQL Auth.
// API keys hanya disimpan di Environment Variables.

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { URL } = require('node:url');

// MODUL AUTENTIKASI POSTGRESQL
const auth = require('./auth');

const ROOT = __dirname;
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';

// ========================================
// GROQ CONFIGURATION
// ========================================

const AI_API_URL = String(
  process.env.AI_API_URL ||
  'https://api.groq.com/openai/v1/chat/completions'
).trim();

const AI_API_KEY = String(
  process.env.AI_API_KEY ||
  process.env.GROQ_API_KEY ||
  ''
).trim();

const AI_MODEL = String(
  process.env.AI_MODEL ||
  'openai/gpt-oss-120b'
).trim();

// ========================================
// TAVILY CONFIGURATION
// ========================================

const TAVILY_API_KEY = String(
  process.env.TAVILY_API_KEY || ''
).trim();

const TAVILY_API_URL = String(
  process.env.TAVILY_API_URL ||
  'https://api.tavily.com/search'
).trim();

// ========================================
// GENERAL CONFIGURATION
// ========================================

const DEFAULT_STREAMING =
  String(process.env.DEFAULT_STREAMING || 'false')
    .toLowerCase() === 'true';

// GPT-OSS 120B hanya menerima teks.
// Aktifkan vision hanya jika menggunakan model
// yang mendukung gambar.
const VISION_ENABLED =
  String(process.env.VISION_ENABLED || 'false')
    .toLowerCase() === 'true';

const REQUEST_TIMEOUT_MS = Math.max(
  5000,
  Number(process.env.REQUEST_TIMEOUT_MS || 90000)
);

const MAX_BODY_BYTES = Math.max(
  1024 * 1024,
  Number(process.env.MAX_BODY_BYTES || 15 * 1024 * 1024)
);

const RATE_LIMIT_WINDOW_MS = Math.max(
  10000,
  Number(process.env.RATE_LIMIT_WINDOW_MS || 60000)
);

const RATE_LIMIT_MAX = Math.max(
  1,
  Number(process.env.RATE_LIMIT_MAX || 40)
);

const ALLOWED_ORIGINS = String(
  process.env.ALLOWED_ORIGINS || '*'
)
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);

const REQUIRE_AUTH_CHAT =
  String(process.env.REQUIRE_AUTH_CHAT || 'false') === 'true';

// ========================================
// MIME TYPES
// ========================================

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.map': 'application/json; charset=utf-8',
};

const rateBuckets = new Map();

// ========================================
// LOGGER
// ========================================

function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

// ========================================
// JSON RESPONSE
// ========================================

function sendJSON(res, statusCode, data, extraHeaders = {}) {
  if (res.writableEnded || res.destroyed) return;

  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });

  res.end(JSON.stringify(data));
}

// ========================================
// CLIENT IP
// ========================================

function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];

  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim();
  }

  return req.socket.remoteAddress || 'unknown';
}

// ========================================
// CORS
// ========================================

function applyCors(req, res) {
  const origin = req.headers.origin;

  const wildcard = ALLOWED_ORIGINS.includes('*');

  const allowed =
    !origin ||
    wildcard ||
    ALLOWED_ORIGINS.includes(origin);

  if (origin && allowed) {
    res.setHeader(
      'Access-Control-Allow-Origin',
      wildcard ? '*' : origin
    );

    if (!wildcard) {
      res.setHeader('Vary', 'Origin');
    }
  }

  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET, POST, OPTIONS, HEAD'
  );

  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization'
  );

  res.setHeader(
    'Access-Control-Max-Age',
    '86400'
  );

  return allowed;
}

// ========================================
// RATE LIMIT
// ========================================

function checkRateLimit(req, res) {
  const now = Date.now();
  const ip = getClientIP(req);

  let bucket = rateBuckets.get(ip);

  if (!bucket || now >= bucket.resetAt) {
    bucket = {
      count: 0,
      resetAt: now + RATE_LIMIT_WINDOW_MS,
    };
  }

  bucket.count += 1;
  rateBuckets.set(ip, bucket);

  if (rateBuckets.size > 5000) {
    for (const [key, value] of rateBuckets) {
      if (now >= value.resetAt) {
        rateBuckets.delete(key);
      }
    }
  }

  res.setHeader(
    'X-RateLimit-Limit',
    String(RATE_LIMIT_MAX)
  );

  res.setHeader(
    'X-RateLimit-Remaining',
    String(Math.max(0, RATE_LIMIT_MAX - bucket.count))
  );

  res.setHeader(
    'X-RateLimit-Reset',
    String(Math.ceil(bucket.resetAt / 1000))
  );

  if (bucket.count > RATE_LIMIT_MAX) {
    const retryAfter = Math.max(
      1,
      Math.ceil((bucket.resetAt - now) / 1000)
    );

    res.setHeader('Retry-After', String(retryAfter));

    sendJSON(res, 429, {
      ok: false,
      error: 'Terlalu banyak request. Coba lagi sebentar.',
      retryAfter,
    });

    return false;
  }

  return true;
}

// ========================================
// REQUEST BODY
// ========================================

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    let settled = false;

    req.on('data', (chunk) => {
      if (settled) return;

      size += chunk.length;

      if (size > MAX_BODY_BYTES) {
        settled = true;

        reject(
          Object.assign(
            new Error('Ukuran request terlalu besar.'),
            { statusCode: 413 }
          )
        );

        req.destroy();
        return;
      }

      chunks.push(chunk);
    });

    req.on('end', () => {
      if (settled) return;

      if (size === 0) {
        return resolve({});
      }

      try {
        resolve(
          JSON.parse(
            Buffer.concat(chunks).toString('utf8')
          )
        );
      } catch {
        reject(
          Object.assign(
            new Error('Body harus berupa JSON yang valid.'),
            { statusCode: 400 }
          )
        );
      }
    });

    req.on('error', (error) => {
      if (!settled) reject(error);
    });
  });
}

// ========================================
// STRING HELPER
// ========================================

function safeString(value, maxLength = 20000) {
  return typeof value === 'string'
    ? value.slice(0, maxLength)
    : '';
}

// ========================================
// IMAGE HELPER
// ========================================

function normaliseImage(image) {
  if (!image) return null;

  if (typeof image === 'string') {
    return /^(https?:\/\/|data:image\/)/i.test(image)
      ? image
      : null;
  }

  if (typeof image === 'object') {
    const imageUrl =
      image.url ||
      image.dataUrl ||
      image.data_url;

    return (
      typeof imageUrl === 'string' &&
      /^(https?:\/\/|data:image\/)/i.test(imageUrl)
    )
      ? imageUrl
      : null;
  }

  return null;
}

function getImageInputs(body) {
  const images = [];

  if (body.image) images.push(body.image);
  if (body.image_url) images.push(body.image_url);
  if (body.imageUrl) images.push(body.imageUrl);

  if (Array.isArray(body.images)) {
    images.push(...body.images);
  }

  return images
    .map(normaliseImage)
    .filter(Boolean);
}

// ========================================
// BUILD AI MESSAGES
// ========================================

function buildMessages(body, imageUrls = []) {
  let messages = Array.isArray(body.messages)
    ? body.messages
    : [];

  messages = messages
    .filter(
      (item) =>
        item &&
        ['system', 'user', 'assistant'].includes(item.role)
    )
    .map((item) => ({
      role: item.role,
      content:
        typeof item.content === 'string' ||
        Array.isArray(item.content)
          ? item.content
          : String(item.content ?? ''),
    }));

  const systemPrompt = safeString(
    body.systemPrompt ||
    body.system ||
    body.instructions,
    12000
  ).trim();

  if (
    systemPrompt &&
    !messages.some((message) => message.role === 'system')
  ) {
    messages.unshift({
      role: 'system',
      content: systemPrompt,
    });
  }

  if (messages.length === 0) {
    const prompt = safeString(
      body.message ||
      body.prompt ||
      body.input ||
      body.text,
      30000
    ).trim();

    if (prompt) {
      messages.push({
        role: 'user',
        content: prompt,
      });
    }
  }

  if (imageUrls.length > 0) {
    let userIndex = -1;

    for (let i = messages.length - 1; i >= 0; i -= 1) {
      if (messages[i].role === 'user') {
        userIndex = i;
        break;
      }
    }

    if (userIndex === -1) {
      messages.push({
        role: 'user',
        content: 'Tolong analisis gambar berikut.',
      });

      userIndex = messages.length - 1;
    }

    const current = messages[userIndex].content;

    const parts =
      typeof current === 'string'
        ? [{ type: 'text', text: current }]
        : Array.isArray(current)
          ? [...current]
          : [
              {
                type: 'text',
                text: String(current ?? ''),
              },
            ];

    for (const imageUrl of imageUrls) {
      parts.push({
        type: 'image_url',
        image_url: {
          url: imageUrl,
        },
      });
    }

    messages[userIndex] = {
      role: 'user',
      content: parts,
    };
  }

  return messages;
}

// ========================================
// PROVIDER ERROR
// ========================================

function extractProviderError(data, fallback) {
  if (!data || typeof data !== 'object') {
    return fallback;
  }

  const error = data.error;

  if (typeof error === 'string') {
    return error.slice(0, 1200);
  }

  if (error && typeof error.message === 'string') {
    return error.message.slice(0, 1200);
  }

  if (typeof data.message === 'string') {
    return data.message.slice(0, 1200);
  }

  return fallback;
}

// ========================================
// READ PROVIDER JSON
// ========================================

async function readUpstreamJSON(response) {
  const raw = await response.text();

  if (!raw) return {};

  try {
    return JSON.parse(raw);
  } catch {
    return {
      message: raw.slice(0, 1200),
    };
  }
}

// ========================================
// EXTRACT AI RESPONSE
// ========================================

function extractReply(data) {
  const content =
    data?.choices?.[0]?.message?.content ??
    data?.choices?.[0]?.text ??
    data?.output_text ??
    '';

  if (typeof content === 'string') {
    return content;
  }

  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (typeof part === 'string') {
          return part;
        }

        if (part && typeof part.text === 'string') {
          return part.text;
        }

        return '';
      })
      .join('');
  }

  return '';
}

// ========================================
// GROQ API REQUEST
// ========================================

async function callAI(messages, options = {}) {
  if (!AI_API_KEY) {
    throw Object.assign(
      new Error(
        'API key Groq belum diatur. Isi AI_API_KEY atau GROQ_API_KEY di Environment Variables.'
      ),
      { statusCode: 503 }
    );
  }

  const requestBody = {
    model: AI_MODEL,
    messages,
    stream: Boolean(options.stream),
  };

  if (Number.isFinite(Number(options.temperature))) {
    requestBody.temperature = Math.min(
      2,
      Math.max(0, Number(options.temperature))
    );
  }

  if (Number.isFinite(Number(options.top_p))) {
    requestBody.top_p = Math.min(
      1,
      Math.max(0, Number(options.top_p))
    );
  }

  if (Number.isFinite(Number(options.max_tokens))) {
    requestBody.max_tokens = Math.min(
      65536,
      Math.max(1, Number(options.max_tokens))
    );
  }

  try {
    const response = await fetch(AI_API_URL, {
      method: 'POST',

      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${AI_API_KEY}`,
      },

      body: JSON.stringify(requestBody),

      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    return response;
  } catch (error) {
    if (
      error.name === 'AbortError' ||
      error.name === 'TimeoutError'
    ) {
      throw Object.assign(
        new Error('Request ke provider AI melewati batas waktu.'),
        { statusCode: 504 }
      );
    }

    throw Object.assign(
      new Error(
        `Tidak dapat terhubung ke provider AI: ${error.message}`
      ),
      { statusCode: 502 }
    );
  }
}

// ========================================
// AI CHAT
// ========================================

async function handleAIChat(res, body) {
  const imageUrls = getImageInputs(body);

  if (imageUrls.length > 0 && !VISION_ENABLED) {
    return sendJSON(res, 400, {
      ok: false,
      error:
        `Model ${AI_MODEL} yang sedang digunakan hanya menerima teks, bukan gambar. Ganti ke model Groq yang mendukung vision sebelum mengaktifkan analisis gambar.`,
    });
  }

  const messages = buildMessages(
    body,
    VISION_ENABLED ? imageUrls : []
  );

  if (messages.length === 0) {
    return sendJSON(res, 400, {
      ok: false,
      error: 'Pesan kosong. Kirim message atau messages.',
    });
  }

  const stream =
    typeof body.stream === 'boolean'
      ? body.stream
      : DEFAULT_STREAMING;

  let upstream;

  try {
    upstream = await callAI(messages, {
      stream,
      temperature: body.temperature,
      top_p: body.top_p,
      max_tokens: body.max_tokens,
    });
  } catch (error) {
    log('[AI PROVIDER] request gagal:', error.message);

    return sendJSON(
      res,
      error.statusCode || 502,
      {
        ok: false,
        error: error.message,
      }
    );
  }

  if (!upstream.ok) {
    const data = await readUpstreamJSON(upstream);

    const message = extractProviderError(
      data,
      `Provider Groq menolak request (HTTP ${upstream.status}).`
    );

    log(`[AI PROVIDER] HTTP ${upstream.status}:`, message);

    return sendJSON(res, upstream.status, {
      ok: false,
      error: message,
      status: upstream.status,
      provider: 'Groq',
    });
  }

  // STREAMING
  if (stream) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
    });

    if (!upstream.body) {
      res.end('data: [DONE]\n\n');
      return;
    }

    const reader = upstream.body.getReader();

    try {
      while (true) {
        const { done, value } = await reader.read();

        if (done) break;

        if (res.destroyed) {
          await reader.cancel();
          return;
        }

        if (value) {
          res.write(Buffer.from(value));
        }
      }
    } catch (error) {
      if (!res.destroyed) {
        const safeMessage = String(
          error.message || 'Streaming terputus.'
        ).replace(/[\r\n]/g, ' ');

        res.write(
          `data: ${JSON.stringify({
            error: safeMessage,
          })}\n\n`
        );
      }
    } finally {
      if (!res.writableEnded) {
        res.end();
      }
    }

    return;
  }

  // NORMAL RESPONSE
  const data = await readUpstreamJSON(upstream);
  const reply = extractReply(data);

  return sendJSON(res, 200, {
    ok: true,
    reply,
    content: reply,
    answer: reply,
    model: data.model || AI_MODEL,
    choices: data.choices || [],
    usage: data.usage || null,
  });
}

// ========================================
// AI CONNECTION TEST
// ========================================

async function handleTestAI(res) {
  const messages = [
    {
      role: 'user',
      content:
        'Balas singkat dalam Bahasa Indonesia: Koneksi Nara AI berhasil.',
    },
  ];

  let upstream;

  try {
    upstream = await callAI(messages, {
      stream: false,
      max_tokens: 100,
      temperature: 0.2,
    });
  } catch (error) {
    log('[AI TEST] gagal:', error.message);

    return sendJSON(
      res,
      error.statusCode || 502,
      {
        ok: false,
        connected: false,
        error: error.message,
      }
    );
  }

  if (!upstream.ok) {
    const data = await readUpstreamJSON(upstream);

    const message = extractProviderError(
      data,
      `Provider Groq menolak tes (HTTP ${upstream.status}).`
    );

    log(`[AI TEST] HTTP ${upstream.status}:`, message);

    return sendJSON(res, upstream.status, {
      ok: false,
      connected: false,
      error: message,
      status: upstream.status,
      model: AI_MODEL,
    });
  }

  const data = await readUpstreamJSON(upstream);
  const reply = extractReply(data);

  return sendJSON(res, 200, {
    ok: true,
    connected: true,
    message: 'Koneksi ke Groq berhasil.',
    reply,
    model: data.model || AI_MODEL,
  });
}

// ========================================
// TAVILY SEARCH
// ========================================

async function handleSearch(res, body) {
  if (!TAVILY_API_KEY) {
    return sendJSON(res, 503, {
      ok: false,
      error: 'TAVILY_API_KEY belum diatur di Environment Variables.',
    });
  }

  const query = safeString(
    body.query || body.q || body.search,
    1000
  ).trim();

  if (!query) {
    return sendJSON(res, 400, {
      ok: false,
      error: 'Query pencarian tidak boleh kosong.',
    });
  }

  const requestBody = {
    api_key: TAVILY_API_KEY,
    query,

    search_depth:
      body.search_depth === 'advanced'
        ? 'advanced'
        : 'basic',

    topic: ['news', 'general', 'finance'].includes(body.topic)
      ? body.topic
      : 'general',

    max_results: Math.min(
      10,
      Math.max(1, Number(body.max_results) || 5)
    ),

    include_answer: body.include_answer !== false,
    include_raw_content: false,
  };

  let upstream;

  try {
    upstream = await fetch(TAVILY_API_URL, {
      method: 'POST',

      headers: {
        'Content-Type': 'application/json',
      },

      body: JSON.stringify(requestBody),

      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (error) {
    const timedOut =
      error.name === 'AbortError' ||
      error.name === 'TimeoutError';

    const message = timedOut
      ? 'Pencarian Tavily melewati batas waktu.'
      : `Tidak dapat terhubung ke Tavily: ${error.message}`;

    log('[TAVILY] request gagal:', message);

    return sendJSON(
      res,
      timedOut ? 504 : 502,
      {
        ok: false,
        error: message,
      }
    );
  }

  const data = await readUpstreamJSON(upstream);

  if (!upstream.ok) {
    const message = extractProviderError(
      data,
      `Tavily menolak request (HTTP ${upstream.status}).`
    );

    log(`[TAVILY] HTTP ${upstream.status}:`, message);

    return sendJSON(res, upstream.status, {
      ok: false,
      error: message,
      status: upstream.status,
    });
  }

  return sendJSON(res, 200, {
    ok: true,
    query,
    answer: data.answer || '',
    results: Array.isArray(data.results)
      ? data.results
      : [],
    response_time: data.response_time ?? null,
    raw: data,
  });
}

// ========================================
// STATIC FILES
// ========================================

function contentTypeFor(filePath) {
  return (
    MIME_TYPES[path.extname(filePath).toLowerCase()] ||
    'application/octet-stream'
  );
}

function serveStatic(req, res, decodedPath) {
  if (decodedPath.includes('\0')) {
    return sendJSON(res, 400, {
      ok: false,
      error: 'Path tidak valid.',
    });
  }

  const relativePath =
    decodedPath === '/'
      ? 'index.html'
      : decodedPath.replace(/^\/+/, '');

  let filePath = path.resolve(ROOT, relativePath);

  if (
    filePath !== ROOT &&
    !filePath.startsWith(ROOT + path.sep)
  ) {
    return sendJSON(res, 403, {
      ok: false,
      error: 'Akses file ditolak.',
    });
  }

  try {
    if (
      fs.existsSync(filePath) &&
      fs.statSync(filePath).isDirectory()
    ) {
      filePath = path.join(filePath, 'index.html');
    }
  } catch {
    return sendJSON(res, 404, {
      ok: false,
      error: 'File tidak ditemukan.',
    });
  }

  if (
    !fs.existsSync(filePath) ||
    !fs.statSync(filePath).isFile()
  ) {
    const indexPath = path.join(ROOT, 'index.html');

    if (
      !path.extname(decodedPath) &&
      fs.existsSync(indexPath)
    ) {
      filePath = indexPath;
    } else {
      return sendJSON(res, 404, {
        ok: false,
        error: 'File tidak ditemukan.',
        path: decodedPath,
      });
    }
  }

  res.writeHead(200, {
    'Content-Type': contentTypeFor(filePath),

    'Cache-Control':
      path.extname(filePath) === '.html'
        ? 'no-cache'
        : 'public, max-age=3600',
  });

  if (req.method === 'HEAD') {
    return res.end();
  }

  const fileStream = fs.createReadStream(filePath);

  fileStream.on('error', (error) => {
    log('[STATIC] gagal membaca file:', error.message);

    if (!res.headersSent) {
      sendJSON(res, 500, {
        ok: false,
        error: 'Gagal membaca file.',
      });
    } else {
      res.destroy(error);
    }
  });

  fileStream.pipe(res);
}

// ========================================
// MAIN ROUTER
// ========================================

async function handleRequest(req, res) {
  if (!applyCors(req, res)) {
    return sendJSON(res, 403, {
      ok: false,
      error: 'Origin tidak diizinkan oleh CORS.',
    });
  }

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  let url;
  let decodedPath;

  try {
    url = new URL(
      req.url,
      `http://${req.headers.host || 'localhost'}`
    );

    decodedPath = decodeURIComponent(url.pathname);
  } catch {
    return sendJSON(res, 400, {
      ok: false,
      error: 'URL request tidak valid.',
    });
  }

  // Menghapus karakter tersembunyi seperti Word Joiner,
  // zero-width characters, dan BOM.

  decodedPath = decodedPath
    .normalize('NFC')
    .replace(/[\u200B-\u200D\u2060\uFEFF]/g, '');

  let pathname = decodedPath;

  // Normalisasi slash dan titik di ujung endpoint API.
  if (pathname.startsWith('/api/')) {
    pathname = pathname.replace(/[/.]+$/, '') || '/';
  }

  const isAPI = pathname.startsWith('/api/');

  if (isAPI && !checkRateLimit(req, res)) {
    return;
  }

  // ========================================
  // HEALTH CHECK
  // GET /api/health
  // ========================================

  if (
    pathname === '/api/health' &&
    req.method === 'GET'
  ) {
    return sendJSON(res, 200, {
      ok: true,
      status: 'online',
      service: 'NARA AI BACKEND',
      timestamp: new Date().toISOString(),

      aiConfigured: Boolean(AI_API_KEY),
      aiProvider: 'Groq-compatible API',
      aiUrl: AI_API_URL,
      aiModel: AI_MODEL,

      tavilyConfigured: Boolean(TAVILY_API_KEY),

      streamingDefault: DEFAULT_STREAMING,
      visionEnabled: VISION_ENABLED,

      // Konfigurasi akun dan email.
      // Ini menunjukkan konfigurasi tersedia,
      // bukan tes koneksi database/email secara langsung.
      dbConfigured: Boolean(auth.configured),
      emailVerificationEnabled: Boolean(auth.verifyEnabled),
      emailConfigured: Boolean(auth.mailConfigured),

      requireAuthChat: REQUIRE_AUTH_CHAT,
    });
  }

  // ========================================
  // AUTHENTICATION ROUTES
  // ========================================

  if (
    isAPI &&
    pathname.startsWith('/api/auth/')
  ) {
    const body =
      req.method === 'POST'
        ? await readRequestBody(req)
        : {};

    return auth.handle(
      req,
      res,
      pathname,
      body,
      sendJSON
    );
  }

  // ========================================
  // AI TEST
  // GET /api/test-ai
  // POST /api/test-ai
  // ========================================

  if (
    pathname === '/api/test-ai' &&
    ['GET', 'POST'].includes(req.method)
  ) {
    return handleTestAI(res);
  }

  // ========================================
  // AI CHAT
  // POST /api/chat
  // ========================================

  if (
    pathname === '/api/chat' &&
    req.method === 'POST'
  ) {
    const body = await readRequestBody(req);

    // Jika login diwajibkan tetapi PostgreSQL
    // belum dikonfigurasi, jangan izinkan akses.
    if (
      REQUIRE_AUTH_CHAT &&
      !auth.configured
    ) {
      return sendJSON(res, 503, {
        ok: false,
        error:
          'Database akun belum dikonfigurasi. ' +
          'Chat sementara tidak tersedia.',
      });
    }

    // Pemeriksaan sesi dan batas penggunaan harian.
    const q = await auth.quota(req);

    if (!q.ok) {
      return sendJSON(res, q.status, {
        ok: false,
        error: q.error,
      });
    }

    return handleAIChat(
      res,
      body && typeof body === 'object'
        ? body
        : {}
    );
  }

  // ========================================
  // TAVILY SEARCH
  // POST /api/search
  // ========================================

  if (
    pathname === '/api/search' &&
    req.method === 'POST'
  ) {
    const body = await readRequestBody(req);

    return handleSearch(
      res,
      body && typeof body === 'object'
        ? body
        : {}
    );
  }

  // ========================================
  // API ROUTE NOT FOUND
  // ========================================

  if (isAPI) {
    return sendJSON(res, 404, {
      ok: false,
      error: 'Route API tidak ditemukan.',
      path: pathname,
    });
  }

  // ========================================
  // FRONTEND STATIC FILES
  // ========================================

  if (['GET', 'HEAD'].includes(req.method)) {
    return serveStatic(req, res, decodedPath);
  }

  return sendJSON(res, 405, {
    ok: false,
    error: 'Method tidak diizinkan.',
  });
}

// ========================================
// HTTP SERVER
// ========================================

const server = http.createServer((req, res) => {
  handleRequest(req, res).catch((error) => {
    log(
      '[SERVER ERROR]',
      error.stack || error.message || error
    );

    if (!res.headersSent) {
      sendJSON(res, error.statusCode || 500, {
        ok: false,

        error:
          error.statusCode === 413
            ? 'Ukuran request terlalu besar.'
            : error.statusCode === 400
              ? error.message
              : 'Terjadi kesalahan internal pada server.',
      });
    } else if (!res.writableEnded) {
      res.end();
    }
  });
});

server.requestTimeout = REQUEST_TIMEOUT_MS + 15000;

server.headersTimeout = Math.max(
  server.requestTimeout + 5000,
  60000
);

// ========================================
// START SERVER
// ========================================

server.listen(PORT, HOST, () => {
  log('================================');
  log('NARA AI BACKEND');
  log('================================');

  log(`Server berjalan pada port: ${PORT}`);
  log(`AI configured: ${Boolean(AI_API_KEY)}`);
  log(`AI URL: ${AI_API_URL}`);
  log(`AI model: ${AI_MODEL}`);
  log(`Tavily configured: ${Boolean(TAVILY_API_KEY)}`);
  log(`CORS: ${ALLOWED_ORIGINS.join(',') || '(none)'}`);
  log(`Streaming default: ${DEFAULT_STREAMING}`);

  log(
    `Vision passthrough: ${VISION_ENABLED ? 'enabled' : 'disabled'}`
  );

  log(`Database configured: ${Boolean(auth.configured)}`);
  log(`Email configured: ${Boolean(auth.mailConfigured)}`);
  log(`Email verification: ${Boolean(auth.verifyEnabled)}`);
  log(`Require auth for chat: ${REQUIRE_AUTH_CHAT}`);

  log('================================');
});

// ========================================
// SERVER ERROR
// ========================================

server.on('error', (error) => {
  log('[SERVER FATAL]', error.message);
  process.exitCode = 1;
});

// ========================================
// GRACEFUL SHUTDOWN
// ========================================

function shutdown(signal) {
  log(`${signal} diterima, server sedang ditutup...`);

  server.close(() => process.exit(0));

  setTimeout(
    () => process.exit(1),
    10000
  ).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
