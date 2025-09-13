// A lightweight CORS proxy for Vercel (Node runtime).
// Features:
// - ?url=https://target.tld (or path style /api/proxy/https://target.tld)
// - Reflects Origin, supports credentials if ENABLE_CREDENTIALS=true
// - OPTIONS preflight with Access-Control-Max-Age
// - Hop-by-hop header scrubbing
// - Blocks localhost & private IP literal hosts by default
// - Optional ORIGIN_ALLOWLIST, ORIGIN_DENYLIST, REQUIRE_HEADER, API_KEY
// - Basic in-memory rate limiting (best-effort in serverless)
// - Redirects passed through with Location header

// ======= Configuration via env =======
const {
  ORIGIN_ALLOWLIST = "",      // CSV of allowed origins, empty = allow all
  ORIGIN_DENYLIST = "",       // CSV of blocked origins
  REQUIRE_HEADER = "",        // CSV of headers that must be present (e.g. "origin,x-requested-with")
  API_KEY = "",               // If set, clients must send header: x-proxy-key: <API_KEY>
  CORS_MAX_AGE = "600",       // seconds for preflight cache
  ENABLE_CREDENTIALS = "false", // "true" to allow cookies/Authorization through browser CORS
  RATE_LIMIT = "0",           // e.g. "100" requests per IP per 10 min window; "0" to disable
} = process.env;

// ======= Small helpers =======
const hopByHopHeaders = new Set([
  "connection","proxy-connection","keep-alive","transfer-encoding",
  "upgrade","te","trailer","proxy-authorization","proxy-authenticate"
]);

function parseCSV(s) {
  return (s || "").split(",").map(v => v.trim()).filter(Boolean);
}
const allowlist = new Set(parseCSV(ORIGIN_ALLOWLIST));
const denylist  = new Set(parseCSV(ORIGIN_DENYLIST));
const requiredHeaders = new Set(parseCSV(REQUIRE_HEADER).map(h => h.toLowerCase()));
const credentials = ENABLE_CREDENTIALS.toLowerCase() === "true";
const rateLimitMax = Math.max(0, parseInt(RATE_LIMIT, 10) || 0);

// naive in-memory RL for serverless (best-effort per instance)
const rlBucket = new Map();
const WINDOW_MS = 10 * 60 * 1000; // 10 minutes

function now() { return Date.now(); }

function rateLimitAllow(ip) {
  if (!rateLimitMax) return true;
  const t = now();
  const rec = rlBucket.get(ip) || { count: 0, reset: t + WINDOW_MS };
  if (t > rec.reset) {
    rec.count = 0;
    rec.reset = t + WINDOW_MS;
  }
  rec.count += 1;
  rlBucket.set(ip, rec);
  return rec.count <= rateLimitMax;
}

function getClientIP(req) {
  return (
    req.headers["x-real-ip"] ||
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.socket?.remoteAddress ||
    "0.0.0.0"
  );
}

function getTargetFromRequest(req) {
  // 1) ?url= param
  try {
    const u = new URL(req.url, "http://x"); // base to parse
    const q = u.searchParams.get("url");
    if (q) return q;
  } catch {}
  
  // 2) path style: /api/proxy/<full-encoded-url>
  const idx = req.url.indexOf("/api/proxy/");
  if (idx !== -1) {
    const part = req.url.slice(idx + "/api/proxy/".length);
    if (part) {
      try {
        // If it looks like "http:/", fix accidental encoding
        return decodeURIComponent(part);
      } catch {
        return part;
      }
    }
  }
  return "";
}

function isHttpHttps(urlStr) {
  try {
    const u = new URL(urlStr);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch { return false; }
}

function isBlockedPrivateHost(urlStr) {
  // Block obvious localhost/private IP literals to avoid SSRF
  try {
    const u = new URL(urlStr);
    const h = u.hostname || "";
    const lower = h.toLowerCase();
    
    if (lower === "localhost" || lower === "0.0.0.0" || lower === "127.0.0.1" || lower === "::1") return true;
    // block private IPv4 ranges by prefix match (not DNS resolution)
    if (/^10\./.test(lower)) return true;
    if (/^192\.168\./.test(lower)) return true;
    if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(lower)) return true;
    // Simple IPv6 private prefixes
    if (lower.startsWith("fc") || lower.startsWith("fd")) return true;
    return false;
  } catch { return true; }
}

function reflectCors(req, res) {
  const origin = req.headers.origin || "*";
  if (credentials) {
    // For credentials, must not use '*'
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Credentials", "true");
  } else {
    res.setHeader("Access-Control-Allow-Origin", "*");
  }
  res.setHeader("Access-Control-Expose-Headers", "*");
}

function preflight(req, res) {
  reflectCors(req, res);
  res.setHeader("Access-Control-Allow-Methods", "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS");
  const reqHeaders = req.headers["access-control-request-headers"];
  if (reqHeaders) res.setHeader("Access-Control-Allow-Headers", reqHeaders);
  res.setHeader("Access-Control-Max-Age", String(parseInt(CORS_MAX_AGE, 10) || 600));
  res.statusCode = 204;
  res.end();
}

function fail(res, code, msg) {
  res.statusCode = code;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify({ error: msg }));
}

function scrubRequestHeaders(headers) {
  const out = new Headers();
  for (const [k, v] of Object.entries(headers)) {
    const lk = k.toLowerCase();
    if (hopByHopHeaders.has(lk)) continue;
    if (lk === "host" || lk === "content-length" || lk === "accept-encoding") continue;
    // Let browser manage cookies if credentials; otherwise forward (browser usually strips anyway)
    // We keep Authorization if client sends it and browser allows it.
    out.set(k, v);
  }
  return out;
}

function scrubResponseHeaders(headers) {
  // Remove hop-by-hop & adjust CORS-y bits
  const out = {};
  for (const [k, v] of headers.entries()) {
    const lk = k.toLowerCase();
    if (hopByHopHeaders.has(lk)) continue;
    // We pass Set-Cookie through (works only with credentials & proper SameSite=None on target)
    out[k] = v;
  }
  return out;
}

export default async function handler(req, res) {
  // Handle preflight up front
  if (req.method === "OPTIONS") {
    reflectCors(req, res);
    return preflight(req, res);
  }
  
  reflectCors(req, res);
  
  // Basic origin policy
  const requestOrigin = (req.headers.origin || "").toLowerCase();
  if (denylist.size && denylist.has(requestOrigin)) {
    return fail(res, 403, "Origin denied.");
  }
  if (allowlist.size && !allowlist.has(requestOrigin)) {
    return fail(res, 403, "Origin not allowed.");
  }
  
  // Required headers policy
  for (const rh of requiredHeaders) {
    if (!(rh in (req.headers || {}))) {
      return fail(res, 400, `Missing required header: ${rh}`);
    }
  }
  
  // Optional API key
  if (API_KEY) {
    if ((req.headers["x-proxy-key"] || "") !== API_KEY) {
      return fail(res, 401, "Invalid or missing API key.");
    }
  }
  
  // Best-effort rate limiting
  const ip = getClientIP(req);
  if (!rateLimitAllow(ip)) {
    return fail(res, 429, "Rate limit exceeded. Try later.");
  }
  
  const target = getTargetFromRequest(req);
  if (!target) return fail(res, 400, "Provide a target URL via ?url= or path /api/proxy/<url>.");
  
  if (!isHttpHttps(target)) return fail(res, 400, "Only http(s) URLs are allowed.");
  if (isBlockedPrivateHost(target)) return fail(res, 403, "Target host is blocked.");
  
  // Build upstream request
  const method = req.method === "GET" || req.method === "HEAD" ? req.method : req.method || "GET";
  const upstreamHeaders = scrubRequestHeaders(req.headers);
  
  // Body handling
  let body = undefined;
  if (!["GET","HEAD"].includes(method)) {
    // Consume request stream
    body = await new Promise((resolve, reject) => {
      const chunks = [];
      req.on("data", c => chunks.push(c));
      req.on("end", () => resolve(Buffer.concat(chunks)));
      req.on("error", reject);
    });
  }
  
  try {
    const upstream = await fetch(target, {
      method,
      headers: upstreamHeaders,
      body,
      redirect: "manual",
    });
    
    // Pass back status, headers, body
    res.statusCode = upstream.status;
    // Copy headers (after CORS reflection)
    const respHeaders = scrubResponseHeaders(upstream.headers);
    for (const [k, v] of Object.entries(respHeaders)) {
      // Don’t override our CORS headers
      if (/^access-control-/i.test(k)) continue;
      res.setHeader(k, v);
    }
    
    // Ensure CORS reflection headers remain
    reflectCors(req, res);
    
    // Stream/pipe response
    const buf = Buffer.from(await upstream.arrayBuffer());
    res.end(buf);
  } catch (err) {
    return fail(res, 502, `Upstream fetch failed: ${String(err && err.message || err)}`);
  }
}
