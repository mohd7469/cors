// /api/proxy.js
// Serverless wrapper for cors-anywhere on Vercel
// Usage:
//   /api/proxy?url=https%3A%2F%2Fhttpbin.org%2Fget
//   /api/proxy/https%3A%2F%2Fhttpbin.org%2Fget
// Health/ready:
//   GET /                       -> 200 JSON (status ok)   <-- added
//   GET /health                 -> 200 "ok"               <-- added
//   GET /api/proxy              -> 200 JSON (status ok)
//   GET /api/proxy/health       -> 200 "ok"
//
// Env vars (mapped to cors-anywhere options):
//   ORIGIN_ALLOWLIST (CSV) -> originWhitelist
//   ORIGIN_DENYLIST  (CSV) -> originBlacklist
//   REQUIRE_HEADER   (CSV) -> requireHeader
//   CORS_MAX_AGE     (int) -> corsMaxAge
//   RATE_LIMIT       (string) -> checkRateLimit (same format used by cors-anywhere demo)

const corsAnywhere = require("cors-anywhere"); // CJS module

let server; // singleton per Vercel instance

function parseCSV(s) {
  return (s || "")
  .split(",")
  .map((x) => x.trim())
  .filter(Boolean);
}

function initServer() {
  if (server) return server;
  
  const {
    ORIGIN_ALLOWLIST = "", // CSV of allowed origins, empty = allow all
    ORIGIN_DENYLIST = "",  // CSV of blocked origins
    REQUIRE_HEADER = "",   // CSV of headers that must be present (e.g. "origin,x-requested-with")
    CORS_MAX_AGE = "",     // seconds for preflight cache
    RATE_LIMIT = "0",      // e.g. "100/10" (100 req / 10 min) or "0" to disable
  } = process.env;
  
  server = corsAnywhere.createServer({
    originWhitelist: parseCSV(ORIGIN_ALLOWLIST), // [] = allow all
    originBlacklist: parseCSV(ORIGIN_DENYLIST),
    requireHeader: parseCSV(REQUIRE_HEADER),     // e.g. ["origin","x-requested-with"]
    corsMaxAge: CORS_MAX_AGE ? parseInt(CORS_MAX_AGE, 10) : undefined,
    removeHeaders: [
      "cookie",
      "cookie2",
      "x-request-start",
      "x-request-id",
      "via",
      "connect-time",
      "total-route-time",
    ],
    // Optional, matches CORS Anywhere public demo's rate limit mechanism:
    checkRateLimit:
      RATE_LIMIT && RATE_LIMIT !== "0"
        ? require("cors-anywhere/lib/rate-limit")(RATE_LIMIT)
        : undefined,
  });
  
  return server;
}

// Helper: build the path format CORS Anywhere expects ("/http://host/path")
function makeCorsAnywherePath(req) {
  const url = new URL(req.url, "http://local"); // dummy base for parsing
  let target = url.searchParams.get("url");
  
  // Support path style: /api/proxy/<encoded-target>
  if (!target) {
    const m = url.pathname.match(/\/api\/proxy\/(.+)/);
    if (m) {
      try {
        target = decodeURIComponent(m[1]);
      } catch {
        target = m[1];
      }
    }
  }
  
  if (!target) return ""; // missing
  
  // cors-anywhere expects an absolute URL right after '/'
  // e.g., "/https://httpbin.org/get"
  if (!/^https?:\/\//i.test(target)) return ""; // only http/https
  return "/" + target;
}

function sendHealthJSON(res) {
  res.statusCode = 200;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(
    JSON.stringify({
      status: "ok",
      name: "cors-anywhere-serverless",
      usage:
        "GET /api/proxy?url=<absolute-url> or /api/proxy/<encoded-absolute-url>",
      version: "1.0.0",
    })
  );
}

function sendHealthText(res) {
  res.statusCode = 200;
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.end("ok");
}

module.exports = (req, res) => {
  const url = new URL(req.url, "http://local"); // for path inspection
  const pathname = url.pathname;
  
  // NEW: Root health endpoints (require routing / -> function in vercel.json)
  if (req.method === "GET" && pathname === "/") {
    return sendHealthJSON(res);
  }
  if (req.method === "GET" && /^\/health\/?$/.test(pathname)) {
    return sendHealthText(res);
  }
  
  // Existing health endpoints under /api/proxy
  if (
    req.method === "GET" &&
    /^\/api\/proxy\/?$/.test(pathname) &&
    !url.searchParams.get("url")
  ) {
    return sendHealthJSON(res);
  }
  // 2) GET /api/proxy/health -> "ok"
  if (req.method === "GET" && /^\/api\/proxy\/health\/?$/.test(pathname)) {
    return sendHealthText(res);
  }
  
  // Convert the function request URL into cors-anywhere path
  const pathForCorsAnywhere = makeCorsAnywherePath(req);
  if (!pathForCorsAnywhere) {
    res.statusCode = 400;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    return res.end(
      JSON.stringify({
        error:
          "Provide target via ?url= or /api/proxy/<url>, only http(s) allowed.",
        example: "/api/proxy?url=https%3A%2F%2Fhttpbin.org%2Fget",
      })
    );
  }
  
  // Rewrite req.url so cors-anywhere sees "/https://example.com/..."
  req.url = pathForCorsAnywhere;
  
  // Let cors-anywhere handle everything (CORS headers, preflight, proxying)
  const srv = initServer();
  srv.emit("request", req, res);
};
