const crypto = require("crypto");

const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = Number(process.env.OWNER_AUTH_RATE_LIMIT || 5);
const SESSION_SECONDS = Number(process.env.OWNER_SESSION_SECONDS || 60 * 60);
const buckets = new Map();

function setSecurityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Cache-Control", "no-store");
}

function clientIp(req) {
  return String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown")
    .split(",")[0]
    .trim();
}

function cleanString(value, max = 240) {
  return String(value || "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .replace(/[<>]/g, "")
    .trim()
    .slice(0, max);
}

function envList(name) {
  return String(process.env[name] || "")
    .split(",")
    .map(v => v.trim().toLowerCase())
    .filter(Boolean);
}

function allowedOrigins(req) {
  const configured = envList("ALLOWED_ORIGINS").map(v => v.startsWith("http") ? v : `https://${v}`);
  const hostHttps = req.headers.host ? `https://${req.headers.host}` : "";
  const hostHttp = req.headers.host ? `http://${req.headers.host}` : "";
  const vercel = process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : "";
  return new Set([...configured, hostHttps, hostHttp, vercel].filter(Boolean));
}

function sameOriginRequest(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  return allowedOrigins(req).has(origin);
}

function applyCors(req, res) {
  const origin = req.headers.origin;
  if (origin && allowedOrigins(req).has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "POST, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Requested-With");
}

function rateLimited(key) {
  const now = Date.now();
  const bucket = buckets.get(key) || { count: 0, resetAt: now + WINDOW_MS };
  if (bucket.resetAt <= now) {
    bucket.count = 0;
    bucket.resetAt = now + WINDOW_MS;
  }
  bucket.count += 1;
  buckets.set(key, bucket);
  return bucket.count > MAX_ATTEMPTS;
}

function base64url(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function signJwt(payload, secret) {
  const header = base64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = base64url(JSON.stringify(payload));
  const signature = crypto.createHmac("sha256", secret).update(`${header}.${body}`).digest("base64url");
  return `${header}.${body}.${signature}`;
}

function sha256(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function validPin(pin) {
  const pinHash = cleanString(process.env.OWNER_PIN_HASH, 128);
  const pinPlain = cleanString(process.env.OWNER_PIN, 128);
  if (pinHash) return safeEqual(sha256(pin), pinHash.toLowerCase());
  if (pinPlain) return safeEqual(pin, pinPlain);
  return false;
}

function audit(action, details) {
  const entry = {
    action,
    at: new Date().toISOString(),
    ...details,
  };
  console.info("[OWNER_AUDIT]", JSON.stringify(entry));
}

module.exports = async function handler(req, res) {
  setSecurityHeaders(res);
  applyCors(req, res);

  if (req.method === "OPTIONS") return res.status(204).end();
  if (!sameOriginRequest(req)) return res.status(403).json({ success: false, error: "CSRF_ORIGIN_BLOCKED" });

  if (req.method === "DELETE") {
    res.setHeader("Set-Cookie", "ral_owner_token=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");
    return res.status(204).end();
  }

  if (req.method !== "POST") return res.status(405).json({ success: false, error: "METHOD_NOT_ALLOWED" });

  const jwtSecret = cleanString(process.env.JWT_SECRET, 500);
  const ownerEmails = envList("OWNER_EMAILS");
  const adminEmails = envList("ADMIN_EMAILS");

  if (!jwtSecret || ownerEmails.length === 0) {
    return res.status(503).json({ success: false, error: "OWNER_AUTH_NOT_CONFIGURED" });
  }

  let body = req.body || {};
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { return res.status(400).json({ success: false, error: "INVALID_JSON" }); }
  }

  const email = cleanString(body.email, 180).toLowerCase();
  const pin = cleanString(body.pin, 80);
  const ip = clientIp(req);
  const rateKey = `owner:${ip}:${email || "unknown"}`;

  if (rateLimited(rateKey)) {
    audit("rate_limited", { email, ip });
    return res.status(429).json({ success: false, error: "RATE_LIMITED" });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(email)) {
    audit("invalid_email", { email, ip });
    return res.status(400).json({ success: false, error: "INVALID_EMAIL" });
  }

  const role = adminEmails.includes(email) ? "ADMIN" : ownerEmails.includes(email) ? "OWNER" : null;
  if (!role || !validPin(pin)) {
    audit("login_denied", { email, ip, role: role || "NONE" });
    return res.status(401).json({ success: false, error: "INVALID_CREDENTIALS" });
  }

  const now = Math.floor(Date.now() / 1000);
  const token = signJwt({
    sub: email,
    email,
    role,
    scope: role === "ADMIN" ? ["owner:read", "owner:write", "admin:write"] : ["owner:read", "owner:write"],
    iat: now,
    exp: now + SESSION_SECONDS,
  }, jwtSecret);

  res.setHeader(
    "Set-Cookie",
    `ral_owner_token=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_SECONDS}`
  );
  audit("login_success", { email, ip, role });
  return res.status(200).json({ success: true, token, role, expiresAt: (now + SESSION_SECONDS) * 1000 });
};
