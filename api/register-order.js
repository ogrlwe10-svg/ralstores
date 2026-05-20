const WINDOW_MS = 60 * 1000;
const MAX_REQUESTS = Number(process.env.ORDER_RATE_LIMIT || 20);
const MAX_BODY_BYTES = 8 * 1024;
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

function allowedOrigins(req) {
  const configured = String(process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map(v => v.trim())
    .filter(Boolean);
  const hostHttps = req.headers.host ? `https://${req.headers.host}` : "";
  const hostHttp = req.headers.host ? `http://${req.headers.host}` : "";
  const vercel = process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : "";
  return new Set([...configured, hostHttps, hostHttp, vercel].filter(Boolean));
}

function applyCors(req, res) {
  const origin = req.headers.origin;
  const allowed = allowedOrigins(req);
  if (origin && allowed.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Requested-With");
}

function sameOriginRequest(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  return allowedOrigins(req).has(origin);
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
  return bucket.count > MAX_REQUESTS;
}

function cleanString(value, max = 300) {
  return String(value || "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .replace(/[<>]/g, "")
    .trim()
    .slice(0, max);
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(value);
}

function normalizePayload(body) {
  const orderId = cleanString(body.orderId, 40);
  const product = cleanString(body.product, 700);
  const email = cleanString(body.email, 180).toLowerCase();
  const discordId = cleanString(body.discordId, 24);
  const total = Number(body.total);

  if (!/^RAL-[A-F0-9]{8}$/i.test(orderId)) throw new Error("INVALID_ORDER_ID");
  if (!product || product.length > 700) throw new Error("INVALID_PRODUCT");
  if (!Number.isFinite(total) || total <= 0 || total > 10000) throw new Error("INVALID_TOTAL");
  if (!validEmail(email)) throw new Error("INVALID_EMAIL");
  if (!/^\d{17,20}$/.test(discordId)) throw new Error("INVALID_DISCORD_ID");

  return { orderId: orderId.toUpperCase(), product, total, email, discordId };
}

module.exports = async function handler(req, res) {
  setSecurityHeaders(res);
  applyCors(req, res);

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ success: false, error: "METHOD_NOT_ALLOWED" });
  if (!sameOriginRequest(req)) return res.status(403).json({ success: false, error: "CSRF_ORIGIN_BLOCKED" });

  const ip = clientIp(req);
  if (rateLimited(`order:${ip}`)) return res.status(429).json({ success: false, error: "RATE_LIMITED" });

  const targetBase = String(process.env.KATABUMP_API_URL || "").trim().replace(/\/$/, "");
  const targetSecret = String(process.env.KATABUMP_API_SECRET || "").trim();

  if (!targetBase) return res.status(500).json({ success: false, error: "KATABUMP_API_URL_MISSING" });
  if (!targetSecret) return res.status(500).json({ success: false, error: "KATABUMP_API_SECRET_MISSING" });

  let parsedBody = req.body || {};
  if (typeof parsedBody === "string") {
    if (Buffer.byteLength(parsedBody, "utf8") > MAX_BODY_BYTES) {
      return res.status(413).json({ success: false, error: "PAYLOAD_TOO_LARGE" });
    }
    try { parsedBody = JSON.parse(parsedBody); } catch { return res.status(400).json({ success: false, error: "INVALID_JSON" }); }
  } else if (Buffer.byteLength(JSON.stringify(parsedBody), "utf8") > MAX_BODY_BYTES) {
    return res.status(413).json({ success: false, error: "PAYLOAD_TOO_LARGE" });
  }

  let payload;
  try {
    payload = normalizePayload(parsedBody);
  } catch (error) {
    return res.status(400).json({ success: false, error: error.message || "INVALID_PAYLOAD" });
  }

  try {
    const upstream = await fetch(`${targetBase}/api/register-order`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Secret": targetSecret,
      },
      body: JSON.stringify(payload),
    });

    const contentType = upstream.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      const data = await upstream.json();
      return res.status(upstream.status).json(data);
    }

    const text = await upstream.text();
    return res.status(upstream.status).json({ success: false, error: cleanString(text || "UPSTREAM_NON_JSON", 400) });
  } catch (error) {
    return res.status(502).json({ success: false, error: "UPSTREAM_UNAVAILABLE" });
  }
};
