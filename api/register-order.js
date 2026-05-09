module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const targetBase = String(process.env.KATABUMP_API_URL || "").trim().replace(/\/$/, "");
  const targetSecret = String(process.env.KATABUMP_API_SECRET || "").trim();

  if (!targetBase) return res.status(500).json({ error: "KATABUMP_API_URL is missing" });
  if (!targetSecret) return res.status(500).json({ error: "KATABUMP_API_SECRET is missing" });

  const payload = typeof req.body === "string" ? req.body : JSON.stringify(req.body || {});

  try {
    const upstream = await fetch(`${targetBase}/api/register-order`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Secret": targetSecret,
      },
      body: payload,
    });

    const contentType = upstream.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      const data = await upstream.json();
      return res.status(upstream.status).json(data);
    }

    const text = await upstream.text();
    return res.status(upstream.status).json({ success: false, error: text || "Upstream non-JSON response" });
  } catch (error) {
    return res.status(502).json({ success: false, error: "Upstream unavailable", detail: String(error?.message || error) });
  }
};
