# Receiver HMAC Node.js — démo polyglotte (Python gateway → Node webhook).
# Usage lab : node index.js   PORT=8015 WEBHOOK_SECRET=lab-webhook-secret-change-me

const http = require("http");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 8015);
const SECRET = process.env.WEBHOOK_SECRET || "lab-webhook-secret-change-me";
const MAX_AGE = 300;

function parseSignature(header) {
  const parts = Object.fromEntries(
    (header || "")
      .split(",")
      .map((p) => p.trim().split("="))
      .filter((kv) => kv.length === 2)
  );
  return { t: parts.t, v1: parts.v1 };
}

function canonical(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonical).join(",") + "]";
  }
  const keys = Object.keys(value).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(value[k])).join(",") + "}";
}

function verify(payload, timestamp, signature) {
  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || !signature) return false;
  if (Math.abs(Math.floor(Date.now() / 1000) - ts) > MAX_AGE) return false;
  const body = canonical(payload);
  const expected = crypto.createHmac("sha256", SECRET).update(`${ts}.${body}`).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, "utf8"), Buffer.from(signature, "utf8"));
  } catch {
    return false;
  }
}

const server = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ status: "healthy", service: "webhook-receiver" }));
    return;
  }
  if (req.method !== "POST" || req.url !== "/webhooks/securepay") {
    res.writeHead(404);
    res.end();
    return;
  }
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    let payload;
    try {
      payload = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
    } catch {
      res.writeHead(400);
      res.end("invalid json");
      return;
    }
    const { t, v1 } = parseSignature(req.headers["x-securepay-signature"]);
    if (!verify(payload, t, v1)) {
      res.writeHead(401);
      res.end("invalid signature");
      return;
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ received: true, type: payload.type || null }));
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`webhook-receiver listening on ${PORT}`);
});
