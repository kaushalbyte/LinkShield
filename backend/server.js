const path = require("node:path");
require("dotenv").config({ path: path.join(__dirname, ".env"), quiet: true });

const express = require("express");
const protobuf = require("protobufjs");
const { rateLimit } = require("express-rate-limit");
const { createHash } = require("node:crypto");
const SearchUrlsResponse = protobuf
  .loadSync(path.join(__dirname, "safe-browsing.proto"))
  .lookupType("SearchUrlsResponse");

const app = express();
const PORT = process.env.PORT || 3000;
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",").map(origin => origin.trim()).filter(Boolean);
const threatCache = new Map();

app.disable("x-powered-by");
if (process.env.TRUST_PROXY) {
  app.set("trust proxy", process.env.TRUST_PROXY.split(",").map(value => value.trim()));
}

const cacheCleanup = setInterval(() => {
  for (const [key, entry] of threatCache) {
    if (entry.expiresAt <= Date.now()) threatCache.delete(key);
  }
}, 60000);
cacheCleanup.unref();

app.use((req, res, next) => {
  const origin = req.headers.origin;
  const sameOrigin = `${req.protocol}://${req.get("host")}`;
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.vary("Origin");

  if (origin && origin !== sameOrigin && !allowedOrigins.includes(origin)) {
    return sendError(res, 403, "This frontend origin is not allowed.", null, "ORIGIN_NOT_ALLOWED");
  }

  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }

  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

app.use("/api", (req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
}, rateLimit({
  windowMs: 60000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => sendError(res, 429, "Too many scans. Please wait a minute.", null, "RATE_LIMITED"),
}));

app.use(express.json({ limit: "8kb" }));

function sendError(res, status, message, url = null, code = "REQUEST_FAILED") {
  return res.status(status).json({
    success: false,
    url,
    isThreat: null,
    threats: [],
    error: message,
    code,
  });
}

app.get("/health", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.json({ status: "ok" });
});

for (const [route, file] of Object.entries({
  "/": "index.html",
  "/index.html": "index.html",
  "/privacy.html": "privacy.html",
  "/css/style.css": "css/style.css",
  "/js/app.js": "js/app.js",
  "/js/analyzer.js": "js/analyzer.js",
})) {
  app.get(route, (req, res) => res.sendFile(path.join(__dirname, "..", file)));
}

app.post("/api/check-url", async (req, res) => {
  const { url } = req.body || {};

  if (typeof url !== "string" || !url.trim()) {
    return sendError(res, 400, "Please enter a URL.", null, "INVALID_URL");
  }

  if (url.length > 4096) {
    return sendError(res, 400, "URL must be 4096 characters or fewer.", null, "INVALID_URL");
  }

  let parsedURL;

  try {
    parsedURL = new URL(url);

    if (!["http:", "https:"].includes(parsedURL.protocol)) {
      return sendError(res, 400, "Only HTTP and HTTPS URLs are supported.", null, "INVALID_URL");
    }
    if (parsedURL.username || parsedURL.password) {
      return sendError(res, 400, "Remove embedded usernames and passwords from the URL.", null, "INVALID_URL");
    }
  } catch {
    return sendError(res, 400, "Invalid URL format.", null, "INVALID_URL");
  }

  if (!process.env.SAFE_BROWSING_API_KEY?.trim()) {
    return sendError(res, 503, "Threat detection service is not configured.", parsedURL.href, "NOT_CONFIGURED");
  }

  const cacheKey = createHash("sha256").update(parsedURL.href).digest("hex");
  const cached = threatCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) return res.json(cached);
  threatCache.delete(cacheKey);

  try {
    const requestedAt = Date.now();
    const apiURL = new URL(
      "https://safebrowsing.googleapis.com/v5/urls:search",
    );

    apiURL.searchParams.set("key", process.env.SAFE_BROWSING_API_KEY);

    apiURL.searchParams.append("urls", parsedURL.href);

    const response = await fetch(apiURL, {
      headers: { Accept: "application/x-protobuf" },
      signal: AbortSignal.timeout(15000),
    });

    if (!response.ok) {
      console.error("Google API error status:", response.status);
      await response.body?.cancel();
      return sendError(res, 502, "Threat detection service failed.", parsedURL.href, "UPSTREAM_FAILED");
    }

    const contentType = (response.headers.get("content-type") || "")
      .split(";")[0].trim().toLowerCase();
    const bytes = new Uint8Array(await response.arrayBuffer());
    let data;
    let cacheSeconds;

    try {
      if (contentType === "application/x-protobuf" || contentType === "application/protobuf") {
        data = SearchUrlsResponse.toObject(SearchUrlsResponse.decode(bytes), {
          enums: String,
          longs: String,
          arrays: true,
        });
      } else if (contentType === "application/json") {
        data = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
      } else {
        throw new Error("Unsupported response format");
      }

      if (!data || typeof data !== "object" || Array.isArray(data) ||
          !data.cacheDuration || data.error ||
          (data.threats !== undefined && !Array.isArray(data.threats)) ||
          (data.threats || []).some(threat => !threat || typeof threat.url !== "string" ||
            !threat.url || !Array.isArray(threat.threatTypes) || !threat.threatTypes.length)) {
        throw new Error("Unexpected response structure");
      }
      cacheSeconds = typeof data.cacheDuration === "string"
        ? (/^\d+(\.\d{1,9})?s$/.test(data.cacheDuration) ? Number(data.cacheDuration.slice(0, -1)) : NaN)
        : Number(data.cacheDuration.seconds || 0) + Number(data.cacheDuration.nanos || 0) / 1e9;
      if (!Number.isFinite(cacheSeconds) || cacheSeconds < 0) {
        throw new Error("Invalid cache duration");
      }
    } catch {
      console.error("Google API returned an invalid threat response.");
      return sendError(res, 502, "Threat detection service returned an invalid response.", parsedURL.href, "UPSTREAM_INVALID_RESPONSE");
    }

    const threats = data.threats || [];

    const result = {
      success: true,
      url: parsedURL.href,
      isThreat: threats.length > 0,
      threats: threats,
      expiresAt: requestedAt + Math.floor(Math.min(cacheSeconds, 1800) * 1000),
    };
    if (result.expiresAt > Date.now()) {
      if (threatCache.size >= 1000) threatCache.delete(threatCache.keys().next().value);
      threatCache.set(cacheKey, result);
    }
    return res.json(result);
  } catch (error) {
    const timedOut = error.name === "TimeoutError";
    console.error(timedOut ? "Google API request timed out." : "Google API request failed.");
    return sendError(res, timedOut ? 504 : 502,
      timedOut ? "Threat detection service timed out." : "Unable to connect to threat detection service.",
      parsedURL.href, timedOut ? "UPSTREAM_TIMEOUT" : "UPSTREAM_UNAVAILABLE");
  }
});

app.use("/api", (req, res) => sendError(res, 404, "API endpoint not found.", null, "NOT_FOUND"));

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  const status = [400, 413, 415].includes(error.status) ? error.status : 500;
  return sendError(res, status, status === 500 ? "Unable to process request." :
    status === 413 ? "Request body is too large." : "Invalid JSON request body.", null,
    status === 500 ? "INTERNAL_ERROR" : "INVALID_REQUEST");
});

if (require.main === module) {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server listening on port ${PORT}`);
  });
}

module.exports = app;
