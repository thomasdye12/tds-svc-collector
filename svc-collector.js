#!/usr/bin/env node
/**
 * TDS Service Collector — WS + optional HTTPS/WSS + optional Admin API
 *
 * Public server:
 *   - WebSocket endpoint at /agent for agents (ws:// or wss://)
 *   - Optional legacy HTTP /ingest (disabled by default)
 *
 * Admin server (optional, defaults OFF):
 *   - Binds to 127.0.0.1 by default
 *   - /admin/hosts, /admin/hosts/:id, /admin/hosts/:id/refresh
 *
 * Auth:
 *   - Authorization: Bearer <AUTH_TOKEN> (required if AUTH_TOKEN is set)
 */

const fs = require("fs");
const http = require("http");
const https = require("https");
const express = require("express");
const { WebSocketServer } = require("ws");
const crypto = require("crypto");

// ------------------------- Config (env) -------------------------
const AUTH = process.env.AUTH_TOKEN || ""; // if set, required for both WS + HTTP

// Public agent endpoint (WS server)
const PORT = Number(process.env.PORT || 5669);
const BIND = process.env.BIND || "0.0.0.0";
const AGENT_PATH = process.env.AGENT_PATH || "/agent";

// WSS (TLS) options for public server
const TLS_ENABLED = (process.env.TLS_ENABLED || "").toLowerCase() === "true";
const TLS_KEY_FILE = process.env.TLS_KEY_FILE || "";
const TLS_CERT_FILE = process.env.TLS_CERT_FILE || "";
const TLS_CA_FILE = process.env.TLS_CA_FILE || ""; // optional (chain)

// Optional legacy HTTP ingest on public server
const HTTP_INGEST_ENABLE = (process.env.HTTP_INGEST_ENABLE || "").toLowerCase() === "true";
const BODY_LIMIT = process.env.BODY_LIMIT || "10mb";

// Admin API (separate server, disabled by default)
const ADMIN_ENABLE = (process.env.ADMIN_ENABLE || "").toLowerCase() === "true";
const ADMIN_BIND = process.env.ADMIN_BIND || "127.0.0.1";
const ADMIN_PORT = Number(process.env.ADMIN_PORT || 5670);

// WS heartbeat settings
const WS_PING_INTERVAL_MS = Number(process.env.WS_PING_INTERVAL_MS || 25000);
const WS_STALE_MS = Number(process.env.WS_STALE_MS || 60000);

// ------------------------- Stores -------------------------
// clients: systemId -> { ws, host, lastSeen, caps, connectedAt }
const clients = new Map();
// hosts:    systemId -> last reported snapshot { host, systemId, takenAt, services[], ... , receivedAt }
const hosts = new Map();

// ------------------------- Helpers -------------------------
function nowIso() {
  return new Date().toISOString();
}

function checkAuthBearer(authorizationHeader) {
  if (!AUTH) return true; // no auth required
  const token = (authorizationHeader || "").replace(/^Bearer\s+/i, "");
  return token === AUTH;
}

function authMiddleware(req, res, next) {
  if (!AUTH) return next();
  if (!checkAuthBearer(req.headers.authorization)) {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
}

function makeRequestId() {
  return crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString("hex");
}

// ------------------------- Public server (WS + optional /ingest) -------------------------
const publicApp = express();
// Only mount /ingest if enabled (legacy HTTP push)
if (HTTP_INGEST_ENABLE) {
  publicApp.use(express.json({ limit: BODY_LIMIT, inflate: true }));
  publicApp.post("/ingest", authMiddleware, (req, res) => {
    const body = req.body || {};
    if (!body.host || !Array.isArray(body.services)) {
      return res.status(400).json({ error: "bad payload" });
    }
    const systemId = body.systemId || body.host;
    hosts.set(systemId, { ...body, receivedAt: nowIso() });
    res.json({ ok: true });
  });
}

// For public exposure “without anything else”, we do **not** add other routes here.

// Choose HTTP or HTTPS for the public server
let publicServer;
if (TLS_ENABLED) {
  const tlsOpts = {
    key: fs.readFileSync(TLS_KEY_FILE),
    cert: fs.readFileSync(TLS_CERT_FILE),
  };
  if (TLS_CA_FILE && fs.existsSync(TLS_CA_FILE)) {
    tlsOpts.ca = fs.readFileSync(TLS_CA_FILE);
  }
  publicServer = https.createServer(tlsOpts, publicApp);
  console.log(`[collector] TLS enabled: serving WSS on ${BIND}:${PORT}${AGENT_PATH}`);
} else {
  publicServer = http.createServer(publicApp);
  console.log(`[collector] Serving WS on ${BIND}:${PORT}${AGENT_PATH}`);
}

// WebSocket server for agents
const wss = new WebSocketServer({ server: publicServer, path: AGENT_PATH, perMessageDeflate: true });

wss.on("connection", (ws, req) => {
  // Enforce bearer if configured
  if (!checkAuthBearer(req.headers.authorization)) {
    ws.close(1008, "unauthorized"); // policy violation
    return;
  }

  // Optional identity hints via query
  const url = new URL(req.url, `http://${req.headers.host}`);
  const systemIdHint = url.searchParams.get("systemId") || "";
  const hostHint = url.searchParams.get("host") || "";

  let systemId = systemIdHint || makeRequestId();
  let host = hostHint || "";

  const entry = {
    ws,
    host,
    caps: {},
    connectedAt: Date.now(),
    lastSeen: Date.now(),
  };

  // temp key; once we learn the real systemId from hello/snapshot we’ll re-key
  clients.set(systemId, entry);

  ws.on("message", (data) => {
    try {
      const msg = JSON.parse(data.toString());
      entry.lastSeen = Date.now();

      switch (msg.type) {
        case "hello": {
          // { type, systemId, host, caps, agent }
          if (msg.systemId && msg.systemId !== systemId) {
            // re-key if changed
            clients.delete(systemId);
            systemId = String(msg.systemId);
            clients.set(systemId, entry);
          }
          if (msg.host) host = String(msg.host);
          entry.host = host;
          entry.caps = msg.caps || {};
          // Acknowledge
          ws.send(JSON.stringify({ type: "helloAck", ts: Date.now() }));
          break;
        }

        case "snapshot": {
          // { systemId, host, takenAt, services, agent }
          const sysId = String(msg.systemId || systemId || msg.host || "");
          const record = {
            ...msg,
            systemId: sysId,
            host: msg.host || host,
            receivedAt: nowIso(),
          };
          hosts.set(sysId, record);

          // If our connection map was still using a temp systemId, re-key it
          if (sysId !== systemId) {
            const cached = clients.get(systemId);
            if (cached) {
              clients.delete(systemId);
              systemId = sysId;
              clients.set(systemId, cached);
            }
          }
          break;
        }

        case "pong": {
          // JSON-level pong (we also use WS native ping/pong below)
          break;
        }

        case "ok": {
          // generic ack from agents
          break;
        }

        default:
          // unknown message types are ignored
          break;
      }
    } catch (_) {
      // ignore invalid JSON
    }
  });

  ws.on("pong", () => {
    entry.lastSeen = Date.now();
  });

  ws.on("close", () => {
    clients.delete(systemId);
  });

  // Send a server hello to kick things off
  try {
    ws.send(JSON.stringify({ type: "hello", ts: Date.now() }));
  } catch (_) {}
});

// Heartbeat + stale cleanup
setInterval(() => {
  const now = Date.now();
  for (const [id, c] of clients) {
    // if stale, terminate
    if (now - c.lastSeen > WS_STALE_MS) {
      try { c.ws.terminate(); } catch (_) {}
      clients.delete(id);
      continue;
    }
    // normal ping to keep NATs alive
    try { c.ws.ping(); } catch (_) {}
  }
}, WS_PING_INTERVAL_MS);

// Start public server
publicServer.listen(PORT, BIND, () => {
  console.log(`[collector] public WS server listening on ${TLS_ENABLED ? "wss" : "ws"}://${BIND}:${PORT}${AGENT_PATH}`);
  if (HTTP_INGEST_ENABLE) {
    console.log(`[collector] legacy HTTP /ingest enabled with BODY_LIMIT=${BODY_LIMIT}`);
  }
});

// ------------------------- Admin server (optional) -------------------------
if (ADMIN_ENABLE) {
  const adminApp = express();
  adminApp.use(express.json({ limit: BODY_LIMIT, inflate: true }));
  adminApp.use((req, res, next) => authMiddleware(req, res, next));

  // List known hosts (from snapshots)
  adminApp.get("/admin/hosts", (_req, res) => {
    const list = Array.from(hosts.values())
      .map((h) => ({
        systemId: h.systemId,
        host: h.host,
        services: Array.isArray(h.services) ? h.services.length : 0,
        takenAt: h.takenAt,
        receivedAt: h.receivedAt,
      }))
      .sort((a, b) => (a.host || a.systemId || "").localeCompare(b.host || b.systemId || ""));
    res.json(list);
  });

  // Get latest snapshot for a systemId
  adminApp.get("/admin/hosts/:id", (req, res) => {
    const sysId = req.params.id;
    const rec = hosts.get(sysId);
    if (!rec) return res.status(404).json({ error: "not found" });
    res.json(rec);
  });

  // Ask an agent to refresh
  adminApp.post("/admin/hosts/:id/refresh", (req, res) => {
    const sysId = req.params.id;
    const client = clients.get(sysId);
    if (!client || client.ws.readyState !== 1) {
      return res.status(404).json({ error: "offline" });
    }
    const id = makeRequestId();
    try {
      client.ws.send(JSON.stringify({ type: "refresh", id }));
      return res.json({ ok: true, id });
    } catch (e) {
      return res.status(500).json({ error: "send-failed", detail: e.message });
    }
  });

  // Optional: ask an agent to send a snapshot (same as refresh, but agent may not rebuild)
  adminApp.post("/admin/hosts/:id/getSnapshot", (req, res) => {
    const sysId = req.params.id;
    const client = clients.get(sysId);
    if (!client || client.ws.readyState !== 1) {
      return res.status(404).json({ error: "offline" });
    }
    const id = makeRequestId();
    try {
      client.ws.send(JSON.stringify({ type: "getSnapshot", id }));
      return res.json({ ok: true, id });
    } catch (e) {
      return res.status(500).json({ error: "send-failed", detail: e.message });
    }
  });

  const adminServer = http.createServer(adminApp);
  adminServer.listen(ADMIN_PORT, ADMIN_BIND, () => {
    console.log(`[collector] admin API on http://${ADMIN_BIND}:${ADMIN_PORT}/admin (protected)`);
  });
} else {
  console.log("[collector] admin API is disabled");
}

// ------------------------- Notes -------------------------
/*
ENV quick start:

# Public WS only (no admin, no legacy ingest), plain WS
PORT=5669 BIND=0.0.0.0 AUTH_TOKEN="REDACTED" node svc-collector.js

# Public WSS (built-in TLS)
TLS_ENABLED=true TLS_KEY_FILE=/path/key.pem TLS_CERT_FILE=/path/cert.pem \
PORT=5669 BIND=0.0.0.0 AUTH_TOKEN="REDACTED" node svc-collector.js

# With admin API on localhost (and auth)
ADMIN_ENABLE=true ADMIN_BIND=127.0.0.1 ADMIN_PORT=5670 AUTH_TOKEN="REDACTED" node svc-collector.js

# Enable legacy HTTP ingest (optional, not recommended when using WS):
HTTP_INGEST_ENABLE=true AUTH_TOKEN="REDACTED" node svc-collector.js

Reverse proxy note (Nginx):
  proxy_set_header Authorization $http_authorization;  # preserve Bearer header for WS
  proxy_set_header Connection "upgrade";
  proxy_set_header Upgrade $http_upgrade;

Data:
  - Connected agents are tracked in "clients" map keyed by systemId.
  - Latest snapshots (from WS or /ingest) are stored in "hosts" map keyed by systemId.
*/
