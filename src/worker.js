// Worker: serves the API. Static files (the page) are served by Cloudflare assets and are free.
import { verifyGoogleToken, roleFor, mintSession, verifySession, canRefresh, safeEqual } from "./auth.js";
import { LEVEL } from "./rules.js";

export { Database } from "./database.js";

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: JSON_HEADERS });
}

function allowedOrigins(env, url) {
  const list = new Set([url.origin]);
  for (const o of String(env.ALLOWED_ORIGINS || "").split(",")) if (o.trim()) list.add(o.trim().replace(/\/+$/, ""));
  return list;
}

// Browsers always send Origin on WebSocket upgrades and on cross-site POSTs.
function originOk(request, env, url, required) {
  const origin = request.headers.get("Origin");
  if (!origin) return !required;
  return allowedOrigins(env, url).has(origin);
}

function bearer(request) {
  const h = request.headers.get("Authorization") || "";
  return h.startsWith("Bearer ") ? h.slice(7).trim() : "";
}

function database(env) {
  return env.DB.get(env.DB.idFromName("main"));
}

async function sessionFromRequest(env, request) {
  const s = await verifySession(env, bearer(request));
  if (!s) return null;
  return { ...s, role: roleFor(env, s.email) };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (path === "/api/config") {
        return json({ clientId: env.GOOGLE_CLIENT_ID || "", configured: !!(env.GOOGLE_CLIENT_ID && env.SESSION_SECRET) });
      }

      if (path === "/api/login" && request.method === "POST") {
        if (!originOk(request, env, url, false)) return json({ error: "bad_origin" }, 403);
        let body;
        try { body = await request.json(); } catch (e) { return json({ error: "bad_request" }, 400); }
        let who;
        try {
          who = await verifyGoogleToken(body && body.credential, env);
        } catch (e) {
          return json({ error: "invalid_token", message: e.message }, 401);
        }
        const role = roleFor(env, who.email);
        if (role === "none") return json({ error: "no_access", email: who.email }, 403);
        const s = await mintSession(env, who.email);
        return json({ token: s.token, exp: s.exp, email: who.email, role });
      }

      if (path === "/api/session" && request.method === "GET") {
        const s = await sessionFromRequest(env, request);
        if (!s) return json({ error: "unauthorized" }, 401);
        if (s.role === "none") return json({ error: "no_access", email: s.email }, 403);
        return json({ email: s.email, role: s.role, exp: s.exp });
      }

      if (path === "/api/refresh" && request.method === "POST") {
        if (!originOk(request, env, url, false)) return json({ error: "bad_origin" }, 403);
        const s = await sessionFromRequest(env, request);
        if (!s || s.role === "none" || !canRefresh(s)) return json({ error: "unauthorized" }, 401);
        const n = await mintSession(env, s.email, s.iat);
        return json({ token: n.token, exp: n.exp, email: s.email, role: s.role });
      }

      if (path === "/api/ws") {
        if (request.headers.get("Upgrade") !== "websocket") return new Response("Expected a WebSocket.", { status: 426 });
        if (!originOk(request, env, url, true)) return new Response("Bad origin.", { status: 403 });
        const protocols = (request.headers.get("Sec-WebSocket-Protocol") || "").split(",").map((p) => p.trim());
        if (!protocols.includes("kim-v1")) return new Response("Bad protocol.", { status: 400 });
        const token = protocols.find((p) => p && p !== "kim-v1");
        const s = await verifySession(env, token);
        if (!s) return new Response("Not signed in.", { status: 401 });
        if (roleFor(env, s.email) === "none") return new Response("No access.", { status: 403 });
        const headers = new Headers(request.headers);
        headers.set("x-user-email", s.email);
        headers.set("x-session-exp", String(s.exp));
        return database(env).fetch(new Request(request.url, { method: "GET", headers }));
      }

      if (path === "/api/export" && request.method === "GET") {
        const s = await sessionFromRequest(env, request);
        if (!s) return json({ error: "unauthorized" }, 401);
        if (LEVEL[s.role] < LEVEL.editor) return json({ error: "forbidden" }, 403);
        const data = await database(env).exportAll();
        const day = new Date().toISOString().slice(0, 10);
        return new Response(JSON.stringify(data, null, 1), {
          headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "content-disposition": 'attachment; filename="speed-dating-backup-' + day + '.json"' },
        });
      }

      if (path === "/api/import" && request.method === "POST") {
        // Only works while the ADMIN_KEY secret exists. Delete the secret when the import is done.
        if (!env.ADMIN_KEY || String(env.ADMIN_KEY).length < 24) return json({ error: "disabled" }, 404);
        if (!(await safeEqual(bearer(request), env.ADMIN_KEY))) return json({ error: "unauthorized" }, 401);
        const text = await request.text();
        if (text.length > 2_000_000) return json({ error: "too_large" }, 413);
        try {
          return json({ ok: true, ...(await database(env).importDocs(text)) });
        } catch (e) {
          return json({ error: "import_failed", message: e && e.message }, 400);
        }
      }

      if (path.startsWith("/api/")) return json({ error: "not_found" }, 404);
      // Everything else is a static file; the assets binding normally answers before we get here.
      return env.ASSETS ? env.ASSETS.fetch(request) : new Response("Not found", { status: 404 });
    } catch (e) {
      console.error("request failed", e && e.message);
      return json({ error: "server_error" }, 500);
    }
  },
};

