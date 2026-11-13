// Worker: serves the API. Static files (the page) are served by Cloudflare assets and are free.
import { verifyGoogleToken, mintSession, verifySession, canRefresh, safeEqual } from "./auth.js";
import { LEVEL, CATEGORY_KEYS } from "./rules.js";

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
  const who = await database(env).whoami(s.email, s.iat, s.jti);
  if (who.revoked) return null; // signed out (by them or an owner) since this session began
  return { ...s, role: who.role, owner: who.owner };
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
        const me = await database(env).loginInfo(who.email);
        if (me.locked) return json({ error: "locked" }, 403);
        if (me.role === "none") return json({ error: "no_access", email: who.email }, 403);
        const s = await mintSession(env, who.email);
        return json({ token: s.token, exp: s.exp, email: who.email, role: me.role, owner: me.owner });
      }

      if (path === "/api/session" && request.method === "GET") {
        const s = await sessionFromRequest(env, request);
        if (!s) return json({ error: "unauthorized" }, 401);
        if (s.role === "none") return json({ error: "no_access", email: s.email }, 403);
        // ?probe=1 is used by a page whose connection was refused, to find out if the room is simply full.
        const full = url.searchParams.get("probe") ? await database(env).isFull(s.role) : undefined;
        return json({ email: s.email, role: s.role, owner: s.owner, exp: s.exp, full });
      }

      if (path === "/api/refresh" && request.method === "POST") {
        if (!originOk(request, env, url, false)) return json({ error: "bad_origin" }, 403);
        const s = await sessionFromRequest(env, request);
        if (!s || s.role === "none" || !canRefresh(s)) return json({ error: "unauthorized" }, 401);
        const n = await mintSession(env, s.email, s.iat, s.jti);
        return json({ token: n.token, exp: n.exp, email: s.email, role: s.role, owner: s.owner });
      }

      if (path === "/api/ws") {
        if (request.headers.get("Upgrade") !== "websocket") return new Response("Expected a WebSocket.", { status: 426 });
        if (!originOk(request, env, url, true)) return new Response("Bad origin.", { status: 403 });
        const protocols = (request.headers.get("Sec-WebSocket-Protocol") || "").split(",").map((p) => p.trim());
        if (!protocols.includes("kim-v1")) return new Response("Bad protocol.", { status: 400 });
        const token = protocols.find((p) => p && p !== "kim-v1");
        const s = await verifySession(env, token);
        if (!s) return new Response("Not signed in.", { status: 401 });
        const headers = new Headers(request.headers);
        headers.set("x-user-email", s.email);
        headers.set("x-session-exp", String(s.exp));
        headers.set("x-session-iat", String(s.iat));
        if (s.jti) headers.set("x-session-jti", s.jti);
        return database(env).fetch(new Request(request.url, { method: "GET", headers }));
      }

      if (path === "/api/roles") {
        // The admin page: owners and editors manage who can use the app (see DEPLOY.md).
        if (request.method !== "GET" && request.method !== "POST") return json({ error: "not_found" }, 404);
        if (request.method === "POST" && !originOk(request, env, url, false)) return json({ error: "bad_origin" }, 403);
        const s = await sessionFromRequest(env, request);
        if (!s) return json({ error: "unauthorized" }, 401);
        let r;
        if (request.method === "GET") r = await database(env).listRoles(s.email);
        else {
          let body;
          try { body = await request.json(); } catch (e) { return json({ error: "bad_request" }, 400); }
          r = await database(env).changeRole(s.email, body && body.email, body && body.role);
        }
        if (r.ok) return json(r);
        return json({ error: r.code, message: r.message }, r.code === "forbidden" ? 403 : r.code === "locked" ? 409 : 400);
      }

      if (path === "/api/signout" && request.method === "POST") {
        // Ends this one session on the server (a copied token stops working), not only in the browser.
        if (!originOk(request, env, url, false)) return json({ error: "bad_origin" }, 403);
        const t = await verifySession(env, bearer(request));
        if (!t) return json({ error: "unauthorized" }, 401);
        return json(await database(env).signOutSelf(t.email, t.jti));
      }

      if ((path === "/api/lock" || path === "/api/revoke" || path === "/api/person") && request.method === "POST") {
        // Owner tools: lock the door, sign someone out everywhere, find and erase a person's records.
        if (!originOk(request, env, url, false)) return json({ error: "bad_origin" }, 403);
        const s = await sessionFromRequest(env, request);
        if (!s) return json({ error: "unauthorized" }, 401);
        let body;
        try { body = await request.json(); } catch (e) { return json({ error: "bad_request" }, 400); }
        body = body && typeof body === "object" ? body : {};
        let r;
        if (path === "/api/lock") r = await database(env).setLock(s.email, !!body.locked);
        else if (path === "/api/revoke") r = await database(env).signOutEmail(s.email, body.email);
        else r = body.action === "erase" ? await database(env).erasePerson(s.email, body.query, body.select) : await database(env).findPerson(s.email, body.query);
        if (r.ok) return json(r);
        return json({ error: r.code, message: r.message }, r.code === "forbidden" ? 403 : 400);
      }

      if (path === "/api/profile" || path === "/api/signup") {
        // A signed-in person's own TikTok username and dater sign-up (one sign-up per email).
        if (request.method !== "GET" && request.method !== "POST") return json({ error: "not_found" }, 404);
        if (request.method === "POST" && !originOk(request, env, url, false)) return json({ error: "bad_origin" }, 403);
        const s = await sessionFromRequest(env, request);
        if (!s) return json({ error: "unauthorized" }, 401);
        if (s.role === "none") return json({ error: "no_access" }, 403);
        let r;
        if (request.method === "GET") r = await database(env).myProfile(s.email);
        else {
          let body;
          try { body = await request.json(); } catch (e) { return json({ error: "bad_request" }, 400); }
          r = path === "/api/profile" ? await database(env).setHandle(s.email, body && body.handle) : await database(env).submitSignup(s.email, body);
        }
        if (r.ok) return json(r);
        return json({ error: r.code, message: r.message }, r.code === "taken" || r.code === "locked" ? 409 : r.code === "limited" ? 429 : 400);
      }

      if (path === "/api/signups" && (request.method === "GET" || request.method === "POST")) {
        // Hosts (editors and owners): the pending dater list, approve, decline, clear, link.
        if (request.method === "POST" && !originOk(request, env, url, false)) return json({ error: "bad_origin" }, 403);
        const s = await sessionFromRequest(env, request);
        if (!s) return json({ error: "unauthorized" }, 401);
        if (LEVEL[s.role] < LEVEL.editor) return json({ error: "forbidden", message: "Only hosts can do that." }, 403);
        let r;
        if (request.method === "GET") r = await database(env).listSignups(s.email);
        else {
          let b;
          try { b = await request.json(); } catch (e) { return json({ error: "bad_request" }, 400); }
          b = b && typeof b === "object" ? b : {};
          const d = database(env);
          r = b.action === "approve" ? await d.approveSignup(s.email, b.id, b.daterId) : b.action === "preview" ? await d.previewMerge(s.email, b.id, b.daterId) : b.action === "unmerge" ? await d.unmergeSignup(s.email, b.id) : b.action === "decline" ? await d.declineSignup(s.email, b.id)
            : b.action === "clear" ? await d.clearSignups(s.email) : b.action === "link" ? await d.linkSignup(s.email, b.id, b.daterId) : { ok: false, code: "invalid", message: "Unknown action." };
        }
        if (r.ok) return json(r);
        return json({ error: r.code, message: r.message }, r.code === "forbidden" ? 403 : r.code === "not_found" ? 404 : 400);
      }

      if ((path === "/api/people" && request.method === "GET") || (path === "/api/people/release" && request.method === "POST")) {
        // Owners only: search everyone who has signed in (email or TikTok username); free up a claimed username.
        if (request.method === "POST" && !originOk(request, env, url, false)) return json({ error: "bad_origin" }, 403);
        const s = await sessionFromRequest(env, request);
        if (!s) return json({ error: "unauthorized" }, 401);
        if (!s.owner) return json({ error: "forbidden", message: "Only owners can do that." }, 403);
        let r;
        if (request.method === "GET") r = await database(env).findPeople(s.email, url.searchParams.get("q"));
        else { let b; try { b = await request.json(); } catch (e) { return json({ error: "bad_request" }, 400); } r = await database(env).releaseHandle(s.email, b && b.email); }
        if (r.ok) return json(r);
        return json({ error: r.code, message: r.message }, r.code === "forbidden" ? 403 : 400);
      }

      if (path === "/api/categorize" && (request.method === "GET" || request.method === "POST")) {
        // Owners only. Sorts questions that have no category using the list shipped with the site (/categories.json).
        if (request.method === "POST" && !originOk(request, env, url, false)) return json({ error: "bad_origin" }, 403);
        const s = await sessionFromRequest(env, request);
        if (!s) return json({ error: "unauthorized" }, 401);
        if (!s.owner) return json({ error: "forbidden", message: "Only owners can do that." }, 403);
        if (request.method === "GET") return json({ ok: true, ...(await database(env).categoryStatus()) });
        let file;
        try {
          const res = await env.ASSETS.fetch(new Request(url.origin + "/categories.json"));
          file = await res.json();
        } catch (e) { return json({ error: "no_file", message: "The category list was not found on the site." }, 500); }
        if (!file || typeof file.map !== "object" || file.map === null) return json({ error: "no_file", message: "The category list is not valid." }, 500);
        const r = await database(env).applyCategories(s.email, file.map, CATEGORY_KEYS);
        if (r.ok) return json(r);
        return json({ error: r.code, message: r.message }, r.code === "forbidden" ? 403 : 400);
      }

      if (path === "/api/pack" && (request.method === "GET" || request.method === "POST")) {
        // Owners only. Adds a question pack shipped with the site (/packs/NAME.json). Never changes existing questions.
        if (request.method === "POST" && !originOk(request, env, url, false)) return json({ error: "bad_origin" }, 403);
        const s = await sessionFromRequest(env, request);
        if (!s) return json({ error: "unauthorized" }, 401);
        if (!s.owner) return json({ error: "forbidden", message: "Only owners can do that." }, 403);
        let name = url.searchParams.get("name") || "";
        if (request.method === "POST") { try { name = String((await request.json()).name || ""); } catch (e) { return json({ error: "bad_request" }, 400); } }
        if (!/^[a-z0-9-]{1,40}$/.test(name)) return json({ error: "bad_request", message: "Unknown pack." }, 400);
        let pack;
        try { pack = await (await env.ASSETS.fetch(new Request(url.origin + "/packs/" + name + ".json"))).json(); } catch (e) { return json({ error: "no_file", message: "That pack was not found on the site." }, 404); }
        if (!pack || !Array.isArray(pack.questions) || pack.questions.length > 500) return json({ error: "no_file", message: "That pack is not valid." }, 500);
        if (request.method === "GET") return json({ ok: true, name, ...(await database(env).packStatus(pack.questions.map((q) => String(q && q.id)))) });
        const r = await database(env).addPack(s.email, pack.questions, CATEGORY_KEYS);
        if (r.ok) return json(r);
        return json({ error: r.code, message: r.message }, r.code === "forbidden" ? 403 : 400);
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

