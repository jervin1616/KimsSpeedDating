// One Durable Object holds all data (SQLite) and keeps every connected page in sync
// over hibernatable WebSockets. Idle connections cost nothing.
import { DurableObject } from "cloudflare:workers";
import {
  RULES, MAX_MESSAGE_BYTES, RuleError, isKnownCollection, validDocId, canRead, canWrite,
  parsePath, validateDoc, newId,
} from "./rules.js";
import { resolveRole, secretEntries, validEmail, verifySession, defaultRole } from "./auth.js";

const MAX_SOCKETS = 40;
const BUCKET_SIZE = 200; // write/read messages allowed in a burst
const BUCKET_REFILL_PER_SEC = 50;
const MAX_VIOLATIONS = 200; // then the connection is closed
const MAX_ASSIGNED_ROLES = 300;
const MAX_SEEN = 300; // recent sign-ins kept; the oldest are dropped first

export class Database extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(
      "CREATE TABLE IF NOT EXISTS docs (coll TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (coll, id)) WITHOUT ROWID"
    );
    this.sql.exec("CREATE TABLE IF NOT EXISTS roles (email TEXT PRIMARY KEY, role TEXT NOT NULL, by TEXT NOT NULL, ts INTEGER NOT NULL) WITHOUT ROWID");
    this.sql.exec("CREATE TABLE IF NOT EXISTS seen (email TEXT PRIMARY KEY, first INTEGER NOT NULL, last INTEGER NOT NULL, n INTEGER NOT NULL) WITHOUT ROWID");
    this.dbRoles = null; // loaded on first use after each wake-up (a handful of rows)
    // Heartbeats are answered without waking the object, so they cost nothing.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
    this.buckets = new WeakMap();
  }

  /* ---------- roles ---------- */

  loadRoles() {
    if (!this.dbRoles) {
      this.dbRoles = new Map();
      for (const r of this.sql.exec("SELECT email, role FROM roles").toArray()) this.dbRoles.set(r.email, r.role);
    }
    return this.dbRoles;
  }

  // { role, owner, source } for any email.
  resolve(email) {
    const e = String(email || "").toLowerCase();
    return resolveRole(this.env, e, this.loadRoles().get(e));
  }

  // Called after an owner or editor changes someone's role: tell or disconnect their open pages.
  onRolesChanged(email) {
    const r = this.resolve(email);
    for (const ws of this.ctx.getWebSockets()) {
      const att = ws.deserializeAttachment();
      if (!att || att.email !== email) continue;
      if (r.role === "none") { try { ws.close(4403, "No access."); } catch (e) { /* gone */ } }
      else this.send(ws, { t: "hello", role: r.role, owner: r.owner, email });
    }
  }

  whoami(email) {
    return this.resolve(email);
  }

  // Used at sign-in only. People who are on no list (they get the default role, or nothing)
  // are remembered so an owner can see them on the access page and give them more access.
  loginInfo(email) {
    const me = this.resolve(email);
    if (me.source === "default") {
      const e = String(email).toLowerCase(), now = Date.now();
      const exists = this.sql.exec("SELECT 1 AS x FROM seen WHERE email = ?", e).toArray().length > 0;
      if (!exists) {
        const n = this.sql.exec("SELECT COUNT(*) AS n FROM seen").one().n;
        if (n >= MAX_SEEN) this.sql.exec("DELETE FROM seen WHERE email IN (SELECT email FROM seen ORDER BY last ASC LIMIT ?)", n - MAX_SEEN + 1);
      }
      this.sql.exec("INSERT INTO seen (email, first, last, n) VALUES (?, ?, ?, 1) ON CONFLICT (email) DO UPDATE SET last = excluded.last, n = n + 1", e, now, now);
    }
    return me;
  }

  // Only owners may use the access page. Returns { ok, ... } or { ok:false, code, message }.
  listRoles(actorEmail) {
    const actor = this.resolve(actorEmail);
    if (!actor.owner) return { ok: false, code: "forbidden", message: "Only owners can manage access." };
    const assigned = this.sql.exec("SELECT email, role, by, ts FROM roles ORDER BY email").toArray().map((r) => ({ ...r, source: "admin" }));
    const seen = this.sql.exec("SELECT email, first, last, n FROM seen ORDER BY last DESC LIMIT 100").toArray()
      .filter((r) => this.resolve(r.email).source === "default");
    return { ok: true, you: { email: actorEmail, owner: actor.owner }, people: [...secretEntries(this.env), ...assigned], seen, defaultRole: defaultRole(this.env) };
  }

  // role: "viewer" | "contributor" | "editor" | "none" (remove) | "forget" (delete from the recent sign-ins).
  // Only owners may do this, and they cannot change people listed in the ROLES secret.
  changeRole(actorEmail, targetEmail, role) {
    const actor = this.resolve(actorEmail);
    if (!actor.owner) return { ok: false, code: "forbidden", message: "Only owners can manage access." };
    const target = String(targetEmail || "").trim().toLowerCase();
    if (!validEmail(target)) return { ok: false, code: "invalid", message: "That does not look like an email address." };
    if (!["viewer", "contributor", "editor", "none", "forget"].includes(role)) return { ok: false, code: "invalid", message: "Unknown role." };
    if (role === "forget") {
      this.sql.exec("DELETE FROM seen WHERE email = ?", target);
      return { ok: true, email: target, role };
    }
    const current = this.resolve(target);
    if (current.source === "secret") return { ok: false, code: "locked", message: "That person is set in the ROLES secret and can only be changed there." };
    const roles = this.loadRoles();
    this.sql.exec("DELETE FROM seen WHERE email = ?", target); // they are on a list now (or were just removed)
    if (role === "none") {
      this.sql.exec("DELETE FROM roles WHERE email = ?", target);
      roles.delete(target);
    } else {
      if (!roles.has(target) && roles.size >= MAX_ASSIGNED_ROLES) return { ok: false, code: "full", message: "The list is full." };
      this.sql.exec("INSERT INTO roles (email, role, by, ts) VALUES (?, ?, ?, ?) ON CONFLICT (email) DO UPDATE SET role = excluded.role, by = excluded.by, ts = excluded.ts",
        target, role, actorEmail, Date.now());
      roles.set(target, role);
    }
    this.onRolesChanged(target);
    return { ok: true, email: target, role };
  }

  /* ---------- WebSocket entry ---------- */

  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket") return new Response("Expected a WebSocket.", { status: 426 });
    const email = request.headers.get("x-user-email");
    const exp = Number(request.headers.get("x-session-exp"));
    if (!email || !exp) return new Response("Bad request.", { status: 400 });
    if (this.ctx.getWebSockets().length >= MAX_SOCKETS) return new Response("Too many connections.", { status: 503 });
    const me = this.resolve(email);
    const role = me.role;
    if (role === "none") return new Response("No access.", { status: 403 });

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({ email, exp, colls: [] });
    server.send(JSON.stringify({ t: "hello", role, owner: me.owner, email }));
    return new Response(null, { status: 101, webSocket: client, headers: { "Sec-WebSocket-Protocol": "kim-v1" } });
  }

  take(ws) {
    const now = Date.now();
    let b = this.buckets.get(ws);
    if (!b) { b = { tokens: BUCKET_SIZE, at: now, bad: 0 }; this.buckets.set(ws, b); }
    b.tokens = Math.min(BUCKET_SIZE, b.tokens + ((now - b.at) / 1000) * BUCKET_REFILL_PER_SEC);
    b.at = now;
    if (b.tokens < 1) { b.bad++; return b; }
    b.tokens -= 1;
    return null;
  }

  async webSocketMessage(ws, message) {
    const att = ws.deserializeAttachment() || {};
    if (typeof message !== "string") { ws.close(1003, "Text only."); return; }
    if (message.length > MAX_MESSAGE_BYTES) { ws.close(1009, "Message too big."); return; }
    const now = Math.floor(Date.now() / 1000);
    if (!att.exp || att.exp <= now) { ws.close(4401, "Session expired."); return; }
    const role = this.resolve(att.email).role;
    if (role === "none") { ws.close(4403, "No access."); return; }

    const limited = this.take(ws);
    if (limited) {
      if (limited.bad >= MAX_VIOLATIONS) { ws.close(4429, "Too many messages."); return; }
      let rid = null;
      try { rid = JSON.parse(message).rid; } catch (e) { /* ignore */ }
      this.send(ws, { t: "err", rid, code: "resource-exhausted", message: "Slow down." });
      return;
    }

    let msg;
    try { msg = JSON.parse(message); } catch (e) { this.send(ws, { t: "err", code: "invalid-argument", message: "Bad message." }); return; }
    if (!msg || typeof msg !== "object") return;

    if (msg.t === "sub") this.onSub(ws, att, role, msg);
    else if (msg.t === "w") this.onWrite(ws, role, msg);
    else if (msg.t === "auth") await this.onAuth(ws, att, msg);
    else this.send(ws, { t: "err", rid: msg.rid ?? null, code: "invalid-argument", message: "Unknown message." });
  }

  async webSocketClose(ws, code, reason) {
    try { ws.close(code && code >= 1000 && code < 5000 && code !== 1005 && code !== 1006 ? code : 1000, reason); } catch (e) { /* already closed */ }
  }

  async webSocketError(ws) {
    try { ws.close(1011, "Error."); } catch (e) { /* already closed */ }
  }

  send(ws, obj) {
    try { ws.send(typeof obj === "string" ? obj : JSON.stringify(obj)); } catch (e) { /* socket gone */ }
  }

  /* ---------- subscribe ---------- */

  onSub(ws, att, role, msg) {
    const sid = typeof msg.sid === "number" || typeof msg.sid === "string" ? msg.sid : null;
    const p = parsePath(msg.path);
    if (sid === null || !p) { this.send(ws, { t: "suberr", sid, code: "invalid-argument", message: "Bad path." }); return; }
    if (!canRead(role, p.coll)) { this.send(ws, { t: "suberr", sid, code: "permission-denied", message: "Not allowed." }); return; }

    const rows = (p.id
      ? this.sql.exec("SELECT id, data FROM docs WHERE coll = ? AND id = ?", p.coll, p.id)
      : this.sql.exec("SELECT id, data FROM docs WHERE coll = ? ORDER BY id", p.coll)).toArray();
    const docs = rows.map((r) => '{"id":' + JSON.stringify(r.id) + ',"data":' + r.data + "}");
    this.send(ws, '{"t":"snap","sid":' + JSON.stringify(sid) + ',"docs":[' + docs.join(",") + "]}");

    if (!att.colls.includes(p.coll)) {
      att.colls.push(p.coll);
      ws.serializeAttachment(att);
    }
  }

  /* ---------- refresh the session on an open connection ---------- */

  async onAuth(ws, att, msg) {
    const s = await verifySession(this.env, msg.token);
    if (!s || s.email !== att.email) { ws.close(4401, "Bad session."); return; }
    att.exp = s.exp;
    ws.serializeAttachment(att);
    this.send(ws, { t: "auth-ok", exp: s.exp });
  }

  /* ---------- writes ---------- */

  getRow(coll, id) {
    const r = this.sql.exec("SELECT data FROM docs WHERE coll = ? AND id = ?", coll, id).toArray();
    return r.length ? r[0].data : null;
  }

  ensureRoom(coll) {
    const n = this.sql.exec("SELECT COUNT(*) AS n FROM docs WHERE coll = ?", coll).one().n;
    if (n >= RULES[coll].max) throw new RuleError("resource-exhausted", "This collection is full.");
  }

  upsert(coll, id, text) {
    this.sql.exec(
      "INSERT INTO docs (coll, id, data) VALUES (?, ?, ?) ON CONFLICT (coll, id) DO UPDATE SET data = excluded.data",
      coll, id, text
    );
  }

  // Applies one write. Returns { id, text } where text is the new JSON or null for a delete.
  applyWrite(op, coll, id, data) {
    switch (op) {
      case "add": {
        if (!RULES[coll].canAdd) throw new RuleError("invalid-argument", "This collection does not allow add.");
        const text = validateDoc(data);
        this.ensureRoom(coll);
        const newDocId = newId();
        this.upsert(coll, newDocId, text);
        return { id: newDocId, text };
      }
      case "set": {
        if (!validDocId(coll, id)) throw new RuleError("invalid-argument", "Bad document id.");
        const text = validateDoc(data);
        if (this.getRow(coll, id) === null) this.ensureRoom(coll);
        this.upsert(coll, id, text);
        return { id, text };
      }
      case "update": {
        if (!validDocId(coll, id)) throw new RuleError("invalid-argument", "Bad document id.");
        const old = this.getRow(coll, id);
        if (old === null) throw new RuleError("not-found", "No such document.");
        if (data === null || typeof data !== "object" || Array.isArray(data)) throw new RuleError("failed-precondition", "Update needs an object.");
        const merged = JSON.parse(old);
        for (const [k, v] of Object.entries(data)) {
          if (v && typeof v === "object" && !Array.isArray(v) && v.$delete === true) delete merged[k];
          else merged[k] = v;
        }
        const text = validateDoc(merged);
        this.upsert(coll, id, text);
        return { id, text };
      }
      case "delete": {
        if (!validDocId(coll, id)) throw new RuleError("invalid-argument", "Bad document id.");
        this.sql.exec("DELETE FROM docs WHERE coll = ? AND id = ?", coll, id);
        return { id, text: null };
      }
      default:
        throw new RuleError("invalid-argument", "Unknown operation.");
    }
  }

  onWrite(ws, role, msg) {
    const rid = msg.rid ?? null;
    try {
      if (!isKnownCollection(msg.coll)) throw new RuleError("invalid-argument", "Unknown collection.");
      if (!canWrite(role, msg.coll)) throw new RuleError("permission-denied", "Not allowed.");
      const r = this.ctx.storage.transactionSync(() => this.applyWrite(msg.op, msg.coll, msg.id, msg.data));
      this.broadcast(msg.coll, r.id, r.text);
      this.send(ws, { t: "ack", rid, id: r.id });
    } catch (e) {
      if (e instanceof RuleError) this.send(ws, { t: "err", rid, code: e.code, message: e.message });
      else {
        console.error("write failed", e && e.message);
        this.send(ws, { t: "err", rid, code: "internal", message: "Could not save." });
      }
    }
  }

  broadcast(coll, id, text) {
    const out = '{"t":"chg","coll":' + JSON.stringify(coll) + ',"id":' + JSON.stringify(id) + ',"data":' + (text === null ? "null" : text) + "}";
    const now = Math.floor(Date.now() / 1000);
    for (const ws of this.ctx.getWebSockets()) {
      const att = ws.deserializeAttachment();
      if (!att || !att.colls || !att.colls.includes(coll) || att.exp <= now) continue;
      if (!canRead(this.resolve(att.email).role, coll)) continue;
      this.send(ws, out);
    }
  }

  /* ---------- RPC used by the Worker (export / import) ---------- */

  exportAll() {
    const out = { app: "kims-speed-dating", exportedAt: new Date().toISOString(), daters: [], questions: [], matches: [], streams: [], seats: [], game: null };
    for (const r of this.sql.exec("SELECT coll, id, data FROM docs ORDER BY coll, id").toArray()) {
      const obj = JSON.parse(r.data);
      if (r.coll === "daters" || r.coll === "questions" || r.coll === "matches") out[r.coll].push({ ...obj, id: r.id });
      else if (r.coll === "seats") (r.id.startsWith("stream_") ? out.streams : out.seats).push({ ...obj, id: r.id });
      else if (r.coll === "game" && r.id === "question") out.game = { question: { text: obj.text || "", handle: obj.handle || "", qid: obj.qid || "" }, hist: Array.isArray(obj.hist) ? obj.hist : [] };
    }
    return out;
  }

  counts() {
    const out = {};
    for (const r of this.sql.exec("SELECT coll, COUNT(*) AS n FROM docs GROUP BY coll").toArray()) out[r.coll] = r.n;
    return out;
  }

  // body: JSON text { docs: [{coll, id, data}], wipe: ["daters", ...] }
  importDocs(text) {
    const body = JSON.parse(text);
    const docs = Array.isArray(body.docs) ? body.docs : [];
    const wipe = Array.isArray(body.wipe) ? body.wipe : [];
    if (docs.length > 500) throw new RuleError("invalid-argument", "At most 500 documents per request.");
    for (const c of wipe) if (!isKnownCollection(c)) throw new RuleError("invalid-argument", "Unknown collection: " + c);

    const prepared = docs.map((d) => {
      if (!d || !isKnownCollection(d.coll) || !validDocId(d.coll, d.id)) throw new RuleError("invalid-argument", "Bad document: " + JSON.stringify([d && d.coll, d && d.id]));
      return { coll: d.coll, id: d.id, text: validateDoc(d.data) };
    });

    const changes = [];
    this.ctx.storage.transactionSync(() => {
      for (const c of wipe) {
        for (const r of this.sql.exec("SELECT id FROM docs WHERE coll = ?", c).toArray()) changes.push({ coll: c, id: r.id, text: null });
        this.sql.exec("DELETE FROM docs WHERE coll = ?", c);
      }
      for (const d of prepared) {
        this.upsert(d.coll, d.id, d.text);
        changes.push(d);
      }
    });
    for (const c of changes) this.broadcast(c.coll, c.id, c.text);
    return { written: prepared.length, wiped: wipe, counts: this.counts() };
  }
}
