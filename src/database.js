// One Durable Object holds all data (SQLite) and keeps every connected page in sync
// over hibernatable WebSockets. Idle connections cost nothing.
import { DurableObject } from "cloudflare:workers";
import {
  RULES, MAX_MESSAGE_BYTES, RuleError, isKnownCollection, validDocId, canRead, canWrite,
  parsePath, validateDoc, newId,
} from "./rules.js";
import { resolveRole, secretEntries, validEmail, verifySession, defaultRole, parseRoles } from "./auth.js";
import { normHandle, handleKey, cleanSignup } from "./people.js";

function parseRolesFor(env, email) { return parseRoles(env.ROLES).get(String(email).toLowerCase()); }

// Capacity: viewers (read-only watchers) are capped; hosts and mods keep STAFF_RESERVE extra places
// so a crowd of viewers can never lock them out. MAX_VIEWERS can be changed in wrangler.jsonc.
const STAFF_RESERVE = 15;
const DEFAULT_MAX_VIEWERS = 500;
function maxViewers(env) {
  const n = Number(env.MAX_VIEWERS);
  return Number.isFinite(n) && n >= 5 && n <= 5000 ? Math.floor(n) : DEFAULT_MAX_VIEWERS;
}
const BUCKET_SIZE = 200; // write/read messages allowed in a burst
const BUCKET_REFILL_PER_SEC = 50;
const MAX_VIOLATIONS = 200; // then the connection is closed
const MAX_ASSIGNED_ROLES = 300;
const MAX_MEMBERS = 5000; // everyone who signed in; the oldest without a username or sign-up are dropped first
const MAX_PENDING = 2000;

export class Database extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(
      "CREATE TABLE IF NOT EXISTS docs (coll TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (coll, id)) WITHOUT ROWID"
    );
    this.sql.exec("CREATE TABLE IF NOT EXISTS roles (email TEXT PRIMARY KEY, role TEXT NOT NULL, by TEXT NOT NULL, ts INTEGER NOT NULL) WITHOUT ROWID");
    this.sql.exec("CREATE TABLE IF NOT EXISTS seen (email TEXT PRIMARY KEY, first INTEGER NOT NULL, last INTEGER NOT NULL, n INTEGER NOT NULL) WITHOUT ROWID");
    this.sql.exec("CREATE TABLE IF NOT EXISTS role_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, actor TEXT NOT NULL, email TEXT NOT NULL, from_role TEXT NOT NULL, to_role TEXT NOT NULL)");
    this.sql.exec("CREATE TABLE IF NOT EXISTS members (email TEXT PRIMARY KEY, first INTEGER NOT NULL, last INTEGER NOT NULL, n INTEGER NOT NULL, handle TEXT, hkey TEXT) WITHOUT ROWID");
    this.sql.exec("CREATE UNIQUE INDEX IF NOT EXISTS members_hkey ON members (hkey) WHERE hkey IS NOT NULL");
    this.sql.exec("CREATE TABLE IF NOT EXISTS signups (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, handle TEXT NOT NULL, doc TEXT NOT NULL, status TEXT NOT NULL, dater_id TEXT, ts INTEGER NOT NULL)");
    this.sql.exec("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID");
    this.sql.exec("CREATE TABLE IF NOT EXISTS revoked (email TEXT PRIMARY KEY, after INTEGER NOT NULL) WITHOUT ROWID");
    // the old "recently signed in" list becomes the permanent member list (once)
    if (!this.sql.exec("SELECT 1 AS x FROM settings WHERE key = 'members_migrated'").toArray().length) {
      this.sql.exec("INSERT OR IGNORE INTO members (email, first, last, n) SELECT email, first, last, n FROM seen");
      this.sql.exec("INSERT INTO settings (key, value) VALUES ('members_migrated', '1')");
    }
    this.lock = undefined; // { ts, by } while the door is locked, else null (loaded on first use)
    this.sql.exec("CREATE TABLE IF NOT EXISTS revoked_jti (jti TEXT PRIMARY KEY, until INTEGER NOT NULL) WITHOUT ROWID");
    this.revokedJti = null; // Set of signed-out session ids
    this.revokedMap = null; // email -> seconds: sessions that began at or before this moment are no longer valid
    this.dbRoles = null; // loaded on first use after each wake-up (a handful of rows)
    // Heartbeats are answered without waking the object, so they cost nothing.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
    this.buckets = new WeakMap();
    this.meta = null; // ws -> attachment, built once per wake-up so a write never re-reads every socket
    this.nv = 0; this.ns = 0; // open viewer / staff connections
    this.snap = new Map(); // collection -> cached snapshot text (cleared on every change to that collection)
    this.memberCount = null;
  }

  /* ---------- connections (cached per wake-up) ---------- */

  loadMeta() {
    if (!this.meta) {
      this.meta = new Map(); this.nv = 0; this.ns = 0;
      for (const ws of this.ctx.getWebSockets()) {
        const a = ws.deserializeAttachment() || {};
        if (!Array.isArray(a.colls)) a.colls = [];
        this.meta.set(ws, a);
        if (a.v) this.nv++; else this.ns++;
      }
    }
    return this.meta;
  }

  attOf(ws) {
    const m = this.loadMeta();
    let a = m.get(ws);
    if (!a) {
      a = ws.deserializeAttachment() || {};
      if (!Array.isArray(a.colls)) a.colls = [];
      m.set(ws, a);
      if (a.v) this.nv++; else this.ns++;
    }
    return a;
  }

  addMeta(ws, att) {
    this.loadMeta().set(ws, att);
    if (att.v) this.nv++; else this.ns++;
  }

  dropMeta(ws) {
    if (!this.meta) return;
    const a = this.meta.get(ws);
    if (a) { if (a.v) this.nv--; else this.ns--; this.meta.delete(ws); }
  }

  isFull(role) {
    this.loadMeta();
    const v = maxViewers(this.env);
    return role === "viewer" ? this.nv >= v : this.nv + this.ns >= v + STAFF_RESERVE;
  }

  /* ---------- roles ---------- */

  loadRoles() {
    if (!this.dbRoles) {
      this.dbRoles = new Map();
      for (const r of this.sql.exec("SELECT email, role FROM roles").toArray()) this.dbRoles.set(r.email, r.role);
    }
    return this.dbRoles;
  }

  loadLock() {
    if (this.lock === undefined) {
      const r = this.sql.exec("SELECT value FROM settings WHERE key = 'lock'").toArray();
      this.lock = null;
      if (r.length) { try { this.lock = JSON.parse(r[0].value); } catch (e) { this.lock = null; } }
    }
    return this.lock;
  }

  loadRevoked() {
    if (!this.revokedMap) {
      this.revokedMap = new Map();
      for (const r of this.sql.exec("SELECT email, after FROM revoked").toArray()) this.revokedMap.set(r.email, r.after);
    }
    return this.revokedMap;
  }

  loadRevokedJti() {
    if (!this.revokedJti) {
      this.revokedJti = new Set();
      for (const r of this.sql.exec("SELECT jti FROM revoked_jti").toArray()) this.revokedJti.add(r.jti);
    }
    return this.revokedJti;
  }

  // True when this session was signed out on its own, or the owner signed the person out everywhere after it began.
  isRevoked(email, iat, jti) {
    if (typeof jti === "string" && this.loadRevokedJti().has(jti)) return true;
    if (typeof iat !== "number") return false;
    const a = this.loadRevoked().get(String(email || "").toLowerCase());
    return a !== undefined && iat <= a;
  }

  // { role, owner, source } for any email. iat = when that person's session began (seconds), if known.
  resolve(email, iat) {
    const e = String(email || "").toLowerCase();
    const lock = this.loadLock();
    return resolveRole(this.env, e, this.loadRoles().get(e), { iat, lockTs: lock ? lock.ts : 0 });
  }

  // Called after an owner or editor changes someone's role: tell or disconnect their open pages.
  onRolesChanged(email) {
    for (const [ws, att] of this.loadMeta()) {
      if (att.email !== email) continue;
      const r = this.resolve(email, att.iat);
      if (r.role === "none") { try { ws.close(4403, "No access."); } catch (e) { /* gone */ } continue; }
      const v = r.role === "viewer";
      if (!!att.v !== v) { if (att.v) this.nv--; else this.ns--; att.v = v; if (v) this.nv++; else this.ns++; try { ws.serializeAttachment(att); } catch (e) { /* gone */ } }
      this.send(ws, { t: "hello", role: r.role, owner: r.owner, email });
    }
  }

  whoami(email, iat, jti) {
    return { ...this.resolve(email, iat), revoked: this.isRevoked(email, iat, jti) };
  }

  // Used at sign-in only. Everyone who signs in is remembered (the permanent member list), so an owner can search them,
  // give people on no list more access, and so people can add a TikTok username.
  loginInfo(email) {
    const me = this.resolve(email, Math.floor(Date.now() / 1000));
    if (!me.locked && (me.source === "default" || me.role !== "none")) this.recordMember(String(email).toLowerCase());
    return me;
  }

  recordMember(e) {
    const now = Date.now();
    const exists = this.sql.exec("SELECT 1 AS x FROM members WHERE email = ?", e).toArray().length > 0;
    if (!exists) {
      if (this.memberCount === null) this.memberCount = this.sql.exec("SELECT COUNT(*) AS n FROM members").one().n;
      if (this.memberCount >= MAX_MEMBERS) {
        const drop = this.memberCount - MAX_MEMBERS + 50; // free a little room so this does not run on every sign-in
        this.sql.exec("DELETE FROM members WHERE email IN (SELECT email FROM members WHERE handle IS NULL AND email NOT IN (SELECT email FROM signups) ORDER BY last ASC LIMIT ?)", drop);
        this.memberCount = this.sql.exec("SELECT COUNT(*) AS n FROM members").one().n;
        if (this.memberCount >= MAX_MEMBERS) return false; // full of people with profiles: do not record more
      }
      this.memberCount++;
    }
    this.sql.exec("INSERT INTO members (email, first, last, n) VALUES (?, ?, ?, 1) ON CONFLICT (email) DO UPDATE SET last = excluded.last, n = n + 1", e, now, now);
    return true;
  }

  // Only owners may use the access page. Returns { ok, ... } or { ok:false, code, message }.
  listRoles(actorEmail) {
    const actor = this.resolve(actorEmail);
    if (!actor.owner) return { ok: false, code: "forbidden", message: "Only owners can manage access." };
    const assigned = this.sql.exec("SELECT email, role, by, ts FROM roles ORDER BY email").toArray().map((r) => ({ ...r, source: "admin" }));
    const seen = this.sql.exec("SELECT email, first, last, n, handle FROM members ORDER BY last DESC LIMIT 400").toArray()
      .filter((r) => this.resolve(r.email).source === "default").slice(0, 100);
    const log = this.sql.exec("SELECT id, ts, actor, email, from_role, to_role FROM role_log ORDER BY id DESC LIMIT 25").toArray();
    return { ok: true, you: { email: actorEmail, owner: actor.owner }, people: [...secretEntries(this.env), ...assigned], seen, log, defaultRole: defaultRole(this.env), locked: this.loadLock() };
  }

  // role: "viewer" | "contributor" | "editor" | "blocked" | "none" (remove) | "forget" (delete from the recent sign-ins).
  // Only owners may do this, and they cannot change people listed in the ROLES secret.
  changeRole(actorEmail, targetEmail, role) {
    const actor = this.resolve(actorEmail);
    if (!actor.owner) return { ok: false, code: "forbidden", message: "Only owners can manage access." };
    const target = String(targetEmail || "").trim().toLowerCase();
    if (!validEmail(target)) return { ok: false, code: "invalid", message: "That does not look like an email address." };
    if (!["viewer", "contributor", "editor", "blocked", "none", "forget"].includes(role)) return { ok: false, code: "invalid", message: "Unknown role." };
    if (role === "forget") {
      this.sql.exec("DELETE FROM signups WHERE email = ?", target);
      this.sql.exec("DELETE FROM members WHERE email = ?", target); this.memberCount = null;
      return { ok: true, email: target, role };
    }
    const current = this.resolve(target);
    if (current.source === "secret") return { ok: false, code: "locked", message: "That person is set in the ROLES secret and can only be changed there." };
    const roles = this.loadRoles();
    const prev = roles.get(target);
    if (role === "none") {
      this.sql.exec("DELETE FROM roles WHERE email = ?", target);
      roles.delete(target);
    } else {
      if (!roles.has(target) && roles.size >= MAX_ASSIGNED_ROLES) return { ok: false, code: "full", message: "The list is full." };
      this.sql.exec("INSERT INTO roles (email, role, by, ts) VALUES (?, ?, ?, ?) ON CONFLICT (email) DO UPDATE SET role = excluded.role, by = excluded.by, ts = excluded.ts",
        target, role, actorEmail, Date.now());
      roles.set(target, role);
    }
    const before = prev || "none";
    if (before !== role) { // remember it so the owner can undo a mistake with one tap
      this.sql.exec("INSERT INTO role_log (ts, actor, email, from_role, to_role) VALUES (?, ?, ?, ?, ?)", Date.now(), actorEmail, target, before, role);
      this.sql.exec("DELETE FROM role_log WHERE id <= (SELECT MAX(id) FROM role_log) - 100");
    }
    this.onRolesChanged(target);
    return { ok: true, email: target, role };
  }

  /* ---------- signing out, locking the door, erasing a person (owners) ---------- */

  // Ends every session of this person that began before now, and closes their open pages.
  revokeSessions(email) {
    const e = String(email || "").toLowerCase();
    const now = Math.floor(Date.now() / 1000);
    this.sql.exec("INSERT INTO revoked (email, after) VALUES (?, ?) ON CONFLICT (email) DO UPDATE SET after = excluded.after", e, now);
    this.sql.exec("DELETE FROM revoked WHERE after < ?", now - 8 * 24 * 3600); // older than any session could live
    this.loadRevoked().set(e, now);
    for (const [ws, att] of this.loadMeta()) if (att.email === e) { try { ws.close(4403, "Signed out."); } catch (x) { /* gone */ } }
  }

  // Ends just this session (jti). Sessions made before session ids existed cannot be told apart, so those end everywhere.
  signOutSelf(email, jti) {
    const e = String(email || "").toLowerCase();
    if (!validEmail(e)) return { ok: false, code: "invalid", message: "Bad email." };
    if (typeof jti !== "string") { this.revokeSessions(e); return { ok: true }; }
    const now = Math.floor(Date.now() / 1000);
    this.sql.exec("INSERT INTO revoked_jti (jti, until) VALUES (?, ?) ON CONFLICT (jti) DO NOTHING", jti, now + 8 * 24 * 3600);
    this.sql.exec("DELETE FROM revoked_jti WHERE until < ?", now);
    this.loadRevokedJti().add(jti);
    for (const [ws, att] of this.loadMeta()) if (att.email === e && att.jti === jti) { try { ws.close(4403, "Signed out."); } catch (x) { /* gone */ } }
    return { ok: true };
  }

  signOutEmail(actorEmail, targetEmail) {
    if (!this.resolve(actorEmail).owner) return { ok: false, code: "forbidden", message: "Only owners can do that." };
    const t = String(targetEmail || "").trim().toLowerCase();
    if (!validEmail(t)) return { ok: false, code: "invalid", message: "That does not look like an email address." };
    this.revokeSessions(t);
    return { ok: true, email: t };
  }

  setLock(actorEmail, locked) {
    if (!this.resolve(actorEmail).owner) return { ok: false, code: "forbidden", message: "Only owners can do that." };
    if (locked) {
      const v = { ts: Math.floor(Date.now() / 1000), by: String(actorEmail).toLowerCase() };
      this.sql.exec("INSERT INTO settings (key, value) VALUES ('lock', ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value", JSON.stringify(v));
      this.lock = v;
    } else {
      this.sql.exec("DELETE FROM settings WHERE key = 'lock'");
      this.lock = null;
    }
    return { ok: true, locked: this.lock };
  }

  // Finds everything that mentions a person, for the "erase a person" tool. Nothing is changed here.
  personMatches(query) {
    const q = String(query || "").trim().toLowerCase();
    if (q.length < 2 || q.length > 80) return null;
    const has = (v) => typeof v === "string" && v.toLowerCase().includes(q);
    const out = { query: q, accounts: [], daters: [], matches: [], questions: [], seats: [] };

    const emails = new Map();
    for (const r of this.sql.exec("SELECT email, role FROM roles").toArray()) if (r.email.includes(q)) emails.set(r.email, { email: r.email, kind: r.role === "blocked" ? "blocked" : "on the list as " + r.role });
    for (const r of this.sql.exec("SELECT email, handle FROM members").toArray()) if ((r.email.includes(q) || (r.handle && r.handle.toLowerCase().includes(q))) && !emails.has(r.email)) emails.set(r.email, { email: r.email, kind: r.handle ? "member, TikTok @" + r.handle : "member" });
    for (const r of this.sql.exec("SELECT email FROM revoked").toArray()) if (r.email.includes(q) && !emails.has(r.email)) emails.set(r.email, { email: r.email, kind: "sign-out record" });
    for (const a of emails.values()) {
      a.locked = !!parseRolesFor(this.env, a.email);
      a.logRows = this.sql.exec("SELECT COUNT(*) AS n FROM role_log WHERE email = ? OR actor = ?", a.email, a.email).one().n;
      out.accounts.push(a);
      if (out.accounts.length >= 25) break;
    }

    const ids = new Set();
    for (const r of this.sql.exec("SELECT id, data FROM docs WHERE coll = 'daters'").toArray()) {
      let d; try { d = JSON.parse(r.data); } catch (e) { continue; }
      if (has(d.name)) { ids.add(r.id); if (out.daters.length < 50) out.daters.push({ id: r.id, label: [d.name, d.age, d.location].filter((x) => x !== undefined && x !== "").join(", ") }); }
    }
    for (const r of this.sql.exec("SELECT id, data FROM docs WHERE coll = 'matches'").toArray()) {
      let d; try { d = JSON.parse(r.data); } catch (e) { continue; }
      if (has(d.hotName) || has(d.pickName) || ids.has(d.hotId) || ids.has(d.pickId)) { if (out.matches.length < 50) out.matches.push({ id: r.id, label: (d.hotName || "?") + " and " + (d.pickName || "?") }); }
    }
    for (const r of this.sql.exec("SELECT id, data FROM docs WHERE coll = 'questions'").toArray()) {
      let d; try { d = JSON.parse(r.data); } catch (e) { continue; }
      if (has(d.handle)) { if (out.questions.length < 50) out.questions.push({ id: r.id, label: (d.handle || "") + ": " + String(d.text || "").slice(0, 60) }); }
    }
    for (const r of this.sql.exec("SELECT id, data FROM docs WHERE coll = 'seats'").toArray()) {
      if (r.id.startsWith("stream_")) continue;
      let d; try { d = JSON.parse(r.data); } catch (e) { continue; }
      const dt = d && d.dater;
      if (dt && (has(dt.name) || ids.has(dt.id))) out.seats.push({ id: r.id, label: "Seat " + r.id + ": " + (dt.name || "?") });
    }
    return out;
  }

  findPerson(actorEmail, query) {
    if (!this.resolve(actorEmail).owner) return { ok: false, code: "forbidden", message: "Only owners can do that." };
    const m = this.personMatches(query);
    if (!m) return { ok: false, code: "invalid", message: "Type at least 2 characters (a name, handle or email)." };
    return { ok: true, ...m };
  }

  // sel: { accounts: [email], daters: [id], matches: [id], questions: [id], seats: [id], deleteQuestions: bool }
  // Only items that still match the search are touched.
  erasePerson(actorEmail, query, sel) {
    if (!this.resolve(actorEmail).owner) return { ok: false, code: "forbidden", message: "Only owners can do that." };
    const m = this.personMatches(query);
    if (!m) return { ok: false, code: "invalid", message: "Type at least 2 characters (a name, handle or email)." };
    sel = sel && typeof sel === "object" ? sel : {};
    const pick = (list, key) => { const want = new Set(Array.isArray(sel[key]) ? sel[key].map(String) : []); return list.filter((x) => want.has(x[key === "accounts" ? "email" : "id"])); };
    const accounts = pick(m.accounts, "accounts").filter((a) => !a.locked);
    const daters = pick(m.daters, "daters"), matches = pick(m.matches, "matches"), questions = pick(m.questions, "questions"), seats = pick(m.seats, "seats");
    const q = m.query;
    const changes = [];
    const counts = { accounts: accounts.length, daters: daters.length, matches: matches.length, questions: questions.length, seats: seats.length };
    this.ctx.storage.transactionSync(() => {
      for (const a of accounts) {
        this.sql.exec("DELETE FROM roles WHERE email = ?", a.email);
        this.sql.exec("DELETE FROM members WHERE email = ?", a.email);
        this.sql.exec("DELETE FROM signups WHERE email = ?", a.email);
        this.sql.exec("DELETE FROM revoked WHERE email = ?", a.email);
        this.sql.exec("UPDATE role_log SET email = '(erased)' WHERE email = ?", a.email);
        this.sql.exec("UPDATE role_log SET actor = '(erased)' WHERE actor = ?", a.email);
        this.sql.exec("UPDATE roles SET by = '(erased)' WHERE by = ?", a.email);
      }
      if (accounts.length) { this.dbRoles = null; this.revokedMap = null; this.memberCount = null; }
      for (const d of daters) { this.sql.exec("DELETE FROM docs WHERE coll = 'daters' AND id = ?", d.id); changes.push({ coll: "daters", id: d.id, text: null }); }
      for (const x of matches) { this.sql.exec("DELETE FROM docs WHERE coll = 'matches' AND id = ?", x.id); changes.push({ coll: "matches", id: x.id, text: null }); }
      for (const x of questions) {
        if (sel.deleteQuestions) { this.sql.exec("DELETE FROM docs WHERE coll = 'questions' AND id = ?", x.id); changes.push({ coll: "questions", id: x.id, text: null }); continue; }
        const row = this.getRow("questions", x.id); if (row === null) continue;
        const o = JSON.parse(row); o.handle = ""; const t = validateDoc(o); this.upsert("questions", x.id, t); changes.push({ coll: "questions", id: x.id, text: t });
      }
      const dids = new Set(daters.map((d) => d.id));
      for (const sdoc of seats) {
        const row = this.getRow("seats", sdoc.id); if (row === null) continue;
        const o = JSON.parse(row); o.dater = null; o.view = null; if ("since" in o) o.since = null; if ("unlocked" in o) o.unlocked = false;
        const t = validateDoc(o); this.upsert("seats", sdoc.id, t); changes.push({ coll: "seats", id: sdoc.id, text: t });
      }
      // the running stream remembers who was seated by id
      const st = this.getRow("seats", "stream");
      if (st !== null && dids.size) {
        const o = JSON.parse(st);
        if (Array.isArray(o.ids)) { o.ids = o.ids.filter((i) => !dids.has(i)); const t = validateDoc(o); this.upsert("seats", "stream", t); changes.push({ coll: "seats", id: "stream", text: t }); }
      }
      // the question on screen and its history can carry a chat handle
      if (questions.length) {
        const g = this.getRow("game", "question");
        if (g !== null) {
          const o = JSON.parse(g); let hit = false;
          const mine = (h) => typeof h === "string" && h.toLowerCase().includes(q);
          if (mine(o.handle)) { o.handle = ""; hit = true; }
          if (Array.isArray(o.hist)) for (const h of o.hist) if (h && mine(h.handle)) { h.handle = ""; hit = true; }
          if (hit) { const t = validateDoc(o); this.upsert("game", "question", t); changes.push({ coll: "game", id: "question", text: t }); }
        }
      }
      this.sql.exec("INSERT INTO role_log (ts, actor, email, from_role, to_role) VALUES (?, ?, '(erased)', 'erased', 'erased')", Date.now(), String(actorEmail).toLowerCase());
      this.sql.exec("DELETE FROM role_log WHERE id <= (SELECT MAX(id) FROM role_log) - 100");
    });
    for (const c of changes) this.broadcast(c.coll, c.id, c.text);
    for (const a of accounts) this.onRolesChanged(a.email);
    return { ok: true, removed: counts };
  }

  /* ---------- WebSocket entry ---------- */

  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket") return new Response("Expected a WebSocket.", { status: 426 });
    const email = request.headers.get("x-user-email");
    const exp = Number(request.headers.get("x-session-exp"));
    const iat = Number(request.headers.get("x-session-iat"));
    const jti = request.headers.get("x-session-jti") || undefined;
    if (!email || !exp || !iat) return new Response("Bad request.", { status: 400 });
    if (this.isRevoked(email, iat, jti)) return new Response("Not signed in.", { status: 401 });
    const me = this.resolve(email, iat);
    const role = me.role;
    if (role === "none") return new Response("No access.", { status: 403 });
    if (this.isFull(role)) return new Response("The room is full right now.", { status: 503, headers: { "retry-after": "240" } });

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server);
    const att = { email, exp, iat, jti, colls: [], v: role === "viewer" };
    server.serializeAttachment(att);
    this.addMeta(server, att);
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
    const att = this.attOf(ws);
    if (typeof message !== "string") { ws.close(1003, "Text only."); return; }
    if (message.length > MAX_MESSAGE_BYTES) { ws.close(1009, "Message too big."); return; }
    const now = Math.floor(Date.now() / 1000);
    if (!att.exp || att.exp <= now) { ws.close(4401, "Session expired."); return; }
    if (this.isRevoked(att.email, att.iat, att.jti)) { ws.close(4403, "Signed out."); return; }
    const role = this.resolve(att.email, att.iat).role;
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
    this.dropMeta(ws);
    try { ws.close(code && code >= 1000 && code < 5000 && code !== 1005 && code !== 1006 ? code : 1000, reason); } catch (e) { /* already closed */ }
  }

  async webSocketError(ws) {
    this.dropMeta(ws);
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

    let docsText;
    if (p.id) {
      const rows = this.sql.exec("SELECT id, data FROM docs WHERE coll = ? AND id = ?", p.coll, p.id).toArray();
      docsText = rows.map((r) => '{"id":' + JSON.stringify(r.id) + ',"data":' + r.data + "}").join(",");
    } else {
      // Whole collections are cached until they change, so a crowd connecting does not re-read the database for each person.
      docsText = this.snap.get(p.coll);
      if (docsText === undefined) {
        const rows = this.sql.exec("SELECT id, data FROM docs WHERE coll = ? ORDER BY id", p.coll).toArray();
        docsText = rows.map((r) => '{"id":' + JSON.stringify(r.id) + ',"data":' + r.data + "}").join(",");
        this.snap.set(p.coll, docsText);
      }
    }
    this.send(ws, '{"t":"snap","sid":' + JSON.stringify(sid) + ',"docs":[' + docsText + "]}");

    if (!att.colls.includes(p.coll)) {
      att.colls.push(p.coll);
      ws.serializeAttachment(att);
    }
  }

  /* ---------- refresh the session on an open connection ---------- */

  async onAuth(ws, att, msg) {
    const s = await verifySession(this.env, msg.token);
    if (!s || s.email !== att.email) { ws.close(4401, "Bad session."); return; }
    if (this.isRevoked(s.email, s.iat, s.jti)) { ws.close(4403, "Signed out."); return; }
    att.exp = s.exp; att.iat = s.iat; if (s.jti) att.jti = s.jti;
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
    this.snap.delete(coll);
    const now = Math.floor(Date.now() / 1000);
    for (const [ws, att] of this.loadMeta()) {
      if (!att.colls.includes(coll) || att.exp <= now) continue;
      const role = this.resolve(att.email, att.iat).role;
      if (role === "none" || this.isRevoked(att.email, att.iat, att.jti)) { try { ws.close(4403, "No access."); } catch (e) { /* gone */ } continue; } // blocked or signed out: send nothing, close
      if (!canRead(role, coll)) continue;
      this.send(ws, out);
    }
  }

  /* ---------- profiles, sign-ups and pending daters ---------- */

  isEditor(email) { return this.resolve(email).role === "editor"; } // owners resolve to editor level

  claimHandle(e, handle) { // sets this person's TikTok username; one account per username
    const key = handleKey(handle);
    const taken = this.sql.exec("SELECT email FROM members WHERE hkey = ? AND email <> ?", key, e).toArray();
    if (taken.length) return { ok: false, code: "taken", message: "That TikTok username is already claimed by another account. If it is yours, ask the host to free it up." };
    if (!this.sql.exec("SELECT 1 AS x FROM members WHERE email = ?", e).toArray().length && !this.recordMember(e)) return { ok: false, code: "full", message: "The member list is full right now." };
    this.sql.exec("UPDATE members SET handle = ?, hkey = ? WHERE email = ?", handle, key, e);
    this.sql.exec("UPDATE signups SET handle = ?, doc = json_set(doc, '$.name', ?) WHERE email = ? AND status = 'pending'", handle, handle, e);
    return { ok: true, handle };
  }

  // The person's own profile and sign-up status.
  myProfile(email) {
    const e = String(email || "").toLowerCase();
    const m = this.sql.exec("SELECT handle FROM members WHERE email = ?", e).toArray();
    const su = this.sql.exec("SELECT id, handle, doc, status, dater_id FROM signups WHERE email = ?", e).toArray()[0];
    let signup = { status: "none" };
    if (su) {
      const gone = su.status === "approved" && su.dater_id && this.getRow("daters", su.dater_id) === null;
      signup = { status: gone ? "removed" : su.status, doc: JSON.parse(su.doc) };
    }
    return { ok: true, handle: m.length ? m[0].handle : null, signup };
  }

  setHandle(email, raw) {
    const e = String(email || "").toLowerCase(), h = normHandle(raw);
    if (!h) return { ok: false, code: "invalid", message: "Enter your TikTok username (2 to 24 letters, numbers, dots or underscores)." };
    const r = this.claimHandle(e, h);
    return r.ok ? { ok: true, handle: h } : r;
  }

  submitSignup(email, body) {
    const e = String(email || "").toLowerCase();
    if (body && body.withdraw === true) {
      const row = this.sql.exec("SELECT status FROM signups WHERE email = ?", e).toArray()[0];
      if (row && row.status === "approved") return { ok: false, code: "locked", message: "You are already on the list. Ask the host if you want to be removed." };
      this.sql.exec("DELETE FROM signups WHERE email = ? AND status = 'pending'", e);
      return { ok: true, status: "none" };
    }
    const c = cleanSignup(body);
    if (!c.ok) return { ok: false, code: "invalid", message: c.message };
    const row = this.sql.exec("SELECT id, status, dater_id FROM signups WHERE email = ?", e).toArray()[0];
    if (row && row.status === "approved" && this.getRow("daters", row.dater_id) !== null) return { ok: false, code: "locked", message: "You are already on the speed dater list. Ask the host to change anything." };
    if (!row) {
      const n = this.sql.exec("SELECT COUNT(*) AS n FROM signups WHERE status = 'pending'").one().n;
      if (n >= MAX_PENDING) return { ok: false, code: "full", message: "The sign-up list is full right now." };
    }
    const h = this.claimHandle(e, c.handle);
    if (!h.ok) return h;
    this.sql.exec("INSERT INTO signups (id, email, handle, doc, status, dater_id, ts) VALUES (?, ?, ?, ?, 'pending', NULL, ?) ON CONFLICT (email) DO UPDATE SET handle = excluded.handle, doc = excluded.doc, status = 'pending', dater_id = NULL, ts = excluded.ts",
      row ? row.id : newId(), e, c.handle, JSON.stringify(c.doc), Date.now());
    return { ok: true, status: "pending" };
  }

  // Host side. Hosts (editors and owners) see sign-ups without email addresses; owners also see the email.
  listSignups(actorEmail) {
    if (!this.isEditor(actorEmail)) return { ok: false, code: "forbidden", message: "Only hosts can see sign-ups." };
    const owner = this.resolve(actorEmail).owner;
    const rows = this.sql.exec("SELECT id, email, handle, doc, ts FROM signups WHERE status = 'pending' ORDER BY ts DESC LIMIT 500").toArray();
    return { ok: true, pending: rows.map((r) => ({ id: r.id, handle: r.handle, ts: r.ts, ...JSON.parse(r.doc), ...(owner ? { email: r.email } : {}) })) };
  }

  approveSignup(actorEmail, id) {
    if (!this.isEditor(actorEmail)) return { ok: false, code: "forbidden", message: "Only hosts can approve sign-ups." };
    const su = this.sql.exec("SELECT id, handle, doc, status, dater_id FROM signups WHERE id = ?", String(id || "")).toArray()[0];
    if (!su) return { ok: false, code: "not_found", message: "That sign-up is gone (declined or withdrawn)." };
    if (su.status === "approved" && su.dater_id) {
      const row = this.getRow("daters", su.dater_id);
      if (row !== null) return { ok: true, daterId: su.dater_id, dater: JSON.parse(row), already: true };
    }
    let out;
    this.ctx.storage.transactionSync(() => {
      this.ensureRoom("daters");
      const data = { ...JSON.parse(su.doc), ts: Date.now(), src: "signup" };
      const daterId = newId();
      const text = validateDoc(data);
      this.upsert("daters", daterId, text);
      this.sql.exec("UPDATE signups SET status = 'approved', dater_id = ? WHERE id = ?", daterId, su.id);
      out = { daterId, data, text };
    });
    this.broadcast("daters", out.daterId, out.text);
    return { ok: true, daterId: out.daterId, dater: out.data };
  }

  declineSignup(actorEmail, id) {
    if (!this.isEditor(actorEmail)) return { ok: false, code: "forbidden", message: "Only hosts can decline sign-ups." };
    this.sql.exec("DELETE FROM signups WHERE id = ? AND status = 'pending'", String(id || ""));
    return { ok: true };
  }

  clearSignups(actorEmail) {
    if (!this.isEditor(actorEmail)) return { ok: false, code: "forbidden", message: "Only hosts can clear sign-ups." };
    const n = this.sql.exec("SELECT COUNT(*) AS n FROM signups WHERE status = 'pending'").one().n;
    this.sql.exec("DELETE FROM signups WHERE status = 'pending'");
    return { ok: true, cleared: n };
  }

  // The host added the dater by hand and confirmed it is the same person as this sign-up.
  linkSignup(actorEmail, id, daterId) {
    if (!this.isEditor(actorEmail)) return { ok: false, code: "forbidden", message: "Only hosts can do that." };
    if (typeof daterId !== "string" || this.getRow("daters", daterId) === null) return { ok: false, code: "not_found", message: "That dater does not exist." };
    this.sql.exec("UPDATE signups SET status = 'approved', dater_id = ? WHERE id = ? AND status = 'pending'", daterId, String(id || ""));
    return { ok: true };
  }

  // Owners only: search everyone who has signed in, by email or TikTok username.
  findPeople(actorEmail, q) {
    if (!this.resolve(actorEmail).owner) return { ok: false, code: "forbidden", message: "Only owners can search people." };
    const t = String(q || "").trim().toLowerCase().replace(/^@+/, "");
    if (t.length < 2 || t.length > 60) return { ok: false, code: "invalid", message: "Type at least 2 characters." };
    const like = "%" + t.replace(/[\\%_]/g, (c) => "\\" + c) + "%";
    const rows = this.sql.exec("SELECT email, first, last, n, handle FROM members WHERE lower(email) LIKE ? ESCAPE '\\' OR hkey LIKE ? ESCAPE '\\' ORDER BY last DESC LIMIT 50", like, like).toArray();
    const people = rows.map((r) => {
      const me = this.resolve(r.email), su = this.sql.exec("SELECT status FROM signups WHERE email = ?", r.email).toArray()[0];
      return { ...r, role: me.source === "secret" ? (me.owner ? "owner" : me.role) : me.blocked ? "blocked" : me.role, source: me.source, signup: su ? su.status : "none" };
    });
    return { ok: true, people, total: this.sql.exec("SELECT COUNT(*) AS n FROM members").one().n };
  }

  releaseHandle(actorEmail, email) {
    if (!this.resolve(actorEmail).owner) return { ok: false, code: "forbidden", message: "Only owners can do that." };
    const e = String(email || "").trim().toLowerCase();
    if (!validEmail(e)) return { ok: false, code: "invalid", message: "That does not look like an email address." };
    this.sql.exec("UPDATE members SET handle = NULL, hkey = NULL WHERE email = ?", e);
    this.sql.exec("DELETE FROM signups WHERE email = ? AND status = 'pending'", e);
    return { ok: true };
  }

  /* ---------- question categories ---------- */

  categoryStatus() {
    let total = 0, done = 0;
    for (const r of this.sql.exec("SELECT data FROM docs WHERE coll = 'questions'").toArray()) {
      total++;
      try { if (typeof JSON.parse(r.data).cat === "string") done++; } catch (e) { /* skip */ }
    }
    return { total, categorized: done };
  }

  // Gives every question that has no category the one listed in `map` (id -> key). Existing categories, ask counts and
  // every other field are left alone. Viewers get one small patch message instead of one message per question.
  applyCategories(actorEmail, map, allowed) {
    if (!this.resolve(actorEmail).owner) return { ok: false, code: "forbidden", message: "Only owners can do that." };
    const okKey = new Set(allowed);
    const patch = [];
    let total = 0, already = 0, unknown = 0;
    this.ctx.storage.transactionSync(() => {
      for (const r of this.sql.exec("SELECT id, data FROM docs WHERE coll = 'questions'").toArray()) {
        total++;
        let d; try { d = JSON.parse(r.data); } catch (e) { continue; }
        if (typeof d.cat === "string") { already++; continue; }
        const c = Object.prototype.hasOwnProperty.call(map, r.id) ? map[r.id] : undefined;
        if (!okKey.has(c)) { unknown++; continue; }
        d.cat = c;
        this.upsert("questions", r.id, validateDoc(d));
        patch.push([r.id, { cat: c }]);
      }
    });
    if (patch.length) this.broadcastPatch("questions", patch);
    return { ok: true, applied: patch.length, already, unknown, total };
  }

  packStatus(ids) {
    let present = 0;
    for (const id of ids) if (this.getRow("questions", id) !== null) present++;
    return { total: ids.length, present, missing: ids.length - present };
  }

  // Adds the questions of a pack that are not there yet (matched by id). Existing questions are never touched.
  addPack(actorEmail, questions, allowed) {
    if (!this.resolve(actorEmail).owner) return { ok: false, code: "forbidden", message: "Only owners can do that." };
    const okKey = new Set(allowed);
    const add = [];
    let skipped = 0;
    const base = Date.now();
    this.ctx.storage.transactionSync(() => {
      for (const q of questions) {
        if (!q || typeof q.id !== "string" || typeof q.text !== "string" || !okKey.has(q.cat) || !validDocId("questions", q.id) || q.text.length < 3 || q.text.length > 300) throw new RuleError("invalid-argument", "The pack has a bad entry.");
        if (this.getRow("questions", q.id) !== null) { skipped++; continue; }
        this.ensureRoom("questions");
        const data = { text: q.text, handle: "", status: "ready", cat: q.cat, ts: base + add.length };
        this.upsert("questions", q.id, validateDoc(data));
        add.push([q.id, data]);
      }
    });
    if (add.length) this.broadcastAdd("questions", add);
    return { ok: true, added: add.length, skipped };
  }

  broadcastAdd(coll, add) {
    this.snap.delete(coll);
    const out = '{"t":"bulk","coll":' + JSON.stringify(coll) + ',"add":' + JSON.stringify(add) + "}";
    const now = Math.floor(Date.now() / 1000);
    for (const [ws, att] of this.loadMeta()) {
      if (!att.colls.includes(coll) || att.exp <= now) continue;
      const role = this.resolve(att.email, att.iat).role;
      if (role === "none" || !canRead(role, coll)) continue;
      this.send(ws, out);
    }
  }

  broadcastPatch(coll, patch) {
    this.snap.delete(coll);
    const out = '{"t":"bulk","coll":' + JSON.stringify(coll) + ',"patch":' + JSON.stringify(patch) + "}";
    const now = Math.floor(Date.now() / 1000);
    for (const [ws, att] of this.loadMeta()) {
      if (!att.colls.includes(coll) || att.exp <= now) continue;
      const role = this.resolve(att.email, att.iat).role;
      if (role === "none" || !canRead(role, coll)) continue;
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
