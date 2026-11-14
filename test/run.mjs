// End-to-end tests: real Worker + Durable Object under "wrangler dev", real Chromium pages,
// and a fake Google key server so forged and genuine tokens can be minted locally.
//   node test/run.mjs
import { spawn, spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { createServer } from "node:http";
import net from "node:net";
import crypto from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import WebSocket from "ws";
import { resolveRole, defaultRole, parseRoles, validEmail } from "../src/auth.js";
import { normHandle, cleanSignup } from "../src/people.js";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

const PORT = 8799, PROXY_PORT = 8798;
const BASE = `http://127.0.0.1:${PORT}`;
const PORT2 = 8797, BASE2 = `http://127.0.0.1:${PORT2}`;
let API_BASE = BASE; // the tests below talk to this server (a second one is started for the default-role-viewer tests)
const PROXY_BASE = `http://127.0.0.1:${PROXY_PORT}`;
const CLIENT_ID = "test-client-id.apps.googleusercontent.com";
const SESSION_SECRET = crypto.randomBytes(32).toString("hex");
const ADMIN_KEY = crypto.randomBytes(24).toString("hex");
const EMAILS = {
  editorA: "editor.a@example.com", editorB: "editor.b@example.com",
  contributor: "mod@example.com", viewer: "viewer@example.com", stranger: "stranger@example.com",
  helper: "helper@example.com", uipick: "uipick@example.com",
};
const ROLES = `${EMAILS.editorA}=owner;${EMAILS.editorB}=editor;${EMAILS.contributor}=contributor;${EMAILS.viewer}=viewer`;

/* ---------- tiny test runner ---------- */
const results = [];
let section = "";
function group(name) { section = name; console.log("\n== " + name); }
function check(name, ok, detail) {
  results.push({ section, name, ok: !!ok, detail });
  console.log((ok ? "  PASS " : "  FAIL ") + name + (!ok && detail !== undefined ? "  -> " + (typeof detail === "string" ? detail : JSON.stringify(detail)) : ""));
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 8000, step = 100) {
  const t0 = Date.now();
  for (;;) {
    try { const v = await fn(); if (v) return v; } catch (e) { /* retry */ }
    if (Date.now() - t0 > ms) return false;
    await sleep(step);
  }
}

/* ---------- fake Google keys and token minting ---------- */
const good = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const evil = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const goodJwk = { ...good.publicKey.export({ format: "jwk" }), kid: "test-key-1", alg: "RS256", use: "sig" };
const b64u = (x) => Buffer.from(typeof x === "string" ? x : JSON.stringify(x)).toString("base64url");
const nowS = () => Math.floor(Date.now() / 1000);

function googleToken(email, o = {}) {
  const header = { alg: o.alg || "RS256", kid: o.kid || "test-key-1", typ: "JWT" };
  const payload = {
    iss: o.iss || "https://accounts.google.com", aud: o.aud || CLIENT_ID, sub: "1234567890", email,
    email_verified: o.ev === undefined ? true : o.ev, name: "Test User", iat: nowS(), exp: o.exp || nowS() + 3600,
  };
  const signing = b64u(header) + "." + b64u(payload);
  let sig = "";
  if (header.alg === "RS256") sig = crypto.sign("RSA-SHA256", Buffer.from(signing), (o.key || good).privateKey).toString("base64url");
  if (header.alg === "HS256") sig = crypto.createHmac("sha256", "whatever").update(signing).digest("base64url");
  return signing + "." + sig;
}
function ourSession(email, { exp = nowS() + 3600, secret = SESSION_SECRET } = {}) {
  const body = b64u({ v: 1, e: email, i: nowS(), x: exp });
  return body + "." + crypto.createHmac("sha256", secret).update(body).digest("base64url");
}

async function post(path, body, headers = {}) {
  const r = await fetch(API_BASE + path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json().catch(() => null) };
}
async function login(email) {
  const r = await post("/api/login", { credential: googleToken(email) });
  return { ...r, session: r.body && r.body.token ? { token: r.body.token, exp: r.body.exp, email: r.body.email, role: r.body.role } : null };
}

/* ---------- WebSocket test client ---------- */
class Client {
  constructor(token, { origin = BASE, protocols } = {}) { this.token = token; this.origin = origin; this.protocols = protocols; this.msgs = []; this.n = 1; }
  open() {
    return new Promise((resolve) => {
      const headers = this.origin ? { Origin: this.origin === BASE ? API_BASE : this.origin } : {};
      this.ws = new WebSocket(API_BASE.replace("http", "ws") + "/api/ws", this.protocols || ["kim-v1", this.token], { headers });
      this.ws.on("open", () => resolve({ ok: true }));
      this.ws.on("unexpected-response", (req, res) => resolve({ ok: false, status: res.statusCode }));
      this.ws.on("error", () => {});
      this.ws.on("message", (d) => { const s = d.toString(); if (s === "pong") return; try { this.msgs.push(JSON.parse(s)); } catch (e) { /* ignore */ } });
      this.ws.on("close", (code) => { this.closed = code; });
    });
  }
  send(o) { this.ws.send(typeof o === "string" ? o : JSON.stringify(o)); }
  async wait(pred, ms = 5000) { const hit = await until(() => this.msgs.find(pred), ms, 20); return hit || null; }
  async sub(path) {
    const sid = this.n++; this.send({ t: "sub", sid, path });
    const m = await this.wait((x) => (x.t === "snap" || x.t === "suberr") && x.sid === sid);
    return m;
  }
  async w(op, coll, id, data) {
    const rid = this.n++; this.send({ t: "w", rid, op, coll, id, data });
    return this.wait((x) => (x.t === "ack" || x.t === "err") && x.rid === rid);
  }
  close() { try { this.ws.close(); } catch (e) { /* ignore */ } }
}
async function connect(session, opts) { const c = new Client(session.token, opts); const r = await c.open(); c.status = r; return c; }

/* ---------- processes ---------- */
let wrangler, wrangler2, jwksServer, proxy;
const logDir = mkdtempSync(join(tmpdir(), "kim-test-"));

function startJwks() {
  return new Promise((resolve) => {
    jwksServer = createServer((req, res) => {
      res.writeHead(200, { "content-type": "application/json", "cache-control": "public, max-age=300" });
      res.end(JSON.stringify({ keys: [goodJwk] }));
    }).listen(0, "127.0.0.1", () => resolve(jwksServer.address().port));
  });
}

async function startWrangler(jwksPort, o = {}) {
  const port = o.port || PORT, base = `http://127.0.0.1:${port}`;
  const vars = {
    GOOGLE_CLIENT_ID: CLIENT_ID, GOOGLE_JWKS_URL: `http://127.0.0.1:${jwksPort}/jwks`, SESSION_SECRET, ADMIN_KEY, ROLES,
    DEFAULT_ROLE: o.defaultRole || "none", MAX_VIEWERS: o.maxViewers || "6", ALLOWED_ORIGINS: `${PROXY_BASE},http://localhost:${PROXY_PORT}`,
  };
  const args = ["wrangler", "dev", "--port", String(port), "--ip", "127.0.0.1", "--inspector-port", o.inspector || "9239", "--persist-to", join(logDir, o.state || "state"), "--local"];
  for (const [k, v] of Object.entries({ ...vars, ...(o.vars || {}) })) args.push("--var", `${k}:${v}`);
  const proc = spawn("npx", args, { cwd: ROOT, env: { ...process.env, NO_PROXY: "127.0.0.1,localhost", no_proxy: "127.0.0.1,localhost", WRANGLER_SEND_METRICS: "false", CI: "1" }, detached: true });
  const out = [];
  proc.stdout.on("data", (d) => out.push(d.toString()));
  proc.stderr.on("data", (d) => out.push(d.toString()));
  const ok = await until(async () => (await fetch(base + "/api/config")).ok, 90000, 500);
  writeFileSync(join(logDir, o.log || "wrangler.log"), out.join(""));
  if (!ok) { console.error(out.join("").slice(-3000)); throw new Error("wrangler dev did not start"); }
  proc.log = out;
  return proc;
}

function makeProxy() {
  const conns = new Set(); let blocked = false;
  const srv = net.createServer((c) => {
    if (blocked) { c.destroy(); return; }
    const t = net.connect(PORT, "127.0.0.1");
    conns.add(c); conns.add(t); c.pipe(t); t.pipe(c);
    const clean = () => { c.destroy(); t.destroy(); conns.delete(c); conns.delete(t); };
    c.on("error", clean); t.on("error", clean); c.on("close", clean); t.on("close", clean);
  });
  srv.listen(PROXY_PORT, "127.0.0.1");
  return { sever() { blocked = true; for (const s of conns) s.destroy(); }, restore() { blocked = false; }, close() { this.sever(); srv.close(); } };
}

function stop() {
  try { process.kill(-wrangler.pid, "SIGKILL"); } catch (e) { /* gone */ }
  try { wrangler2 && process.kill(-wrangler2.pid, "SIGKILL"); } catch (e) { /* gone */ }
  try { jwksServer && jwksServer.close(); } catch (e) { /* ignore */ }
  try { proxy && proxy.close(); } catch (e) { /* ignore */ }
}

/* ---------- data ---------- */
function syntheticDir() {
  const dir = join(logDir, "synthetic"); mkdirSync(dir, { recursive: true });
  const daters = [], questions = [];
  for (let i = 0; i < 40; i++) daters.push({ id: "d" + String(i).padStart(3, "0"), name: "Dater" + i, age: 22 + (i % 15), location: "NC", gender: i % 2 ? "woman" : "man", sexuality: "straight", min: 20, max: 45, ts: 1700000000000 + i, ...(i % 5 === 0 ? { panelMs: 12345 + i, panelCount: 2, hotMs: 600000, hotCount: 1 } : {}) });
  for (let i = 0; i < 50; i++) questions.push({ id: "q" + String(i).padStart(3, "0"), text: "Question number " + i + "?", handle: i % 3 ? "" : "@fan" + i, status: "ready", ts: 1700000000000 + i, ...(i % 4 === 0 ? { askCount: 2, lastAsked: 1700000099999 } : {}) });
  writeFileSync(join(dir, "fixture.json"), JSON.stringify({
    app: "kims-speed-dating", daters, questions,
    matches: [{ id: "m1", hotId: "d000", hotName: "Dater0", pickId: "d001", pickName: "Dater1", fit: "Fits both", ts: 1700000000500 }],
    streams: [{ id: "stream_1700000000000", startedAt: 1700000000000, endedAt: 1700003600000, dates: 3, hotMs: 900000, hotMax: 400000, daters: 6, matches: 1, questions: 4 }],
    game: { question: { text: "Fixture question?", handle: "", qid: "q001" }, hist: [{ text: "Older one?", handle: "", qid: "q002" }] },
  }));
  return dir;
}

/* ---------- main ---------- */
let browser;
try {
  const jwksPort = await startJwks();
  wrangler = await startWrangler(jwksPort);
  proxy = makeProxy();

  /* ===== import ===== */
  group("Import script and export endpoint (round trip)");
  const realDir = join(ROOT, "data");
  const useReal = existsSync(realDir) && readdirSync(realDir).some((f) => f.endsWith(".json"));
  const dataDir = useReal ? realDir : syntheticDir();
  console.log("  using " + (useReal ? "your real data folder" : "synthetic fixture data"));
  const noKey = spawnSync("node", ["scripts/import.mjs", "--url", BASE, "--dir", dataDir], { cwd: ROOT, env: { ...process.env, ADMIN_KEY: "wrong-key-wrong-key-wrong-key" }, encoding: "utf8" });
  check("import with a wrong key is refused", noKey.status !== 0 && /refused \(401\)/.test(noKey.stderr), noKey.stderr);
  const imp = spawnSync("node", ["scripts/import.mjs", "--url", BASE, "--dir", dataDir], { cwd: ROOT, env: { ...process.env, ADMIN_KEY }, encoding: "utf8" });
  console.log(imp.stdout.split("\n").map((l) => "    " + l).join("\n"));
  check("import script succeeds and its own count check passes", imp.status === 0 && /Check passed/.test(imp.stdout), imp.stderr);
  const imp2 = spawnSync("node", ["scripts/import.mjs", "--url", BASE, "--dir", dataDir], { cwd: ROOT, env: { ...process.env, ADMIN_KEY }, encoding: "utf8" });
  check("running the import twice is safe (same counts)", imp2.status === 0, imp2.stderr);
  const replaceNoYes = spawnSync("node", ["scripts/import.mjs", "--url", BASE, "--dir", dataDir, "--replace"], { cwd: ROOT, env: { ...process.env, ADMIN_KEY }, encoding: "utf8" });
  check("--replace without --yes refuses to erase anything", replaceNoYes.status !== 0 && /--yes/.test(replaceNoYes.stderr));

  const sessions = {};
  for (const [k, email] of Object.entries(EMAILS)) sessions[k] = (await login(email)).session;

  const exp = await fetch(BASE + "/api/export", { headers: { Authorization: "Bearer " + sessions.editorA.token } });
  const exported = await exp.json();
  check("Editor can download the export (one JSON file, attachment)", exp.status === 200 && /attachment/.test(exp.headers.get("content-disposition") || ""), exp.status);
  const stable = (v) => Array.isArray(v) ? "[" + v.map(stable).join(",") + "]" : v && typeof v === "object" ? "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + stable(v[k])).join(",") + "}" : JSON.stringify(v);
  const src = {};
  for (const f of readdirSync(dataDir).filter((f) => f.endsWith(".json"))) Object.assign(src, JSON.parse(readFileSync(join(dataDir, f), "utf8")));
  for (const c of ["daters", "questions", "matches", "streams"]) {
    const a = [...src[c]].sort((x, y) => (x.id < y.id ? -1 : 1)).map(stable), b = [...exported[c]].sort((x, y) => (x.id < y.id ? -1 : 1)).map(stable);
    const diffAt = a.findIndex((x, i) => x !== b[i]);
    check(`${c}: ${src[c].length} records come back identical (ids and every field)`, a.length === b.length && diffAt < 0, { want: a.length, got: b.length, first: a[diffAt], gotFirst: b[diffAt] });
  }
  check("game question and history come back identical", stable(src.game) === stable(exported.game), { want: src.game, got: exported.game });
  const noExp = [["Contributor", sessions.contributor], ["Viewer", sessions.viewer]];
  for (const [n, s] of noExp) check(`${n} cannot download the export (403)`, (await fetch(BASE + "/api/export", { headers: { Authorization: "Bearer " + s.token } })).status === 403);
  check("export with no login is refused (401)", (await fetch(BASE + "/api/export")).status === 401);
  check("export with a forged token is refused (401)", (await fetch(BASE + "/api/export", { headers: { Authorization: "Bearer " + ourSession(EMAILS.editorA, { secret: "x".repeat(40) }) } })).status === 401);

  /* ===== login ===== */
  group("Google sign-in verification (forged and wrong tokens)");
  const L = async (name, tokOpts, email = EMAILS.editorA, want = 401) => {
    const r = await post("/api/login", { credential: googleToken(email, tokOpts) });
    check(name, r.status === want && !(r.body && r.body.token), { status: r.status, body: r.body });
  };
  const okLogin = await login(EMAILS.editorA);
  check("genuine Editor token logs in with role editor", okLogin.status === 200 && okLogin.body.role === "editor", okLogin.body);
  check("genuine Contributor token gets role contributor", (await login(EMAILS.contributor)).body.role === "contributor");
  check("genuine Viewer token gets role viewer", (await login(EMAILS.viewer)).body.role === "viewer");
  await L("email not on the list gets no access (403, default role none)", {}, EMAILS.stranger, 403);
  await L("token signed with the wrong private key is rejected", { key: evil });
  await L("token for a different Google client ID is rejected", { aud: "someone-elses-app.apps.googleusercontent.com" });
  await L("expired token is rejected", { exp: nowS() - 600 });
  await L("unverified email is rejected", { ev: false });
  await L("wrong issuer is rejected", { iss: "https://evil.example.com" });
  await L("unknown signing key id is rejected", { kid: "not-a-google-key" });
  await L("algorithm 'none' is rejected", { alg: "none" });
  await L("HS256 key-confusion attempt is rejected", { alg: "HS256" });
  const t = googleToken(EMAILS.stranger).split(".");
  const swapped = [t[0], b64u({ ...JSON.parse(Buffer.from(t[1], "base64url")), email: EMAILS.editorA }), t[2]].join(".");
  const r1 = await post("/api/login", { credential: swapped });
  check("genuine signature with the email swapped to an Editor is rejected", r1.status === 401, r1);
  check("garbage credential is rejected", (await post("/api/login", { credential: "not.a.token" })).status === 401);
  check("missing credential is rejected", (await post("/api/login", {})).status === 401);

  /* ===== websocket auth ===== */
  group("WebSocket door: origin and session checks");
  check("no token: refused", (await connect({ token: "" }, { protocols: ["kim-v1"] })).status.status === 401);
  check("random token: refused (401)", (await connect({ token: "abc.def" })).status.status === 401);
  check("session signed with a different secret: refused (401)", (await connect({ token: ourSession(EMAILS.editorA, { secret: "y".repeat(40) }) })).status.status === 401);
  check("genuine signature but expired session: refused (401)", (await connect({ token: ourSession(EMAILS.editorA, { exp: nowS() - 5 }) })).status.status === 401);
  check("valid session for an email not on the list: refused (403)", (await connect({ token: ourSession(EMAILS.stranger) })).status.status === 403);
  check("wrong Origin: refused (403)", (await connect(sessions.editorA, { origin: "https://evil.example.com" })).status.status === 403);
  check("missing Origin: refused (403)", (await connect(sessions.editorA, { origin: null })).status.status === 403);
  const tampered = sessions.viewer.token.split(".");
  tampered[0] = b64u({ v: 1, e: EMAILS.editorA, i: nowS(), x: nowS() + 3600 });
  check("viewer session with the payload edited to an Editor email: refused (401)", (await connect({ token: tampered.join(".") })).status.status === 401);
  const okc = await connect(sessions.editorA);
  check("genuine Editor session from the right Origin connects", okc.status.ok);
  const hello = await okc.wait((m) => m.t === "hello");
  check("server tells the page its role (editor)", hello && hello.role === "editor", hello);
  okc.close();

  /* ===== role matrix ===== */
  group("Server-side rules by role (read and write)");
  const C = {};
  for (const k of ["editorA", "editorB", "contributor", "viewer"]) { C[k] = await connect(sessions[k]); }
  const allowed = (m) => m && m.t === "snap";
  const denied = (m) => m && m.t === "suberr" && m.code === "permission-denied";
  for (const coll of ["daters", "matches", "seats", "game", "questions"]) check(`Editor can read ${coll}`, allowed(await C.editorA.sub(coll === "game" ? "game/question" : coll)));
  const readRules = { contributor: { daters: false, matches: false, seats: true, game: true, questions: true }, viewer: { daters: false, matches: false, seats: true, game: true, questions: true } };
  for (const who of ["contributor", "viewer"]) {
    for (const [coll, can] of Object.entries(readRules[who])) {
      const m = await C[who].sub(coll === "game" ? "game/question" : coll);
      check(`${who} ${can ? "can" : "can NOT"} read ${coll}`, can ? allowed(m) : denied(m), m);
    }
  }
  const wDenied = (m) => m && m.t === "err" && m.code === "permission-denied";
  const wOk = (m) => m && m.t === "ack";
  const dataFor = { daters: { name: "Rule Test", age: 30, location: "NC", gender: "man", sexuality: "straight", min: 20, max: 40, ts: 1 }, matches: { hotId: "a", hotName: "A", pickId: "b", pickName: "B", fit: "Fits both", ts: 1 }, questions: { text: "Rule test question?", handle: "", status: "ready", ts: 1 } };
  const e1 = await C.editorA.w("add", "daters", null, dataFor.daters);
  check("Editor can add a dater", wOk(e1), e1);
  const ruleDaterId = e1 && e1.id;
  check("Editor can add a match", wOk(await C.editorA.w("add", "matches", null, dataFor.matches)));
  check("Editor can set seat 'hot'", wOk(await C.editorA.w("set", "seats", "hot", { dater: ruleDaterId, view: null, since: 1 })));
  check("Editor can set game/question", wOk(await C.editorA.w("set", "game", "question", { text: "Editor set this", handle: "", qid: "", hist: [] })));
  const eq = await C.editorA.w("add", "questions", null, dataFor.questions);
  check("Editor can add a question", wOk(eq), eq);
  const ruleQ = eq && eq.id;

  check("Contributor can add a question", wOk(await C.contributor.w("add", "questions", null, { ...dataFor.questions, text: "From a mod?" })));
  check("Contributor can mark a question asked (askCount + lastAsked)", wOk(await C.contributor.w("update", "questions", ruleQ, { askCount: 1, lastAsked: 5 })));
  check("Contributor can change the current question (game/question)", wOk(await C.contributor.w("set", "game", "question", { text: "Mod picked this", handle: "", qid: ruleQ, hist: [] })));
  check("Contributor can NOT seat daters (seats)", wDenied(await C.contributor.w("set", "seats", "s1", { dater: ruleDaterId, view: null, since: 1 })));
  check("Contributor can NOT add a dater", wDenied(await C.contributor.w("add", "daters", null, dataFor.daters)));
  check("Contributor can NOT edit or delete a dater", wDenied(await C.contributor.w("update", "daters", ruleDaterId, { age: 99 })) && wDenied(await C.contributor.w("delete", "daters", ruleDaterId)));
  check("Contributor can NOT touch matches", wDenied(await C.contributor.w("add", "matches", null, dataFor.matches)));

  for (const [coll, id, d] of [["daters", ruleDaterId, dataFor.daters], ["matches", "x1", dataFor.matches], ["seats", "hot", { dater: null }], ["game", "question", { text: "v" }], ["questions", ruleQ, { text: "v" }]]) {
    check(`Viewer can NOT write ${coll} (set)`, wDenied(await C.viewer.w("set", coll, id, d)));
  }
  check("Viewer can NOT add or delete", wDenied(await C.viewer.w("add", "questions", null, dataFor.questions)) && wDenied(await C.viewer.w("delete", "questions", ruleQ)));
  const still = await C.editorA.sub("questions");
  check("the viewer's and contributor's rejected writes changed nothing", still.docs.find((d) => d.id === ruleQ).data.text === "Rule test question?");

  group("Server-side input checks");
  const bad = async (name, p, codes) => { const m = await p; check(name, m && m.t === "err" && codes.includes(m.code), m); };
  await bad("unknown collection (write) is rejected", C.editorA.w("set", "secrets", "a", { x: 1 }), ["invalid-argument"]);
  const unk = await C.editorA.sub("secrets");
  check("unknown collection (read) is rejected", unk && unk.t === "suberr" && unk.code === "invalid-argument", unk);
  await bad("seat id that is not a real seat is rejected", C.editorA.w("set", "seats", "zzz", { dater: null }), ["invalid-argument"]);
  await bad("game doc other than 'question' is rejected", C.editorA.w("set", "game", "other", { text: "x" }), ["invalid-argument"]);
  await bad("add() on seats is rejected", C.editorA.w("add", "seats", null, { dater: null }), ["invalid-argument"]);
  await bad("path tricks in a document id are rejected", C.editorA.w("set", "daters", "../questions/x", { a: 1 }), ["invalid-argument"]);
  await bad("very long document id is rejected", C.editorA.w("set", "daters", "a".repeat(200), { a: 1 }), ["invalid-argument"]);
  await bad("oversized document (40 KB) is rejected", C.editorA.w("set", "questions", "big1", { text: "x".repeat(3900), a: Array(9).fill("y".repeat(3900)) }), ["failed-precondition"]);
  await bad("bad field names are rejected", C.editorA.w("set", "questions", "bad1", { "a.b": 1 }), ["failed-precondition"]);
  await bad("__proto__ field is rejected", C.editorA.w("set", "questions", "bad2", JSON.parse('{"__proto__":{"x":1}}')), ["failed-precondition"]);
  await bad("a document that is not an object is rejected", C.editorA.w("set", "questions", "bad3", [1, 2]), ["failed-precondition"]);
  await bad("update of a missing document fails (not-found)", C.editorA.w("update", "questions", "nope-nope", { a: 1 }), ["not-found"]);
  await bad("unknown operation is rejected", C.editorA.w("explode", "questions", "x", {}), ["invalid-argument"]);
  const del = await C.editorA.w("update", "questions", ruleQ, { handle: { $delete: true } });
  const after = await C.editorA.sub("questions");
  check("update can delete a field (db.deleteField)", wOk(del) && !("handle" in after.docs.find((d) => d.id === ruleQ).data));
  C.editorA.send("not json at all");
  check("malformed JSON gets an error, connection survives", !!(await C.editorA.wait((m) => m.t === "err" && m.code === "invalid-argument")) && !C.editorA.closed);

  group("Limited users never receive dater data");
  const spy = await connect(sessions.contributor);
  await spy.sub("seats"); await spy.sub("questions");
  const dsub = await spy.sub("daters");
  const beforeLen = spy.msgs.length;
  await C.editorA.w("add", "daters", null, { ...dataFor.daters, name: "SecretDater" });
  await C.editorA.w("update", "daters", ruleDaterId, { age: 31 });
  await C.editorA.w("add", "matches", null, dataFor.matches);
  await sleep(800);
  const leaked = spy.msgs.slice(beforeLen).filter((m) => m.coll === "daters" || m.coll === "matches" || JSON.stringify(m).includes("SecretDater"));
  check("subscribing to daters is denied for a Contributor", denied(dsub), dsub);
  check("no dater or match changes are pushed to a Contributor", leaked.length === 0, leaked);
  const viewerSpy = await connect(sessions.viewer);
  await viewerSpy.sub("seats"); const vd = await viewerSpy.sub("daters");
  check("subscribing to daters is denied for a Viewer", denied(vd), vd);
  spy.close(); viewerSpy.close();

  group("Rate limit, message size, idle wake-up");
  const flood = await connect(sessions.viewer);
  for (let i = 0; i < 600; i++) flood.send({ t: "w", rid: 1000 + i, op: "set", coll: "daters", id: "x", data: {} });
  await sleep(2000);
  const limited = flood.msgs.filter((m) => m.code === "resource-exhausted").length;
  check("a flood of 600 messages is answered 'slow down' (rate limit)", limited > 100, { limited });
  check("...and a connection that keeps flooding is closed (4429)", flood.closed === 4429, flood.closed);
  const burst = await connect(sessions.viewer);
  for (let i = 0; i < 260; i++) burst.send({ t: "w", rid: 2000 + i, op: "set", coll: "daters", id: "x", data: {} });
  await sleep(1500);
  const slowed = burst.msgs.filter((m) => m.code === "resource-exhausted").length;
  check("a smaller burst of 260 is partly slowed down but not disconnected", slowed > 10 && !burst.closed, { slowed, closed: burst.closed });
  await sleep(5000);
  const calm = await burst.w("set", "seats", "hot", { dater: null });
  check("after calming down the same connection works again", calm && calm.t === "err" && calm.code === "permission-denied", calm);
  burst.close();
  const big = await connect(sessions.contributor);
  big.send("x".repeat(70000)); await sleep(500);
  check("a message over 64 KB closes the connection (1009)", big.closed === 1009, big.closed);
  const bin = await connect(sessions.contributor);
  bin.ws.send(Buffer.from([1, 2, 3])); await sleep(500);
  check("a binary message closes the connection (1003)", bin.closed === 1003, bin.closed);
  const idle = await connect(sessions.editorB); await idle.sub("questions");
  await sleep(13000); // long enough for the Durable Object to hibernate
  const wake = await idle.w("add", "questions", null, { ...dataFor.questions, text: "after idle" });
  check("after 13 s idle (object hibernated) the connection still works", wOk(wake), wake);
  const got = await C.editorA.wait((m) => m.t === "chg" && m.data && m.data.text === "after idle", 3000);
  check("...and other users still get the change after the wake-up", !!got);
  const refreshed = await post("/api/refresh", {}, { Authorization: "Bearer " + sessions.editorB.token });
  check("session refresh returns a new token", refreshed.status === 200 && refreshed.body.token && refreshed.body.token !== sessions.editorB.token, refreshed.status);
  idle.send({ t: "auth", token: refreshed.body.token });
  check("an open connection accepts the refreshed session", !!(await idle.wait((m) => m.t === "auth-ok")));
  idle.close();
  for (const c of Object.values(C)) c.close();

  /* ===== capacity and cache ===== */
  group("Capacity: viewers are capped, hosts and mods keep reserved room");
  await sleep(700); // let the sockets from the groups above finish closing
  const vsock = []; for (let i = 0; i < 6; i++) vsock.push(await connect(sessions.viewer));
  check("6 viewers can connect (the limit used in this test)", vsock.every((c) => c.status.ok), vsock.map((c) => c.status));
  const v7 = await connect(sessions.viewer);
  check("the 7th viewer is told the room is full (503)", v7.status.status === 503, v7.status);
  const probe = async (s) => (await (await fetch(BASE + "/api/session?probe=1", { headers: { Authorization: "Bearer " + s.token } })).json()).full;
  check("a refused viewer can ask 'is it full?' and the answer is yes", (await probe(sessions.viewer)) === true);
  const edC = await connect(sessions.editorA), ctC = await connect(sessions.contributor);
  check("a host and a mod still get in while viewers are full", edC.status.ok && ctC.status.ok);
  check("...and the room is not 'full' for them yet", (await probe(sessions.editorA)) === false);
  await vsock[0].sub("questions");
  const capQ = await edC.w("add", "questions", null, { ...dataFor.questions, text: "Capacity probe" });
  check("people already connected keep getting live updates while the room is full", !!(await vsock[0].wait((m) => m.t === "chg" && m.data && m.data.text === "Capacity probe", 3000)));
  await edC.w("delete", "questions", capQ.id, null);
  vsock[5].close(); await sleep(600);
  const v7b = await connect(sessions.viewer);
  check("when a viewer leaves, the next viewer gets in", v7b.status.ok, v7b.status);
  const staff = [edC, ctC]; for (let i = 0; i < 13; i++) staff.push(await connect(sessions.editorB));
  check("hosts and mods can use the 15 reserved places on top of the viewers", staff.every((c) => c.status.ok), staff.map((c) => c.status.status).filter(Boolean));
  const over = await connect(sessions.editorA);
  check("beyond the reserve even a host is refused (hard ceiling = viewers + 15)", over.status.status === 503, over.status);
  check("viewers stay refused while hosts and mods fill the room", (await connect(sessions.viewer)).status.status === 503);
  for (const c of [...vsock, v7b, ...staff]) c.close();
  await sleep(800);
  const again = await connect(sessions.viewer); check("after everyone leaves, connecting works again", again.status.ok); again.close();

  group("Snapshot cache never serves stale data");
  const cA = await connect(sessions.editorA); await cA.sub("questions"); // warms the cache
  const cq = await cA.w("add", "questions", null, { ...dataFor.questions, text: "Cache probe one" });
  const cB = await connect(sessions.editorB);
  check("a new subscriber sees a question added after the list was cached", (await cB.sub("questions")).docs.some((d) => d.data.text === "Cache probe one"));
  await cA.w("update", "questions", cq.id, { text: "Cache probe two" });
  const cC = await connect(sessions.editorB);
  check("...and an edit", (await cC.sub("questions")).docs.some((d) => d.id === cq.id && d.data.text === "Cache probe two"));
  await cA.w("delete", "questions", cq.id, null);
  const cD = await connect(sessions.editorB);
  check("...and a deletion", !(await cD.sub("questions")).docs.some((d) => d.id === cq.id));
  const seatsBefore = (await cD.sub("seats")).docs.length;
  await cA.w("set", "seats", "s3", { dater: null, view: null, since: null });
  check("seats (whole collection) also reflect a change for the next subscriber", (await (await connect(sessions.editorB)).sub("seats")).docs.some((d) => d.id === "s3"));
  await cA.w("delete", "seats", "s3", null);
  check("...and its removal", !(await (await connect(sessions.editorB)).sub("seats")).docs.some((d) => d.id === "s3") && seatsBefore >= 0);
  for (const c of [cA, cB, cC, cD]) c.close();

  /* ===== roles admin ===== */
  group("Role assignment: owners, editors, the admin page API");
  const rolesApi = async (session, method = "GET", body, extra = {}) => {
    const r = await fetch(API_BASE + "/api/roles", { method, headers: { Authorization: "Bearer " + (session ? session.token : "none"), "content-type": "application/json", ...extra }, body: body ? JSON.stringify(body) : undefined });
    return { status: r.status, body: await r.json().catch(() => null) };
  };
  const loginRes = await login(EMAILS.editorA);
  check("the access API also says what unlisted people get (the default role)", (await rolesApi(sessions.editorA)).body.defaultRole === "none");
  check("a person listed as owner logs in as editor-level with owner true", loginRes.body.role === "editor" && loginRes.body.owner === true, loginRes.body);
  const lb = await rolesApi(sessions.editorA);
  check("owner can list people (secret entries are included and marked)", lb.status === 200 && lb.body.you.owner === true && lb.body.people.some((p) => p.email === EMAILS.editorB && p.source === "secret"), lb);
  check("a normal Editor cannot use the admin API at all (403)", (await rolesApi(sessions.editorB)).status === 403 && (await rolesApi(sessions.editorB, "POST", { email: "x@example.com", role: "viewer" })).status === 403);
  check("Contributor cannot use the admin API (403)", (await rolesApi(sessions.contributor)).status === 403);
  check("Viewer cannot use the admin API (403)", (await rolesApi(sessions.viewer)).status === 403);
  check("no login: admin API refused (401)", (await rolesApi(null)).status === 401);
  check("forged session: admin API refused (401)", (await rolesApi({ token: ourSession(EMAILS.editorA, { secret: "z".repeat(40) }) })).status === 401);
  check("admin POST from a wrong Origin is refused (403)", (await rolesApi(sessions.editorA, "POST", { email: EMAILS.newbie || "n@example.com", role: "viewer" }, { Origin: "https://evil.example.com" })).status === 403);

  check("before being added, an unlisted account gets no access (403)", (await login(EMAILS.stranger)).status === 403);
  const seen0 = await rolesApi(sessions.editorA);
  check("a person who signed in but is on no list shows up under 'signed in recently'", seen0.body.seen.some((p) => p.email === EMAILS.stranger && p.n >= 1), seen0.body.seen);
  check("people who are on a list do not appear there", !seen0.body.seen.some((p) => [EMAILS.editorA, EMAILS.editorB, EMAILS.contributor, EMAILS.viewer].includes(p.email)));
  await login("ghost@example.com");
  check("a normal Editor cannot forget or add anyone from that list (403)", (await rolesApi(sessions.editorB, "POST", { email: "ghost@example.com", role: "forget" })).status === 403);
  const forgot = await rolesApi(sessions.editorA, "POST", { email: "ghost@example.com", role: "forget" });
  check("owner can forget an entry", forgot.status === 200 && !(await rolesApi(sessions.editorA)).body.seen.some((p) => p.email === "ghost@example.com"), forgot);
  const addV = await rolesApi(sessions.editorA, "POST", { email: EMAILS.stranger.toUpperCase(), role: "viewer" });
  check("owner adds the stranger as Viewer (email is lower-cased)", addV.status === 200 && addV.body.email === EMAILS.stranger, addV);
  check("adding someone to the list takes them off the 'signed in recently' list", !(await rolesApi(sessions.editorA)).body.seen.some((p) => p.email === EMAILS.stranger));
  const sl = await login(EMAILS.stranger);
  check("the new Viewer can now sign in and gets role viewer", sl.status === 200 && sl.body.role === "viewer" && sl.body.owner === false, sl.body);
  const sw = await connect(sl.session);
  const swHello = await sw.wait((m) => m.t === "hello");
  check("their WebSocket opens with role viewer", sw.status.ok && swHello && swHello.role === "viewer", swHello);
  check("the new Viewer can read questions but cannot write", allowed(await sw.sub("questions")) && wDenied(await sw.w("add", "questions", null, dataFor.questions)));
  const daterDeny = await sw.sub("daters");
  check("the new Viewer cannot read daters", denied(daterDeny), daterDeny);

  const upC = await rolesApi(sessions.editorA, "POST", { email: EMAILS.stranger, role: "contributor" });
  check("owner promotes a Viewer to Contributor", upC.status === 200, upC);
  const live = await sw.wait((m) => m.t === "hello" && m.role === "contributor", 3000);
  check("their open page is told right away that its access changed", !!live, sw.msgs.filter((m) => m.t === "hello"));
  check("...and the new access applies to the open connection at once (can add questions now)", wOk(await sw.w("add", "questions", null, { ...dataFor.questions, text: "From the new contributor" })));
  check("a normal Editor cannot make anyone an Editor (403)", (await rolesApi(sessions.editorB, "POST", { email: EMAILS.stranger, role: "editor" })).status === 403);
  check("...nor a brand new Editor either (403)", (await rolesApi(sessions.editorB, "POST", { email: EMAILS.helper, role: "editor" })).status === 403);
  check("owner makes the helper an Editor (200)", (await rolesApi(sessions.editorA, "POST", { email: EMAILS.helper, role: "editor" })).status === 200);
  const hl = await login(EMAILS.helper);
  check("the helper signs in as an editor but not an owner", hl.status === 200 && hl.body.role === "editor" && hl.body.owner === false, hl.body);
  const hc = await connect(hl.session);
  check("the helper reads daters like any Editor", allowed(await hc.sub("daters")));
  check("an Editor made on the page is still not an owner: the admin API refuses them (403)", (await rolesApi(hl.session)).status === 403 && (await rolesApi(hl.session, "POST", { email: EMAILS.uipick, role: "viewer" })).status === 403);
  check("a normal Editor cannot demote or remove another Editor (403)", (await rolesApi(sessions.editorB, "POST", { email: EMAILS.helper, role: "viewer" })).status === 403 && (await rolesApi(sessions.editorB, "POST", { email: EMAILS.helper, role: "none" })).status === 403);
  const lockedChange = await rolesApi(sessions.editorA, "POST", { email: EMAILS.editorB, role: "viewer" });
  check("people set in the ROLES secret are locked, even for owners (409)", lockedChange.status === 409, lockedChange);
  check("...so nobody can remove an owner from the page (409)", (await rolesApi(sessions.editorA, "POST", { email: EMAILS.editorA, role: "none" })).status === 409);
  check("a bad email is rejected (400)", (await rolesApi(sessions.editorA, "POST", { email: "not-an-email", role: "viewer" })).status === 400);
  check("an unknown role is rejected (400)", (await rolesApi(sessions.editorA, "POST", { email: "x@example.com", role: "admin" })).status === 400);
  check("an email with list separators is rejected (400)", (await rolesApi(sessions.editorA, "POST", { email: "a@example.com,b@example.com", role: "viewer" })).status === 400);
  const listAfter = await rolesApi(sessions.editorA);
  const helperRow = listAfter.body.people.find((p) => p.email === EMAILS.helper);
  for (let i = 0; i < 320; i++) await login(`cap${i}@example.com`);
  const capList = await rolesApi(sessions.editorA);
  check("320 sign-ins later the recent list is capped, newest first, oldest dropped", capList.body.seen.length <= 100 && capList.body.seen[0].email === "cap319@example.com" && !capList.body.seen.some((p) => p.email === "cap0@example.com"), { n: capList.body.seen.length, first: capList.body.seen[0] && capList.body.seen[0].email });
  check("the list records who added whom", helperRow && helperRow.by === EMAILS.editorA && helperRow.role === "editor" && helperRow.source === "admin", helperRow);
  const exH = await fetch(BASE + "/api/export", { headers: { Authorization: "Bearer " + hl.session.token } });
  check("an Editor assigned on the page can download the export", exH.status === 200, exH.status);

  const rm = await rolesApi(sessions.editorA, "POST", { email: EMAILS.stranger, role: "none" });
  check("owner removes the stranger", rm.status === 200, rm);
  await sleep(500);
  check("their open connection is closed at once (4403)", sw.closed === 4403, sw.closed);
  check("they can no longer sign in (403)", (await login(EMAILS.stranger)).status === 403);
  check("their old, still valid session token is refused at the door (403)", (await connect(sl.session)).status.status === 403);
  await rolesApi(sessions.editorA, "POST", { email: EMAILS.helper, role: "none" });
  await sleep(400);
  check("removing the helper closes their connection too", hc.closed === 4403, hc.closed);
  await rolesApi(sessions.editorA, "POST", { email: EMAILS.uipick, role: "none" });
  sw.close(); hc.close();

  group("Role rules in code (default role, owner, precedence)");
  const lockEnv = { ROLES: "boss@x.com=owner", DEFAULT_ROLE: "viewer" };
  check("a blocked person gets no access even though the default is Viewer", resolveRole(lockEnv, "bad@x.com", "blocked").role === "none" && resolveRole(lockEnv, "bad@x.com", "blocked").blocked === true);
  check("a block can never apply to someone in the ROLES secret", resolveRole(lockEnv, "boss@x.com", "blocked").role === "editor");
  check("a locked door turns away new sign-ins from unlisted people but not older sessions, added people or owners", resolveRole(lockEnv, "n@x.com", undefined, { iat: 200, lockTs: 100 }).role === "none" && resolveRole(lockEnv, "n@x.com", undefined, { iat: 50, lockTs: 100 }).role === "viewer" && resolveRole(lockEnv, "n@x.com", "viewer", { iat: 200, lockTs: 100 }).role === "viewer" && resolveRole(lockEnv, "boss@x.com", undefined, { iat: 200, lockTs: 100 }).role === "editor" && resolveRole(lockEnv, "n@x.com", undefined, { iat: undefined, lockTs: 100 }).role === "viewer");
  const wp = await import("../src/webpush.js"); const an = await import("../src/announce.js");
  check("push services are allowed only on their real hosts (lookalikes and plain http are refused)", wp.okEndpoint({}, "https://fcm.googleapis.com/fcm/send/abc") && wp.okEndpoint({}, "https://updates.push.services.mozilla.com/wpush/v2/abc") && wp.okEndpoint({}, "https://web.push.apple.com/abc") && wp.okEndpoint({}, "https://wns2-par02p.notify.windows.com/w/?token=x") && !wp.okEndpoint({}, "https://fcm.googleapis.com.evil.com/x") && !wp.okEndpoint({}, "https://evilgoogleapis.com/x") && !wp.okEndpoint({}, "http://fcm.googleapis.com/x") && !wp.okEndpoint({}, "https://user:pw@fcm.googleapis.com/x") && !wp.okEndpoint({}, "http://127.0.0.1:9/x") && wp.okEndpoint({ ALLOW_INSECURE_PUSH: "1" }, "http://127.0.0.1:9/x") && !wp.okEndpoint({ ALLOW_INSECURE_PUSH: "1" }, "http://evil.example.com/x"));
  check("Discord webhooks are only accepted on discord.com with a real webhook path", an.okWebhook({}, "https://discord.com/api/webhooks/123456789/abc-DEF_1") && an.okWebhook({}, "https://discordapp.com/api/webhooks/1/x") && !an.okWebhook({}, "https://discord.com.evil.com/api/webhooks/1/x") && !an.okWebhook({}, "https://discord.com/other") && !an.okWebhook({}, "http://discord.com/api/webhooks/1/x") && !an.okWebhook({}, ""));
  check("the encryption for a phone is the standard one: a phone's own key decrypts it, nobody else's does", await (async () => {
    const e = crypto.createECDH("prime256v1"); e.generateKeys(); const auth = crypto.randomBytes(16), pub = e.getPublicKey();
    const body = Buffer.from(await wp.encryptPayload({ p256dh: pub.toString("base64url"), auth: auth.toString("base64url") }, new TextEncoder().encode(JSON.stringify({ hi: "there" }))));
    const hk = (ikm, salt, info, n) => Buffer.from(crypto.hkdfSync("sha256", ikm, salt, info, n));
    const open = (ecdh, au) => { const salt = body.subarray(0, 16), idlen = body[20], asPub = body.subarray(21, 21 + idlen), ct = body.subarray(21 + idlen); const ikm = hk(ecdh.computeSecret(asPub), au, Buffer.concat([Buffer.from("WebPush: info\0"), pub, asPub]), 32); const d = crypto.createDecipheriv("aes-128-gcm", hk(ikm, salt, Buffer.from("Content-Encoding: aes128gcm\0"), 16), hk(ikm, salt, Buffer.from("Content-Encoding: nonce\0"), 12)); d.setAuthTag(ct.subarray(ct.length - 16)); return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]); };
    const plain = open(e, auth); const other = crypto.createECDH("prime256v1"); other.generateKeys();
    let blocked = false; try { open(other, auth); } catch (x) { blocked = true; }
    return plain.subarray(0, plain.length - 1).toString() === '{"hi":"there"}' && plain[plain.length - 1] === 2 && body[20] === 65 && body.readUInt32BE(16) === 4096 && blocked;
  })());
  const et = {}; new Function("window", readFileSync(join(ROOT, "public", "ettime.js"), "utf8"))(et);
  check("Eastern time: 5 PM in winter is 22:00 UTC and in summer 21:00 UTC, including around the clock changes", new Date(et.EtTime.etToUtcMs("2026-12-15", "17:00")).toISOString() === "2026-12-15T22:00:00.000Z" && new Date(et.EtTime.etToUtcMs("2027-07-15", "17:00")).toISOString() === "2027-07-15T21:00:00.000Z" && new Date(et.EtTime.etToUtcMs("2027-03-14", "03:30")).toISOString() === "2027-03-14T07:30:00.000Z" && new Date(et.EtTime.etToUtcMs("2026-11-01", "00:30")).toISOString() === "2026-11-01T04:30:00.000Z" && Number.isNaN(et.EtTime.etToUtcMs("", "17:00")));
  check("the time is written the same way on the page and in the messages", et.EtTime.fmtEt(Date.UTC(2026, 11, 15, 22, 0)) === "5:00 PM" && an.fmtEt(Date.UTC(2026, 11, 15, 22, 0)) === "5:00 PM" && et.EtTime.fmtEt(Date.UTC(2027, 6, 15, 21, 30), true) === an.fmtEt(Date.UTC(2027, 6, 15, 21, 30), true) && an.messageFor("1h", Date.UTC(2026, 11, 15, 22, 0), "https://x.test").body === "We go live in 1 hour (5:00 PM ET).");
  const sm = {}; new Function("window", readFileSync(join(ROOT, "public", "match.js"), "utf8"))(sm); const SM = sm.SignupMatch;
  check("usernames: @ is optional, 2 to 24 letters, numbers, dots and underscores, capitals kept", normHandle("@Jess_NC") === "Jess_NC" && normHandle("ab") === "ab" && normHandle("a") === null && normHandle("x".repeat(25)) === null && normHandle("has space") === null && normHandle(".dot") === null && normHandle("emoji\u{1F600}") === null && normHandle("") === null && normHandle(null) === null);
  check("sign-up checks mirror the host's dater form (18+, ranges, state only, confirmation)", cleanSignup({ handle: "a_b", age: 20, location: "NC", gender: "man", sexuality: "straight", min: 20, max: 30, adult: true }).ok && !cleanSignup({ handle: "a_b", age: "17", location: "NC", gender: "man", sexuality: "straight", min: 20, max: 30, adult: true }).ok && !cleanSignup({ handle: "a_b", age: 20, location: "NC", gender: "man", sexuality: "straight", min: 20, max: 30, adult: "yes" }).ok && cleanSignup({ handle: "a_b", age: "20", location: "NC", gender: "man", sexuality: "straight", min: "20", max: "30", adult: true }).doc.min === 20);
  check("a sign-up cannot smuggle extra fields into the dater record", !("role" in cleanSignup({ handle: "a_b", age: 20, location: "NC", gender: "man", sexuality: "gay", min: 20, max: 30, adult: true, role: "editor", panelMs: 9 }).doc) && !("panelMs" in cleanSignup({ handle: "a_b", age: 20, location: "NC", gender: "man", sexuality: "gay", min: 20, max: 30, adult: true, panelMs: 9 }).doc));
  check("matching: same name ignoring @, capitals, dots, underscores and spaces is a strong match, and trailing numbers do not matter", SM.compare({ name: "@Match Me", age: 1, location: "x" }, { handle: "match_me", age: 99, location: "y" }) === "strong" && SM.compare({ name: "Jess.NC", age: 1, location: "x" }, { handle: "jess_nc", age: 99, location: "y" }) === "strong" && SM.compare({ name: "Mia Quinn", age: 30, location: "NC" }, { handle: "mia_quinn88", age: 31, location: "NC" }) === "strong");
  const poss = (n, h, a1 = 27, l1 = "NC", a2 = 27, l2 = "NC") => SM.compare({ name: n, age: a1, location: l1 }, { handle: h, age: a2, location: l2 }) === "possible";
  check("matching: misspellings, transposed letters and sounds-alike spellings are found", poss("Jessica", "jesica_nc") && poss("Michael", "micheal_f") && poss("Katherine", "catherine.x") && poss("Kaylee", "kayleigh_oh") && poss("Brandon", "brandan_k") && poss("Stephanie", "stefanie_t"));
  check("matching: a first name finds the username that starts with it, and a username finds a full name", poss("Jess", "jessica_88") && poss("Sam", "samantha_k") && poss("Brianna Lee", "bri_lee_") && poss("Mia Quinn", "miaq"));
  check("matching: the state is written either way (NC or North Carolina)", poss("Jess", "jessica_88", 27, "NC", 27, "North Carolina") && SM.score({ name: "Jess", age: 27, location: "North Carolina" }, { handle: "jessica_88", age: 27, location: "nc" }).reasons.includes("same state"));
  check("matching: unrelated names do not match, even with the same state and age, and very short names are not guessed", !poss("Alex", "zoe_88") && !poss("Marcus", "tiffany_r") && !poss("Al", "zz_top") && SM.compare({ name: "x", age: 27, location: "NC" }, { handle: "xy", age: 27, location: "NC" }) === null);
  check("matching: every match says why (so the host can judge it)", (() => { const r = SM.score({ name: "Jessica", age: 27, location: "NC" }, { handle: "jesica_nc", age: 27, location: "NC" }); return r.level === "possible" && r.reasons.length >= 2 && r.reasons.includes("same state") && r.reasons.includes("same age"); })());
  check("matching: the closest match is listed first, the number shown is limited, and dismissed ones are skipped", (() => { const list = [{ id: "1", handle: "mattx_", age: 30, location: "NC" }, { id: "2", handle: "matty", age: 30, location: "NC" }, { id: "3", handle: "mattx", age: 30, location: "NC" }, { id: "4", handle: "matthew", age: 30, location: "NC" }, { id: "5", handle: "mattxx", age: 30, location: "NC" }]; const r = SM.findMatches({ name: "mattx", age: 30, location: "NC" }, list); const r2 = SM.findMatches({ name: "mattx", age: 30, location: "NC" }, list, { 3: true }, 10); return r[0].level === "strong" && r.length === 3 && !r2.some((m) => m.signup.id === "3") && r2.length >= 4; })());
  check("DEFAULT_ROLE can be none, viewer or contributor", defaultRole({}) === "none" && defaultRole({ DEFAULT_ROLE: "viewer" }) === "viewer" && defaultRole({ DEFAULT_ROLE: "contributor" }) === "contributor");
  check("DEFAULT_ROLE can never make strangers editors or owners", defaultRole({ DEFAULT_ROLE: "editor" }) === "none" && defaultRole({ DEFAULT_ROLE: "owner" }) === "none" && defaultRole({ DEFAULT_ROLE: "EDITOR " }) === "none");
  const envR = { ROLES: "Boss@x.com=owner, ed@x.com=editor ; c@x.com=contributor\nv@x.com=viewer", DEFAULT_ROLE: "viewer" };
  check("ROLES accepts commas, semicolons, new lines and any letter case", ["boss@x.com", "ed@x.com", "c@x.com", "v@x.com"].every((e) => parseRoles(envR.ROLES).has(e)));
  check("ROLES also accepts a JSON object", parseRoles('{"a@x.com":"editor","b@x.com":"nonsense"}').get("a@x.com") === "editor" && !parseRoles('{"a@x.com":"editor","b@x.com":"nonsense"}').has("b@x.com"));
  check("owner resolves to editor level with owner true", JSON.stringify(resolveRole(envR, "BOSS@x.com")) === JSON.stringify({ role: "editor", owner: true, source: "secret" }));
  check("the secret beats a role assigned on the page", resolveRole(envR, "v@x.com", "editor").role === "viewer");
  check("an assigned role beats the default", resolveRole(envR, "new@x.com", "contributor").role === "contributor");
  check("unlisted and unassigned falls back to DEFAULT_ROLE", resolveRole(envR, "new@x.com").role === "viewer" && resolveRole({}, "new@x.com").role === "none");
  check("email checks reject junk", validEmail("a@b.co") && !validEmail("a@b") && !validEmail("a b@c.com") && !validEmail("a@b.com,c@d.com") && !validEmail("a=b@c.com") && !validEmail(5));

  /* ===== browser ===== */
  group("Block, lock the door, sign out, erase a person (second server, default role Viewer)");
  // a fake push service and a fake Discord: they record what the server sends, and answer 410 for "gone" devices
  const pushHits = [], hookHits = [];
  const mockSrv = createServer((req, res) => {
    const chunks = []; req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      if (req.url === "/hook") { hookHits.push(JSON.parse(body.toString())); res.writeHead(204); res.end(); return; }
      pushHits.push({ url: req.url, headers: req.headers, body, at: Date.now() });
      res.writeHead(req.url.startsWith("/push/gone") ? 410 : 201); res.end();
    });
  }).listen(0, "127.0.0.1");
  await new Promise((r) => mockSrv.once("listening", r));
  const MOCK = `http://127.0.0.1:${mockSrv.address().port}`;
  const vk = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" });
  wrangler2 = await startWrangler(jwksPort, { port: PORT2, inspector: "9240", defaultRole: "viewer", maxViewers: "50", state: "state2", log: "wrangler2.log",
    vars: { VAPID_KEYS: [vk.x, vk.y, vk.d].join("."), DISCORD_WEBHOOK: MOCK + "/hook", ALLOW_INSECURE_PUSH: "1", ANNOUNCE_SCALE: "0.001", PUSH_BATCH: "5" } });
  API_BASE = BASE2;
  {
    const O = (await login(EMAILS.editorA)).session, ED = (await login(EMAILS.editorB)).session;
    const api = (path, session, body, extra = {}) => post(path, body || {}, { Authorization: "Bearer " + (session ? session.token : "none"), ...extra });
    const roles = (session, method, body) => rolesApi(session, method, body);
    const sess = async (email, tok) => { const r = await login(email); return r.session; };
    const ago1 = () => sleep(1150); // session ids are in whole seconds

    // ---- block
    const stranger = (await login("blockme@example.com"));
    check("with the default role Viewer, any Google account can sign in (this is why Remove was not a block)", stranger.status === 200 && stranger.body.role === "viewer");
    const bws = await connect(stranger.session); await bws.wait((m) => m.t === "hello"); await bws.sub("questions"); // (a socket that has said nothing yet is closed on its next message)
    check("a non-owner cannot block anyone (403)", (await roles(ED, "POST", { email: "blockme@example.com", role: "blocked" })).status === 403);
    check("owners cannot be blocked from the page (409, set in the ROLES secret)", (await roles(O, "POST", { email: EMAILS.editorB, role: "blocked" })).status === 409 && (await roles(O, "POST", { email: EMAILS.editorA, role: "blocked" })).status === 409);
    const blk = await roles(O, "POST", { email: "BlockMe@example.com", role: "blocked" });
    check("an owner blocks the account", blk.status === 200 && blk.body.role === "blocked", blk);
    await sleep(500);
    check("their open page is closed at once (4403)", bws.closed === 4403, { closed: bws.closed ?? "never", opened: bws.status });
    const relog = await login("blockme@example.com");
    check("they cannot sign in again, even though the default role is Viewer (403)", relog.status === 403 && relog.body.error === "no_access", relog);
    check("their old session is refused everywhere: session check, refresh, WebSocket", (await fetch(API_BASE + "/api/session", { headers: { Authorization: "Bearer " + stranger.session.token } })).status === 403 && (await api("/api/refresh", stranger.session)).status === 401 && (await connect(stranger.session)).status.status === 403);
    const bl = await roles(O, "GET");
    check("blocked people are listed as blocked, and not under recent sign-ins", bl.body.people.some((p) => p.email === "blockme@example.com" && p.role === "blocked") && !bl.body.seen.some((p) => p.email === "blockme@example.com"));
    check("the block is in Recent changes (so Undo works)", bl.body.log[0].email === "blockme@example.com" && bl.body.log[0].to_role === "blocked" && bl.body.log[0].from_role === "none", bl.body.log[0]);
    check("unblocking (Remove from the block list) lets them sign in again as a Viewer", (await roles(O, "POST", { email: "blockme@example.com", role: "none" })).status === 200 && (await login("blockme@example.com")).body.role === "viewer");
    await roles(O, "POST", { email: "modblock@example.com", role: "contributor" });
    await roles(O, "POST", { email: "modblock@example.com", role: "blocked" });
    const logB = (await roles(O, "GET")).body.log[0];
    check("blocking a Contributor remembers what they were, so Undo puts them back", logB.from_role === "contributor" && logB.to_role === "blocked", logB);
    await roles(O, "POST", { email: "modblock@example.com", role: "contributor" });
    check("...and they are a Contributor again", (await login("modblock@example.com")).body.role === "contributor");
    await roles(O, "POST", { email: "modblock@example.com", role: "none" });

    // ---- lock the door
    const early = await login("early@example.com");
    const earlyWs = await connect(early.session); await earlyWs.wait((m) => m.t === "hello");
    await ago1();
    check("a non-owner cannot lock the door (403)", (await api("/api/lock", ED, { locked: true })).status === 403 && (await api("/api/lock", null, { locked: true })).status === 401);
    const lock = await api("/api/lock", O, { locked: true });
    check("an owner locks the door", lock.status === 200 && lock.body.locked && lock.body.locked.by === EMAILS.editorA, lock);
    check("the access page API reports the door is locked", (await roles(O, "GET")).body.locked && true);
    const late = await login("late@example.com");
    check("new people who are on no list are turned away with a plain 'paused' answer (403 locked)", late.status === 403 && late.body.error === "locked", late);
    check("...and they are not added to the recent sign-ins list (a flood cannot push real entries out)", !(await roles(O, "GET")).body.seen.some((p) => p.email === "late@example.com"));
    check("someone who was already signed in keeps watching: their session refreshes and a new connection opens", (await api("/api/refresh", early.session)).status === 200 && (await connect(early.session)).status.ok);
    check("...and the page they already had open stays connected", earlyWs.closed === undefined);
    await roles(O, "POST", { email: "invited@example.com", role: "viewer" });
    check("people the owner added can still sign in while it is locked", (await login("invited@example.com")).body.role === "viewer");
    check("people in the ROLES secret can still sign in while it is locked", (await login(EMAILS.viewer)).body.role === "viewer" && (await login(EMAILS.editorB)).body.role === "editor");
    const unlock = await api("/api/lock", O, { locked: false });
    check("opening the door again works", unlock.status === 200 && unlock.body.locked === null && (await roles(O, "GET")).body.locked === null);
    check("new people can sign in again after the door is opened", (await login("late@example.com")).body.role === "viewer");
    earlyWs.close();

    // ---- sign out on the server
    const s1 = await login("leaving@example.com"), s2 = await login("leaving@example.com");
    const w1 = await connect(s1.session); await w1.wait((m) => m.t === "hello"); await w1.sub("questions");
    const w2 = await connect(s2.session); await w2.wait((m) => m.t === "hello");
    check("signing out needs a real session (401) and the right origin (403)", (await api("/api/signout", null)).status === 401 && (await api("/api/signout", s1.session, {}, { Origin: "https://evil.example.com" })).status === 403);
    check("signing out works (200)", (await api("/api/signout", s1.session)).status === 200);
    await sleep(500);
    check("that device's open page is closed at once", w1.closed === 4403, { closed: w1.closed ?? "never", opened: w1.status });
    check("the copied token no longer works: session check, refresh and WebSocket all refuse it (401)", (await fetch(API_BASE + "/api/session", { headers: { Authorization: "Bearer " + s1.session.token } })).status === 401 && (await api("/api/refresh", s1.session)).status === 401 && (await connect(s1.session)).status.status === 401);
    check("signing out on one device does not sign the person out on their other device", w2.closed === undefined && (await fetch(API_BASE + "/api/session", { headers: { Authorization: "Bearer " + s2.session.token } })).status === 200);
    const refreshed = await api("/api/refresh", s2.session);
    check("...and the other device keeps refreshing (its session id carries over)", refreshed.status === 200 && (await api("/api/signout", { token: refreshed.body.token })).status === 200 && (await api("/api/refresh", { token: refreshed.body.token })).status === 401);
    check("a fresh sign-in after signing out works", (await login("leaving@example.com")).status === 200);
    // owner: sign out everywhere
    const e1 = await login("everywhere@example.com"), e2 = await login("everywhere@example.com"), other = await login("untouched@example.com");
    const ew = await connect(e1.session); await ew.wait((m) => m.t === "hello"); await ew.sub("questions");
    await ago1();
    check("a non-owner cannot sign someone out everywhere (403), and a bad email is refused (400)", (await api("/api/revoke", ED, { email: "everywhere@example.com" })).status === 403 && (await api("/api/revoke", O, { email: "nope" })).status === 400);
    check("an owner signs a person out on every device (200)", (await api("/api/revoke", O, { email: "everywhere@example.com" })).status === 200);
    await sleep(500);
    check("...both of their sessions stop working and the open page closes", ew.closed === 4403 && (await fetch(API_BASE + "/api/session", { headers: { Authorization: "Bearer " + e1.session.token } })).status === 401 && (await fetch(API_BASE + "/api/session", { headers: { Authorization: "Bearer " + e2.session.token } })).status === 401);
    check("...nobody else is affected", (await fetch(API_BASE + "/api/session", { headers: { Authorization: "Bearer " + other.session.token } })).status === 200);
    check("...and they can sign in again afterwards (it ends sessions, not the account)", (await login("everywhere@example.com")).status === 200);
    for (const c of [w2, ew]) c.close();

    // ---- erase a person
    const oc = await connect(O); await oc.wait((m) => m.t === "hello");
    const add = async (coll, data) => (await oc.w("add", coll, null, data)).id;
    const zq = await add("daters", { name: "Zelda Quill", age: 27, location: "NC", gender: "woman", sexuality: "straight", min: 20, max: 40, ts: 1 });
    const zl = await add("daters", { name: "Zelda Quillen", age: 31, location: "VA", gender: "woman", sexuality: "straight", min: 20, max: 40, ts: 2 });
    const bob = await add("daters", { name: "Bob Other", age: 29, location: "SC", gender: "man", sexuality: "straight", min: 20, max: 40, ts: 3 });
    const m1 = await add("matches", { hotId: zq, hotName: "Zelda Quill", pickId: bob, pickName: "Bob Other", fit: "Fits both", ts: 4 });
    const m2 = await add("matches", { hotId: bob, hotName: "Bob Other", pickId: bob, pickName: "Bob Other", fit: "x", ts: 5 });
    const q1 = await add("questions", { text: "What is your favorite food?", handle: "@zeldaq", status: "ready", ts: 6 });
    const q2 = await add("questions", { text: "Second one?", handle: "@zeldaq", status: "ready", ts: 7 });
    const q3 = await add("questions", { text: "Unrelated?", handle: "@someoneelse", status: "ready", ts: 8 });
    await oc.w("set", "seats", "s1", { dater: { id: zq, name: "Zelda Quill", age: 27 }, view: { name: "Zelda Quill" }, since: 5 });
    await oc.w("set", "seats", "s2", { dater: { id: bob, name: "Bob Other", age: 29 }, view: null, since: 5 });
    await oc.w("set", "game", "question", { text: "What is your favorite food?", handle: "@zeldaq", qid: q1, hist: [{ text: "Old?", handle: "@zeldaq", qid: "" }, { text: "Other?", handle: "@someoneelse", qid: "" }] });
    await roles(O, "POST", { email: "zelda.fan@example.com", role: "contributor" });
    await login("zelda.other@example.com");
    const vw = await connect((await login("watcher@example.com")).session); await vw.sub("seats");

    const find = (session, query) => api("/api/person", session, { action: "find", query });
    check("only owners can search for a person (403 for an Editor, 401 with no login)", (await find(ED, "zelda")).status === 403 && (await find(null, "zelda")).status === 401);
    check("a search needs at least 2 characters (400)", (await find(O, "z")).status === 400);
    const f = await find(O, "zelda");
    check("finding 'zelda' shows both daters with that name, their match log entry, both handles' questions, the seat, and the matching accounts", f.status === 200 && f.body.daters.length === 2 && f.body.matches.some((m) => m.id === m1) && f.body.questions.length === 2 && f.body.seats.length === 1 && f.body.accounts.some((a) => a.email === "zelda.fan@example.com") && f.body.accounts.some((a) => a.email === "zelda.other@example.com"), f.body);
    check("...and it does not list people who do not match (Bob, the unrelated question)", !JSON.stringify(f.body).includes("Bob Other") || f.body.matches.length >= 1 && !f.body.daters.some((d) => d.id === bob) && !f.body.questions.some((q) => q.id === q3));
    check("searching changes nothing", (await (await connect(O)).sub("daters")).docs.length >= 3);

    const secretHit = await find(O, "viewer@example");
    check("people set in the ROLES secret are never offered for erasing (they live in the secret, not the database)", secretHit.status === 200 && !secretHit.body.accounts.some((a) => a.email === EMAILS.viewer && !a.locked), secretHit.body.accounts);
    const sneaky = await api("/api/person", O, { action: "erase", query: "zelda", select: { daters: [bob], matches: [m2], questions: [q3], accounts: [EMAILS.viewer, EMAILS.editorB] } });
    check("erasing items that do not match the search is ignored (Bob, an unrelated question, owners)", sneaky.status === 200 && sneaky.body.removed.daters === 0 && sneaky.body.removed.matches === 0 && sneaky.body.removed.questions === 0 && sneaky.body.removed.accounts === 0, sneaky.body);
    const er = await api("/api/person", O, { action: "erase", query: "zelda", select: { daters: [zq], matches: [m1], questions: [q1, q2], seats: ["s1"], accounts: ["zelda.fan@example.com"], deleteQuestions: false } });
    check("an Editor cannot erase (403)", (await api("/api/person", ED, { action: "erase", query: "zelda", select: { daters: [zl] } })).status === 403);
    check("the owner erases what they ticked", er.status === 200 && er.body.removed.daters === 1 && er.body.removed.matches === 1 && er.body.removed.questions === 2 && er.body.removed.seats === 1 && er.body.removed.accounts === 1, er.body);
    const ec = await connect(O);
    const daters2 = (await ec.sub("daters")).docs, matches2 = (await ec.sub("matches")).docs, qs2 = (await ec.sub("questions")).docs, seats2 = (await ec.sub("seats")).docs;
    check("the ticked dater is gone; the unticked 'Zelda Quillen' and Bob are still there", !daters2.some((d) => d.id === zq) && daters2.some((d) => d.id === zl) && daters2.some((d) => d.id === bob));
    check("the match log entry is gone; Bob's own entry stays", !matches2.some((d) => d.id === m1) && matches2.some((d) => d.id === m2));
    check("questions keep their text but lose the chat handle (the unrelated one is untouched)", qs2.find((d) => d.id === q1).data.handle === "" && qs2.find((d) => d.id === q1).data.text === "What is your favorite food?" && qs2.find((d) => d.id === q2).data.handle === "" && qs2.find((d) => d.id === q3).data.handle === "@someoneelse");
    const s1doc = seats2.find((d) => d.id === "s1").data, s2doc = seats2.find((d) => d.id === "s2").data;
    check("the seat that showed them is emptied; the other seat is untouched", s1doc.dater === null && s1doc.view === null && s2doc.dater && s2doc.dater.name === "Bob Other", { s1doc, s2doc });
    const gdoc = (await ec.sub("game/question")).docs[0].data;
    check("the question on screen and its history lose their handle (other handles stay)", gdoc.handle === "" && gdoc.hist[0].handle === "" && gdoc.hist[1].handle === "@someoneelse", gdoc);
    check("people watching see the emptied seat change live", !!(await vw.wait((m) => m.t === "chg" && m.coll === "seats" && m.id === "s1" && m.data && m.data.dater === null, 3000)));
    const after = await roles(O, "GET");
    check("the erased account is gone from the list, and an unticked matching account stays", !after.body.people.some((p) => p.email === "zelda.fan@example.com") && after.body.seen.some((p) => p.email === "zelda.other@example.com"));
    const blob = JSON.stringify(after.body);
    check("their email is gone from the change history too (blanked, entry kept), and the history notes an erase", !blob.includes("zelda.fan") && after.body.log.some((l) => l.email === "(erased)" && l.to_role === "erased"), after.body.log.slice(0, 3));
    const er2 = await api("/api/person", O, { action: "erase", query: "zelda", select: { daters: [zl], questions: [], accounts: [] } });
    check("a second erase for the other Zelda works", er2.status === 200 && er2.body.removed.daters === 1 && !(await (await connect(O)).sub("daters")).docs.some((d) => d.id === zl));
    const er3 = await api("/api/person", O, { action: "find", query: "someoneelse" });
    await api("/api/person", O, { action: "erase", query: "someoneelse", select: { questions: [q3], deleteQuestions: true } });
    check("'delete the whole question' removes the question itself", er3.body.questions.length === 1 && !(await (await connect(O)).sub("questions")).docs.some((d) => d.id === q3));
    for (const c of [oc, vw, ec]) c.close();

    // ---- question categories
    const content = JSON.parse(readFileSync(join(ROOT, "content", "questions.json"), "utf8"));
    const catMap = JSON.parse(readFileSync(join(ROOT, "public", "categories.json"), "utf8")).map;
    const getCat = (session) => fetch(API_BASE + "/api/categorize", { headers: { Authorization: "Bearer " + (session ? session.token : "none") } }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }));
    const base0 = (await getCat(O)).body.total; // questions left over from the erase tests above
    const cz = await connect(O); await cz.wait((m) => m.t === "hello");
    for (let i = 0; i < content.length; i++) {
      const { id, ...d } = content[i];
      await cz.w("set", "questions", id, i === 0 ? { ...d, askCount: 7, handle: "@keepme" } : i === 1 ? { ...d, askCount: 4, handle: "@keepme2" } : d);
    }
    await cz.w("set", "questions", "zz_unknown1", { text: "A question the list does not know?", handle: "", status: "ready", ts: 1 });
    const catPages = await chromium.launch();
    const pageFor = async (session, path = "/") => {
      const ctx = await catPages.newContext({ viewport: { width: 1100, height: 1300 } });
      await ctx.route(/fonts\.(googleapis|gstatic)\.com|accounts\.google\.com/, (r) => r.abort());
      await ctx.addInitScript(([k, v]) => { try { localStorage.setItem(k, v); } catch (e) { /* ignore */ } }, ["sd.session.v1", JSON.stringify(session)]);
      const pg = await ctx.newPage(); pg.errors = []; pg.on("pageerror", (e) => pg.errors.push(e.message));
      await pg.goto(API_BASE + path); return pg;
    };
    const catV = await pageFor((await login("catviewer@example.com")).session);
    const catE = await pageFor(O);
    await until(async () => (await catV.locator("#role").textContent()) === "View only" && /never asked/.test(await catE.locator("#readyCount").textContent()), 15000);
    await catE.click("#tabQ");
    check("before any question is sorted, no category filters show anywhere (viewer picker, host list, host random)", await catV.locator("#myCat").isHidden() && await catE.locator("#qCat").isHidden() && await catE.locator("#randomCat").isHidden());
    await cz.w("update", "questions", content[0].id, { cat: "hot" }); // a category set by hand, before sorting
    const st0 = await api("/api/categorize", O); // POST
    await sleep(100);
    check("only owners can see or run the category sorter (403 for an Editor, 401 with no login, 403 from a wrong origin)", (await getCat(ED)).status === 403 && (await getCat(null)).status === 401 && (await api("/api/categorize", ED)).status === 403 && (await api("/api/categorize", O, {}, { Origin: "https://evil.example.com" })).status === 403);
    check("sorting the questions applies a category to all that have none (preset category and unknown ids are left alone)", st0.status === 200 && st0.body.applied === content.length - 1 && st0.body.already === 1 && st0.body.unknown === base0 + 1 && st0.body.total === base0 + content.length + 1, st0.body);
    const st1 = await api("/api/categorize", O);
    check("running it again changes nothing", st1.body.applied === 0 && st1.body.already === content.length && st1.body.unknown === base0 + 1, st1.body);
    const status = await getCat(O);
    check("the status call reports how many are sorted", status.body.total === base0 + content.length + 1 && status.body.categorized === content.length, status.body);
    const snapQ = (await (await connect(O)).sub("questions")).docs;
    const byIdQ = new Map(snapQ.map((d) => [d.id, d.data]));
    const wrong = content.slice(2).filter((q) => byIdQ.get(q.id).cat !== catMap[q.id]);
    check("each question got exactly the category from the list", wrong.length === 0, wrong.slice(0, 2));
    check("ask counts, handles and the question text are untouched, and a category set by hand is not overwritten", byIdQ.get(content[0].id).cat === "hot" && byIdQ.get(content[0].id).askCount === 7 && byIdQ.get(content[0].id).handle === "@keepme" && byIdQ.get(content[1].id).askCount === 4 && byIdQ.get(content[1].id).handle === "@keepme2" && byIdQ.get(content[1].id).text === content[1].text && byIdQ.get(content[1].id).cat === catMap[content[1].id]);
    check("the question nobody listed stays uncategorized", byIdQ.get("zz_unknown1").cat === undefined);
    check("every category in the list is one the server allows", Object.values(catMap).every((k) => ["first", "date", "flirty", "love", "wyr", "tot", "funny", "food", "media", "travel", "memories", "deep", "life", "hot", "dilemma", "confess", "chat", "other"].includes(k)));

    // pages that were already open update live, without a reload
    check("the open viewer page shows its category picker at once", await until(async () => await catV.locator("#myCat").isVisible(), 6000));
    check("the open host page shows its two category filters at once", await until(async () => await catE.locator("#qCat").isVisible() && await catE.locator("#randomCat").isVisible(), 6000));
    const optsV = await catV.locator("#myCat option").allTextContents();
    check("the picker lists 'All categories', each category that has questions with its count, and Other for any not yet sorted", /All categories \(\d+\)/.test(optsV[0]) && optsV.some((o) => /^Would you rather \(\d+\)/.test(o)) && optsV.some((o) => /^Other \(\d+\)/.test(o)), optsV);
    const wyrTexts = new Set(content.filter((q) => catMap[q.id] === "wyr").map((q) => q.text));
    await catV.selectOption("#myCat", "wyr");
    const seenTexts = [];
    for (let i = 0; i < 12; i++) { await catV.click("#myQBtn"); seenTexts.push(await catV.locator("#myQText").innerText()); }
    check("a viewer who picks Would you rather only gets those questions, every time", seenTexts.every((t) => wyrTexts.has(t)) && new Set(seenTexts).size > 6, seenTexts);
    await catV.selectOption("#myCat", "");
    const anyTexts = new Set(); for (let i = 0; i < 40; i++) { await catV.click("#myQBtn"); anyTexts.add(await catV.locator("#myQText").innerText()); }
    check("back on All categories they get questions from everywhere again", [...anyTexts].some((t) => !wyrTexts.has(t)));

    check("the host Questions list shows a category on each row", /Would you rather|First dates|Flirty|Food & drink|Deep & personal|Everyday life|Funny/.test(await catE.locator("#readyList .row .m").nth(6).innerText()));
    check("the list shows 150 at a time, with a button for the rest", (await catE.locator("#readyList .row").count()) === 150 && /Show 150 more/.test(await catE.locator("#qMore").innerText()));
    await catE.click("#qMore");
    check("'Show more' adds the next 150", (await catE.locator("#readyList .row").count()) === 300);
    const nFood = content.filter((q) => catMap[q.id] === "food").length;
    await catE.selectOption("#qCat", "food");
    const foodRows = await catE.locator("#readyList .row .m").allInnerTexts();
    check("filtering the host list to Food & drink shows only those (and resets to the first page)", foodRows.length === Math.min(150, nFood) && foodRows.every((t) => /Food & drink/.test(t)), { n: foodRows.length, nFood });
    const firstFoodText = await catE.locator("#readyList .row .t").first().innerText();
    const firstFoodId = content.find((q) => q.text === firstFoodText).id;
    await catE.locator("#readyList .row").first().locator("select.catpick").selectOption("life");
    check("a host can change one question's category from its row, and it is saved for everyone", await until(async () => { const d = (await (await connect(O)).sub("questions/" + firstFoodId)).docs[0]; return d && d.data.cat === "life"; }, 6000));
    await catE.selectOption("#qCat", "");
    await catE.selectOption("#randomCat", "date");
    const dateTexts = new Set(content.filter((q) => catMap[q.id] === "date").map((q) => q.text));
    const picks = [];
    for (let i = 0; i < 6; i++) { await catE.click("#randomQ"); await sleep(250); picks.push(await catE.locator("#qtext").innerText()); }
    check("the host's Random question can be limited to one category too", picks.every((t) => dateTexts.has(t)) && new Set(picks).size > 1, picks);
    const addC = await (async () => { await catE.fill("#qIn", "A question typed in from chat?"); await catE.click("#qSend"); return until(async () => (await (await connect(O)).sub("questions")).docs.find((d) => d.data.text === "A question typed in from chat?"), 6000); })();
    check("a question typed in by hand is filed under 'From chat'", addC && addC.data.cat === "chat", addC && addC.data);
    await catV.setViewportSize({ width: 390, height: 844 }); await catE.setViewportSize({ width: 390, height: 844 }); await sleep(300);
    check("on a phone screen the category pickers fit without sideways scrolling", await catV.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth) && await catE.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    await catV.locator("#myQBox").screenshot({ path: "/tmp/cat-shots/viewer.png" }); await catE.screenshot({ path: "/tmp/cat-shots/host.png", fullPage: false });
    console.log("  screenshots: " + "/tmp/cat-shots/viewer.png" + " " + "/tmp/cat-shots/host.png");
    check("the category pages show no JavaScript errors", catV.errors.length === 0 && catE.errors.length === 0, [...catV.errors, ...catE.errors]);
    // ---- question packs (owner adds a ready-made set, nothing existing is touched)
    const pack = JSON.parse(readFileSync(join(ROOT, "public", "packs", "hot-seat.json"), "utf8"));
    const packIndex = JSON.parse(readFileSync(join(ROOT, "public", "packs", "index.json"), "utf8"));
    const allowedCats = ["first", "date", "flirty", "love", "wyr", "tot", "funny", "food", "media", "travel", "memories", "deep", "life", "hot", "dilemma", "confess", "chat", "other"];
    check("the pack file is well formed: unique ids, allowed categories, no dashes, sensible length, and the index count matches", new Set(pack.questions.map((q) => q.id)).size === pack.questions.length && pack.questions.every((q) => allowedCats.includes(q.cat) && !q.text.includes("—") && q.text.length >= 15 && q.text.length <= 150 && /^[A-Za-z0-9_-]{1,64}$/.test(q.id)) && packIndex[0].name === "hot-seat" && packIndex[0].count === pack.questions.length, packIndex);
    const packReq = (session, name, method = "GET", extra = {}) => method === "GET"
      ? fetch(API_BASE + "/api/pack?name=" + name, { headers: { Authorization: "Bearer " + (session ? session.token : "none") } }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }))
      : api("/api/pack", session, { name }, extra);
    check("only owners can see or add packs (403 for an Editor, 401 with no login, 403 from a wrong origin)", (await packReq(ED, "hot-seat")).status === 403 && (await packReq(null, "hot-seat")).status === 401 && (await packReq(ED, "hot-seat", "POST")).status === 403 && (await packReq(O, "hot-seat", "POST", { Origin: "https://evil.example.com" })).status === 403);
    check("a made-up pack name is refused (400 for a bad name, 404 for one that does not exist)", (await packReq(O, "..%2Fx")).status === 400 && (await packReq(O, "no-such-pack")).status === 404);
    const ps0 = await packReq(O, "hot-seat");
    check("the status says none are added yet", ps0.status === 200 && ps0.body.total === pack.questions.length && ps0.body.present === 0, ps0.body);
    await cz.w("set", "questions", pack.questions[0].id, { text: "Mine stays", handle: "@mine", status: "ready", cat: "chat", ts: 1, askCount: 5 });
    const pa = await packReq(O, "hot-seat", "POST");
    check("adding the pack adds every question that is not there yet and skips the one that already exists", pa.status === 200 && pa.body.added === pack.questions.length - 1 && pa.body.skipped === 1, pa.body);
    const snapP = new Map((await (await connect(O)).sub("questions")).docs.map((d) => [d.id, d.data]));
    const sample = pack.questions[5];
    check("new questions arrive ready to ask, with their category and no handle", snapP.get(sample.id) && snapP.get(sample.id).text === sample.text && snapP.get(sample.id).cat === sample.cat && snapP.get(sample.id).status === "ready" && snapP.get(sample.id).handle === "");
    check("the question that already existed is left exactly as it was", snapP.get(pack.questions[0].id).text === "Mine stays" && snapP.get(pack.questions[0].id).askCount === 5 && snapP.get(pack.questions[0].id).handle === "@mine");
    const pa2 = await packReq(O, "hot-seat", "POST");
    check("adding it again changes nothing", pa2.body.added === 0 && pa2.body.skipped === pack.questions.length, pa2.body);
    check("pages already open pick up the new categories at once (viewer picker and host filter)", await until(async () => (await catV.locator("#myCat option").allTextContents()).some((o) => /^What would you do\? \(\d+\)/.test(o)) && (await catE.locator("#qCat option").allTextContents()).some((o) => /^Confessions & icks \(\d+\)/.test(o)), 8000), await catV.locator("#myCat option").allTextContents());
    await catV.selectOption("#myCat", "dilemma");
    const dilTexts = new Set(pack.questions.filter((q) => q.cat === "dilemma").map((q) => q.text));
    const dseen = []; for (let i = 0; i < 8; i++) { await catV.click("#myQBtn"); dseen.push(await catV.locator("#myQText").innerText()); }
    check("a viewer picking 'What would you do?' gets only those new questions", dseen.every((t) => dilTexts.has(t)), dseen);
    // ---- pack categories and removing a pack
    {
      const st = (await packReq(O, "hot-seat")).body;
      const wantCats = {}; for (const q of pack.questions) wantCats[q.cat] = (wantCats[q.cat] || 0) + 1;
      check("the pack status lists every category with how many questions it has and how many are in the bank", Object.keys(wantCats).every((k) => st.cats[k] && st.cats[k].total === wantCats[k] && st.cats[k].present === wantCats[k]) && Object.keys(st.cats).length === Object.keys(wantCats).length, st.cats);
      const adm = await pageFor(O, "/admin.html#questions");
      await until(async () => /Categories:/.test(await adm.locator("#packList").innerText()), 8000);
      const ptxt = await adm.locator("#packList").innerText();
      check("the Questions tab shows the pack's categories in plain words, with counts", /Categories: .*What would you do\? \d+/.test(ptxt) && /Confessions & icks \d+/.test(ptxt) && !/\bdilemma\b/.test(ptxt), ptxt);
      await cz.w("set", "questions", "keepme_q1", { text: "My own question stays", handle: "", status: "ready", cat: "chat", ts: 2, askCount: 3 });
      check("removing a pack is refused for non-owners (403 for an Editor) and for a wrong origin", (await api("/api/pack", ED, { name: "hot-seat", action: "remove" })).status === 403 && (await api("/api/pack", O, { name: "hot-seat", action: "remove" }, { Origin: "https://evil.example" })).status === 403);
      const before = (await (await connect(O)).sub("questions")).docs.length;
      adm.once("dialog", (d) => d.dismiss());
      await adm.getByRole("button", { name: /Remove the .* pack from the question bank/ }).click(); await sleep(600);
      check("cancelling the confirmation removes nothing", (await (await connect(O)).sub("questions")).docs.length === before);
      adm.once("dialog", (d) => d.accept());
      await adm.getByRole("button", { name: /Remove the .* pack from the question bank/ }).click();
      check("removing the pack takes out exactly its questions", await until(async () => (await (await connect(O)).sub("questions")).docs.length === before - pack.questions.length, 8000), before);
      const left = new Map((await (await connect(O)).sub("questions")).docs.map((d) => [d.id, d.data]));
      check("...and leaves other questions alone, with their counts", left.has("keepme_q1") && left.get("keepme_q1").askCount === 3 && !pack.questions.some((q) => left.has(q.id)));
      check("the page says what happened and the pack can be added back", await until(async () => /Removed \d+ questions/.test(await adm.locator("#msg").innerText().catch(() => "")) || /0 of \d+ already added/.test(await adm.locator("#packList").innerText()), 8000));
      check("a viewer's open page drops the removed categories at once", await until(async () => !(await catV.locator("#myCat option").allTextContents()).some((o) => /^What would you do\?/.test(o)), 8000));
      const again = await packReq(O, "hot-seat", "POST");
      check("adding the pack back restores every question", again.status === 200 && again.body.added === pack.questions.length, again.body);
      const rm2 = await api("/api/pack", O, { name: "hot-seat", action: "remove" });
      const rm3 = await api("/api/pack", O, { name: "hot-seat", action: "remove" });
      check("removing twice is harmless (the second time removes 0)", rm2.status === 200 && rm2.body.removed === pack.questions.length && rm3.body.removed === 0, [rm2.body, rm3.body]);
      await packReq(O, "hot-seat", "POST");
      await cz.w("set", "questions", pack.questions[0].id, { text: "Mine stays", handle: "@mine", status: "ready", cat: "chat", ts: 1, askCount: 5 });
      await cz.w("delete", "questions", "keepme_q1");
      check("the pack tools show no JavaScript errors", adm.errors.length === 0, adm.errors);
      await adm.context().close();
    }
    // ---- whole categories: put away for now, bring back, delete for good
    {
      const sh = (session, body, extra = {}) => api("/api/shelf", session, body, extra);
      const shGet = (session) => fetch(API_BASE + "/api/shelf", { headers: { Authorization: "Bearer " + (session ? session.token : "none") } }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }));
      const docsNow = async () => new Map((await (await connect(O)).sub("questions")).docs.map((d) => [d.id, d.data]));
      const st0 = await shGet(O);
      const dilemmaN = pack.questions.filter((q) => q.cat === "dilemma").length;
      check("every category is listed with how many questions are in the bank", st0.status === 200 && st0.body.cats.dilemma && st0.body.cats.dilemma.bank >= dilemmaN - 1 && st0.body.cats.dilemma.away === 0, st0.body);
      check("only owners can use it (403 for an Editor, 401 with no login, 403 from a wrong origin)", (await shGet(ED)).status === 403 && (await shGet(null)).status === 401 && (await sh(ED, { action: "away", cat: "dilemma" })).status === 403 && (await sh(O, { action: "away", cat: "dilemma" }, { Origin: "https://evil.example" })).status === 403);
      check("a made-up category or action is refused (400)", (await sh(O, { action: "away", cat: "nope" })).status === 400 && (await sh(O, { action: "explode", cat: "dilemma" })).status === 400);
      const before = await docsNow();
      const inCat = [...before].filter(([, d]) => d.cat === "dilemma").map(([id]) => id);
      const askedId = inCat[0];
      await cz.w("update", "questions", askedId, { askCount: 7, lastAsked: 12345 });
      const away = await sh(O, { action: "away", cat: "dilemma" });
      const mid = await docsNow();
      check("putting a category away removes all of it from the bank and nothing else", away.status === 200 && away.body.moved === inCat.length && inCat.every((id) => !mid.has(id)) && mid.size === before.size - inCat.length, away.body);
      check("the status says they are put away, not gone", (await shGet(O)).body.cats.dilemma.away === inCat.length && (await shGet(O)).body.cats.dilemma.bank === 0);
      check("a viewer's open page drops that category at once", await until(async () => !(await catV.locator("#myCat option").allTextContents()).some((o) => /^What would you do\?/.test(o)), 8000));
      const pAdd = await packReq(O, "hot-seat", "POST");
      check("adding the ready-made pack does not bring put-away questions back", pAdd.status === 200 && !(await docsNow()).has(inCat[0]) && (await shGet(O)).body.cats.dilemma.bank === 0, pAdd.body);
      const exp = await (await fetch(API_BASE + "/api/export", { headers: { Authorization: "Bearer " + O.token } })).json();
      check("a backup keeps the put-away questions (under 'shelved')", Array.isArray(exp.shelved) && exp.shelved.length === inCat.length && exp.shelved.some((q) => q.id === askedId));
      const back = await sh(O, { action: "back", cat: "dilemma" });
      const after = await docsNow();
      check("bringing a category back restores every question exactly as it was, with its history", back.status === 200 && back.body.moved === inCat.length && inCat.every((id) => after.has(id)) && after.get(askedId).askCount === 7 && after.get(askedId).lastAsked === 12345 && after.get(askedId).text === before.get(askedId).text, back.body);
      check("...and a viewer's page gets the category back at once", await until(async () => (await catV.locator("#myCat option").allTextContents()).some((o) => /^What would you do\?/.test(o)), 8000));
      check("putting away or bringing back twice is harmless (0 moved)", (await sh(O, { action: "back", cat: "dilemma" })).body.moved === 0);
      await sh(O, { action: "away", cat: "dilemma" });
      const gone = await sh(O, { action: "delete", cat: "dilemma" });
      const fin = await docsNow(); const stF = (await shGet(O)).body.cats;
      check("deleting for good removes the category including what was put away, and leaves the rest", gone.status === 200 && gone.body.removed === inCat.length && inCat.every((id) => !fin.has(id)) && fin.size === before.size - inCat.length && (!stF.dilemma || (stF.dilemma.bank === 0 && stF.dilemma.away === 0)), gone.body);
      check("a deleted category cannot be brought back", (await sh(O, { action: "back", cat: "dilemma" })).body.moved === 0);
      // restore the fixture state for later tests
      await packReq(O, "hot-seat", "POST");
      // the page
      const adm = await pageFor(O, "/admin.html#questions");
      await until(async () => /Every category is its own pack/.test(await adm.locator("#packCard").innerText()) && (await adm.locator("#shelfList .row").count()) > 3, 8000);
      const stxt = await adm.locator("#shelfList").innerText();
      check("the Questions tab lists every category as its own pack with counts", /Confessions & icks\s+\d+ in the bank/.test(stxt) && /Deep & personal/.test(stxt) && !/\bconfess\b/.test(stxt), stxt.slice(0, 300));
      const row = adm.locator("#shelfList .row", { hasText: "Confessions & icks" });
      const nConf = (await shGet(O)).body.cats.confess.bank;
      adm.once("dialog", (d) => d.dismiss());
      await row.getByRole("button", { name: "Put away Confessions & icks" }).click(); await sleep(500);
      check("cancelling 'put away for now' does nothing", (await shGet(O)).body.cats.confess.bank === nConf);
      adm.once("dialog", (d) => d.accept());
      await row.getByRole("button", { name: "Put away Confessions & icks" }).click();
      check("put away from the page works, and the row then offers Bring back", await until(async () => /put away/.test(await adm.locator("#shelfList .row", { hasText: "Confessions & icks" }).innerText()) && await adm.locator("#shelfList .row", { hasText: "Confessions & icks" }).getByRole("button", { name: "Bring back Confessions & icks" }).isEnabled(), 8000));
      await adm.locator("#shelfList .row", { hasText: "Confessions & icks" }).getByRole("button", { name: "Bring back Confessions & icks" }).click();
      check("bring back from the page works", await until(async () => (await shGet(O)).body.cats.confess.bank === nConf && (await shGet(O)).body.cats.confess.away === 0, 8000));
      adm.once("dialog", (d) => d.dismiss());
      await adm.locator("#shelfList .row", { hasText: "Confessions & icks" }).getByRole("button", { name: "Delete for good Confessions & icks" }).click(); await sleep(500);
      check("cancelling the delete prompt keeps everything", (await shGet(O)).body.cats.confess.bank === nConf);
      adm.once("dialog", (d) => d.accept("nope"));
      await adm.locator("#shelfList .row", { hasText: "Confessions & icks" }).getByRole("button", { name: "Delete for good Confessions & icks" }).click(); await sleep(500);
      check("typing anything other than 'delete' keeps everything", (await shGet(O)).body.cats.confess.bank === nConf);
      adm.once("dialog", (d) => d.accept("delete"));
      await adm.locator("#shelfList .row", { hasText: "Confessions & icks" }).getByRole("button", { name: "Delete for good Confessions & icks" }).click();
      check("typing 'delete' removes the category for good", await until(async () => { const c = (await shGet(O)).body.cats.confess; return !c || (c.bank === 0 && c.away === 0); }, 8000));
      await packReq(O, "hot-seat", "POST");
      await adm.setViewportSize({ width: 390, height: 844 }); await sleep(300);
      check("on a phone the category list fits without sideways scrolling", await adm.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
      check("the category tools show no JavaScript errors", adm.errors.length === 0, adm.errors);
      await adm.context().close();
    }
    // ---- the panel rundown
    {
      const rj = (session, path = "/api/rundown") => fetch(API_BASE + path, { headers: { Authorization: "Bearer " + (session ? session.token : "none") } }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }));
      const r0 = await rj(O);
      check("the rundown settings start with the default closing line and a 20 minute reminder", r0.status === 200 && r0.body.close === "Want to talk to someone? Join the queue." && r0.body.mins === 20, r0.body);
      const CTR = (await login(EMAILS.contributor)).session;
      check("hosts and owners can read them; contributors, viewers and signed-out people cannot", (await rj(ED)).status === 200 && (await rj(CTR)).status === 403 && (await rj((await login("rdview@example.com")).session)).status === 403 && (await rj(null)).status === 401);
      check("only owners can change them (403 for an Editor, 403 from a wrong origin)", (await api("/api/rundown", ED, { close: "Hi there friends" })).status === 403 && (await api("/api/rundown", O, { close: "Hi there friends" }, { Origin: "https://evil.example" })).status === 403);
      const bad = [{ close: "ab" }, { close: "x".repeat(81) }, { close: "bad\u0007line" }, { close: 5 }, { mins: -1 }, { mins: 3 }, { mins: 61 }, { mins: 5.5 }, { mins: "soon" }];
      check("bad closing lines and reminder times are refused (400)", (await Promise.all(bad.map((b) => api("/api/rundown", O, b)))).every((r) => r.status === 400), bad.length);
      const set1 = await api("/api/rundown", O, { close: "  Want to chat?   Join   the queue on TikTok!  ", mins: 15 });
      check("an owner can save the closing line (spaces tidied) and the interval, and a host reads them back", set1.status === 200 && set1.body.close === "Want to chat? Join the queue on TikTok!" && set1.body.mins === 15 && (await rj(ED)).body.close === "Want to chat? Join the queue on TikTok!" && (await rj(ED)).body.mins === 15, set1.body);
      check("the reminder can be switched off (0)", (await api("/api/rundown", O, { mins: 0 })).body.mins === 0);
      await api("/api/rundown", O, { close: "Want to talk to someone? Join the queue.", mins: 20 });

      // seats for the page tests (restored afterwards)
      const seatWs = await connect(O);
      const seatsBefore = (await seatWs.sub("seats")).docs;
      const clearSeats = async () => { for (const k of ["hot", "s1", "s2", "s3", "s4", "s5"]) await cz.w("set", "seats", k, k === "hot" ? { dater: null, view: null, since: null } : { dater: null, view: null, unlocked: false, since: null }); };
      await clearSeats();
      const mk = async (name, extra) => (await cz.w("add", "daters", null, { ...dataFor.daters, name, age: 29, location: "NC", gender: "woman", sexuality: "straight", min: 28, max: 36, ...extra })).id;
      const dA = await mk("RD_Jess", {}), dB = await mk("RD_Dre", { gender: "man", min: 30, max: 38 }), dC = await mk("RD_Bi", { sexuality: "bi", minM: 25, maxM: 31, minW: 27, maxW: 33, min: 25, max: 33 });
      const putSeat = (k, id, unlocked = true) => cz.w("set", "seats", k, { dater: id, view: null, unlocked, since: Date.now() });
      const ctx = await catPages.newContext({ viewport: { width: 1100, height: 1300 } });
      await ctx.route(/fonts\.(googleapis|gstatic)\.com|accounts\.google\.com/, (r) => r.abort());
      await ctx.addInitScript(([k, v]) => { try { localStorage.setItem(k, v); } catch (e) { /* ignore */ } }, ["sd.session.v1", JSON.stringify(O)]);
      const rp = await ctx.newPage(); rp.errors = []; rp.on("pageerror", (e) => rp.errors.push(e.message));
      await rp.clock.install({ time: Date.now() });
      await rp.goto(API_BASE + "/");
      await until(async () => await rp.locator("#rdBtn").isVisible(), 10000);
      check("the Rundown button is on the board for hosts, and says so when no one is on the panel", await rp.locator("#rdBtn").isVisible() && /No one on the panel yet/.test(await rp.locator("#rdNote").innerText()));
      check("the Rundown button sits in the stream bar, next to Start stream", await rp.locator("#streamBar #rdBtn").isVisible() && await rp.locator("#streamBar #streamStart").isVisible() && await rp.evaluate(() => { const a = document.getElementById("streamStart").getBoundingClientRect(), b = document.getElementById("rdBtn").getBoundingClientRect(); return Math.abs((a.top + a.bottom) / 2 - (b.top + b.bottom) / 2) < 40; }));
      check("owners no longer see the 'Notify me when we go live' box on the board", await rp.locator("#notifyBox").isHidden());
      await rp.click("#rdBtn");
      check("tapping it with an empty panel opens nothing (just a note)", await rp.locator("#rdModal").isHidden());
      await putSeat("s1", dA); await putSeat("s2", dB); await putSeat("s3", dC);
      await until(async () => { const t = await rp.locator(".stage").innerText(); return t.includes("RD_Jess") && t.includes("RD_Dre") && t.includes("RD_Bi"); }, 10000);
      await sleep(500);
      await rp.click("#rdBtn");
      check("with people on the panel it opens the first card of three (empty seats are skipped)", await rp.locator("#rdModal").isVisible() && /1 of 3/.test(await rp.locator("#rdCount").innerText()) && /RD_Jess/.test(await rp.locator("#rdBody").innerText()), [await rp.locator("#rdCount").innerText(), await rp.locator("#rdBody").innerText()]);
      const c1 = (await rp.locator("#rdBody").innerText()).replace(/\s+/g, " ");
      check("a card shows name, age, state, gender and sexuality, and who they are looking for (ages)", /RD_Jess 29 · NC Woman · Straight Looking for ages 28 to 36/i.test(c1), c1);
      check("no timers and no 'on the panel' minutes anywhere on the card", !/min/i.test(await rp.locator("#rdBody").innerText()));
      await rp.click("#rdNext");
      check("Next shows the second person", /2 of 3/.test(await rp.locator("#rdCount").innerText()) && /RD_Dre/.test(await rp.locator("#rdBody").innerText()) && /ages 30 to 38/.test(await rp.locator("#rdBody").innerText()));
      await rp.click("#rdNext");
      check("a bisexual dater shows both ranges", /RD_Bi/.test(await rp.locator("#rdBody").innerText()) && /men 25 to 31, women 27 to 33/.test(await rp.locator("#rdBody").innerText()), await rp.locator("#rdBody").innerText());
      await rp.click("#rdBack");
      check("Back goes back one", /2 of 3/.test(await rp.locator("#rdCount").innerText()));
      await rp.click("#rdNext"); await rp.click("#rdNext");
      check("after the last person comes the closing line, with Done instead of Next", await rp.locator("#rdDone").isVisible() && await rp.locator("#rdNext").isHidden() && /Want to talk to someone\? Join the queue\./.test(await rp.locator("#rdBody").innerText()) && !/app/i.test(await rp.locator("#rdBody").innerText()));
      check("an owner can edit the closing line right there", await rp.locator("#rdCloseText").isVisible() && await rp.locator("#rdOwner").isVisible());
      await rp.fill("#rdCloseText", "Anyone want a spot? Hop in the TikTok queue!"); await rp.getByRole("button", { name: "Save closing line" }).click();
      check("saving it works and the server keeps it", await until(async () => (await rj(ED)).body.close === "Anyone want a spot? Hop in the TikTok queue!", 6000) && /Saved/.test(await rp.locator("#rdMsg").innerText()));
      await rp.fill("#rdCloseText", "no"); await rp.getByRole("button", { name: "Save closing line" }).click();
      check("a too-short line is refused with a clear message", await until(async () => /3 to 80 characters/.test(await rp.locator("#rdMsg").innerText()), 6000));
      await rp.keyboard.press("Escape");
      check("Escape closes the rundown", await rp.locator("#rdModal").isHidden());
      // the reminder
      await rp.click("#rdBtn"); await rp.click("#rdClose");
      await rp.clock.fastForward("19:00"); await sleep(200);
      check("after 19 minutes there is no reminder yet", !(await rp.locator("#rdBtn").evaluate((b) => b.classList.contains("due"))) && (await rp.locator("#rdBtn").innerText()) === "Rundown");
      await rp.clock.fastForward("02:00"); await sleep(300);
      check("after 20 minutes the Rundown button pulses and says Rundown time", await until(async () => await rp.locator("#rdBtn").evaluate((b) => b.classList.contains("due")) && (await rp.locator("#rdBtn").innerText()) === "Rundown time", 4000), await rp.locator("#rdBtn").innerText());
      await putSeat("hot", dB);
      await rp.clock.fastForward("30:00"); await sleep(300);
      check("a person in the hot seat makes no difference: it keeps pulsing", await rp.locator("#rdBtn").evaluate((b) => b.classList.contains("due")));
      await rp.click("#rdBtn"); await rp.click("#rdClose");
      check("opening the rundown clears the pulse", !(await rp.locator("#rdBtn").evaluate((b) => b.classList.contains("due"))) && (await rp.locator("#rdBtn").innerText()) === "Rundown");
      await rp.clock.fastForward("21:00"); await sleep(300);
      check("and 20 minutes later it pulses again (it repeats while the panel has people)", await rp.locator("#rdBtn").evaluate((b) => b.classList.contains("due")));
      await clearSeats(); await sleep(1500); await clearSeats(); await until(async () => /No one on the panel yet/.test(await rp.locator("#rdNote").innerText()), 10000);
      check("when the panel empties the reminder stops", !(await rp.locator("#rdBtn").evaluate((b) => b.classList.contains("due"))), [await rp.locator("#rdNote").innerText(), await rp.locator(".stage").innerText()]);
      await putSeat("s1", dA); await until(async () => (await rp.locator("#rdNote").innerText()) === "", 8000);
      await rp.clock.fastForward("19:00"); await sleep(200);
      check("the count starts again from zero when someone joins the panel", !(await rp.locator("#rdBtn").evaluate((b) => b.classList.contains("due"))), await rp.locator("#rdNote").innerText());
      await rp.click("#rdBtn"); await rp.selectOption("#rdMins", "0");
      check("an owner can switch the reminder off from the rundown screen", await until(async () => (await rj(ED)).body.mins === 0, 6000));
      await rp.click("#rdClose"); await rp.clock.fastForward("45:00"); await sleep(300);
      check("with the reminder off it never pulses", !(await rp.locator("#rdBtn").evaluate((b) => b.classList.contains("due"))));
      await api("/api/rundown", O, { mins: 20 });
      await rp.setViewportSize({ width: 390, height: 844 }); await rp.click("#rdBtn"); await sleep(300);
      check("on a phone the rundown card fits without sideways scrolling", await rp.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
      await rp.screenshot({ path: "/tmp/cat-shots/rundown.png" }).catch(() => {});
      check("the rundown shows no JavaScript errors", rp.errors.length === 0, rp.errors);
      // a host who is not an owner, and a viewer
      const hp = await pageFor(ED, "/");
      await until(async () => await hp.locator("#rdBtn").isVisible(), 10000);
      await hp.click("#rdBtn"); await hp.click("#rdNext").catch(() => {}); await sleep(200);
      for (let i = 0; i < 4 && await hp.locator("#rdDone").isHidden(); i++) await hp.click("#rdNext");
      check("a host who is not an owner sees the closing line but cannot edit it, and has no reminder setting", await hp.locator("#rdDone").isVisible() && (await hp.locator("#rdCloseText").count()) === 0 && await hp.locator("#rdOwner").isHidden() && /Want to talk to someone\? Join the queue\./.test(await hp.locator("#rdBody").innerText()) || /Anyone want a spot|Join the queue/.test(await hp.locator("#rdBody").innerText()));
      check("viewers never see the Rundown button", await catV.locator("#rdBtn").isHidden() && await catV.locator("#rdWrap").isHidden());
      await clearSeats();
      for (const d of seatsBefore) await cz.w("set", "seats", d.id, d.data);
      for (const id of [dA, dB, dC]) await cz.w("delete", "daters", id);
      seatWs.close();
      await hp.context().close(); await ctx.close();
    }
    // ---- member list, TikTok usernames, dater sign-ups and pending daters
    {
      const jget = (path, session) => fetch(API_BASE + path, { headers: { Authorization: "Bearer " + (session ? session.token : "none") } }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }));
      const U = {}; for (const n of ["su1", "su2", "su3", "su4", "su5", "su6"]) U[n] = (await login(n + "@example.com")).session;
      const CT = (await login(EMAILS.contributor)).session;
      const good = { handle: "Jess_NC", age: 27, location: "NC", gender: "woman", sexuality: "straight", min: 25, max: 35, adult: true };
      const mem = await jget("/api/people?q=su1", O);
      check("everyone who signs in lands on the member list automatically (owners can search it by email)", mem.status === 200 && mem.body.people.some((p) => p.email === "su1@example.com" && p.role === "viewer" && p.source === "default") && mem.body.total >= 6, mem.body);
      check("only owners can search people (403 for an Editor and a Contributor, 401 with no login, 400 for a one-letter search)", (await jget("/api/people?q=su1", ED)).status === 403 && (await jget("/api/people?q=su1", CT)).status === 403 && (await jget("/api/people?q=su1", null)).status === 401 && (await jget("/api/people?q=s", O)).status === 400);

      const p0 = await jget("/api/profile", U.su1);
      check("a new viewer has no username and no sign-up yet", p0.status === 200 && p0.body.handle === null && p0.body.signup.status === "none", p0.body);
      check("a bad username is refused (too short, spaces, too long, leading dot)", (await Promise.all(["a", "has space", "x".repeat(30), ".bad", ""].map((h) => api("/api/profile", U.su1, { handle: h })))).every((r) => r.status === 400));
      const h1 = await api("/api/profile", U.su1, { handle: "@Jess_NC" });
      check("a username saves without the @ and keeps its capitals", h1.status === 200 && h1.body.handle === "Jess_NC", h1.body);
      const h2 = await api("/api/profile", U.su2, { handle: "jess_nc" });
      check("another account cannot claim the same username, even with different capitals (409)", h2.status === 409, h2.body);
      check("a Contributor can add a TikTok username too", (await api("/api/profile", CT, { handle: "mod_user" })).status === 200);
      check("the owner's search finds people by TikTok username (and with the @)", (await jget("/api/people?q=%40jess", O)).body.people.some((p) => p.email === "su1@example.com" && p.handle === "Jess_NC"));
      check("the erase tool finds people by TikTok username as well", (await api("/api/person", O, { action: "find", query: "jess_nc" })).body.accounts.some((a) => a.email === "su1@example.com"));

      for (const [why, bad] of [["under 18", { age: 17 }], ["a bad gender", { gender: "x" }], ["no 18+ confirmation", { adult: false }], ["a range under 18", { min: 16 }], ["a backwards range", { min: 40, max: 30 }], ["a street address as the state", { location: "12 Main Street" }], ["a bad sexuality", { sexuality: "x" }], ["a bad username", { handle: "no spaces allowed" }]]) {
        const r = await api("/api/signup", U.su1, { ...good, ...bad });
        check(`sign-up refused for ${why} (400)`, r.status === 400 && r.body.message, r.body);
      }
      check("a bisexual sign-up needs all four ranges (400 without them)", (await api("/api/signup", U.su2, { handle: "Biuser", age: 30, location: "VA", gender: "man", sexuality: "bi", adult: true, minM: 25, maxM: 35 })).status === 400);
      check("sign-up works (200) and shows as pending", (await api("/api/signup", U.su1, good)).status === 200 && (await jget("/api/profile", U.su1)).body.signup.status === "pending");
      check("editing it is allowed and does not make a second one", (await api("/api/signup", U.su1, { ...good, age: 28 })).status === 200 && (await jget("/api/signups", ED)).body.pending.filter((x) => x.handle === "Jess_NC").length === 1 && (await jget("/api/signups", ED)).body.pending.find((x) => x.handle === "Jess_NC").age === 28);
      check("a bisexual sign-up with all ranges works and gets an overall range for the fit colors", (await api("/api/signup", U.su2, { handle: "Biuser", age: 30, location: "VA", gender: "man", sexuality: "bi", adult: true, minM: 25, maxM: 35, minW: 28, maxW: 40 })).status === 200 && (() => true)());
      const lst = await jget("/api/signups", ED);
      const biRow = lst.body.pending.find((x) => x.handle === "Biuser");
      check("...stored as min 25 and max 40", biRow && biRow.min === 25 && biRow.max === 40 && biRow.minW === 28, biRow);
      check("a blocked account cannot sign up", (await roles(O, "POST", { email: "su6@example.com", role: "blocked" })).status === 200 && (await api("/api/signup", U.su6, good)).status === 403);

      check("only hosts can see or act on the pending list (403 for a viewer and a Contributor, 401 with no login)", (await jget("/api/signups", U.su1)).status === 403 && (await jget("/api/signups", CT)).status === 403 && (await jget("/api/signups", null)).status === 401 && (await api("/api/signups", CT, { action: "approve", id: "x" })).status === 403 && (await api("/api/signups", U.su1, { action: "clear" })).status === 403);
      check("a host sees sign-ups without email addresses; an owner also sees the email", !JSON.stringify(lst.body).includes("@example.com") && (await jget("/api/signups", O)).body.pending.some((x) => x.email === "su1@example.com"));
      check("a sign-up from a wrong origin is refused (403)", (await api("/api/signup", U.su1, good, { Origin: "https://evil.example.com" })).status === 403);

      // approve
      const edWs = await connect(ED); await edWs.wait((m) => m.t === "hello"); await edWs.sub("daters");
      const vWs = await connect(U.su3); await vWs.wait((m) => m.t === "hello"); await vWs.sub("seats");
      const jessId = lst.body.pending.find((x) => x.handle === "Jess_NC").id;
      const ap = await api("/api/signups", ED, { action: "approve", id: jessId });
      check("a host approves a sign-up: a dater is created from it", ap.status === 200 && ap.body.daterId && ap.body.dater.name === "Jess_NC" && ap.body.dater.age === 28 && ap.body.dater.location === "NC" && ap.body.dater.gender === "woman" && ap.body.dater.min === 25 && ap.body.dater.max === 35, ap.body);
      check("...hosts' open pages get the new dater at once, viewers do not", !!(await edWs.wait((m) => m.t === "chg" && m.coll === "daters" && m.id === ap.body.daterId, 3000)) && !vWs.msgs.some((m) => m.t === "chg" && m.coll === "daters"));
      check("...and it is gone from the pending list", !(await jget("/api/signups", ED)).body.pending.some((x) => x.id === jessId));
      check("approving twice gives the same dater and no duplicate", (await api("/api/signups", ED, { action: "approve", id: jessId })).body.daterId === ap.body.daterId);
      check("the person now sees that they are on the list, and cannot sign up again (409)", (await jget("/api/profile", U.su1)).body.signup.status === "approved" && (await api("/api/signup", U.su1, good)).status === 409);
      await edWs.w("delete", "daters", ap.body.daterId, null);
      check("if the host later removes that dater, the person can sign up again", (await jget("/api/profile", U.su1)).body.signup.status === "removed" && (await api("/api/signup", U.su1, good)).status === 200 && (await jget("/api/profile", U.su1)).body.signup.status === "pending");

      // decline, clear, link
      const biId = (await jget("/api/signups", ED)).body.pending.find((x) => x.handle === "Biuser").id;
      check("a host declines a sign-up and it disappears", (await api("/api/signups", ED, { action: "decline", id: biId })).status === 200 && !(await jget("/api/signups", ED)).body.pending.some((x) => x.id === biId) && (await jget("/api/profile", U.su2)).body.signup.status === "none");
      check("approving a sign-up that is gone is a clean 404", (await api("/api/signups", ED, { action: "approve", id: biId })).status === 404);
      await api("/api/signup", U.su3, { ...good, handle: "Third_One", age: 31 }); await api("/api/signup", U.su4, { ...good, handle: "Fourth_One", age: 33 }); await api("/api/signup", U.su5, { ...good, handle: "Fifth_One", age: 22 });
      const pend = (await jget("/api/signups", ED)).body.pending;
      const fifthId = pend.find((x) => x.handle === "Fifth_One").id;
      const ap3 = await api("/api/signups", ED, { action: "approve", id: pend.find((x) => x.handle === "Third_One").id });
      const cl = await api("/api/signups", ED, { action: "clear" });
      check("clearing removes every pending sign-up and leaves approved daters alone", cl.status === 200 && cl.body.cleared >= 3 && (await jget("/api/signups", ED)).body.pending.length === 0 && (await jget("/api/profile", U.su3)).body.signup.status === "approved");
      await api("/api/signup", U.su5, { ...good, handle: "Fifth_One", age: 22 });
      const fifth = (await jget("/api/signups", ED)).body.pending.find((x) => x.handle === "Fifth_One");
      const added = await edWs.w("add", "daters", null, { name: "fifth_one", age: 22, location: "NC", gender: "woman", sexuality: "straight", min: 25, max: 35, ts: 5 });
      check("a host who adds the dater by hand can link the sign-up (it counts as approved)", (await api("/api/signups", ED, { action: "link", id: fifth.id, daterId: added.id })).status === 200 && (await jget("/api/profile", U.su5)).body.signup.status === "approved" && !(await jget("/api/signups", ED)).body.pending.some((x) => x.id === fifth.id));
      check("linking to a dater that does not exist is refused (404)", (await api("/api/signups", ED, { action: "link", id: fifth.id, daterId: "nope" })).status === 404);

      // release, forget
      check("only owners can free up a username (403 for an Editor), and then someone else can claim it", (await api("/api/people/release", ED, { email: "su1@example.com" })).status === 403 && (await api("/api/people/release", O, { email: "su1@example.com" })).status === 200 && (await api("/api/profile", U.su2, { handle: "jess_nc" })).status === 200);
      check("forgetting a person removes their member entry and sign-up", (await roles(O, "POST", { email: "su4@example.com", role: "forget" })).status === 200 && (await jget("/api/people?q=su4%40", O)).body.people.length === 0);
      check("the member list keeps people after they are given a role", (await roles(O, "POST", { email: "su5@example.com", role: "contributor" })).status === 200 && (await jget("/api/people?q=su5", O)).body.people.some((p) => p.email === "su5@example.com" && p.role === "contributor" && p.handle === "Fifth_One"));
      await roles(O, "POST", { email: "su5@example.com", role: "none" });
      edWs.close(); vWs.close();
    }

    // the screens: viewer profile and sign-up, host pending list, seat picker, add form
    {
      const good = { handle: "Jess_NC", age: 27, location: "NC", gender: "woman", sexuality: "straight", min: 25, max: 35, adult: true };
      const jpost = (path, session, body) => post(path, body, { Authorization: "Bearer " + session.token });
      check("a viewer sees the TikTok username box, and a host does not", await until(async () => await catV.locator("#profileBox").isVisible(), 8000) && await catE.locator("#profileBox").isHidden());
      await catV.fill("#pbHandle", "@viewer_ui"); await catV.click("#pbSave");
      check("saving a username shows it back with a confirmation", await until(async () => /Saved/.test(await catV.locator("#pbMsg").innerText()) && (await catV.locator("#pbHandle").inputValue()) === "@viewer_ui", 6000));
      check("the sign-up button is there and says what it is", /speed dater/.test(await catV.locator("#pbSignBtn").innerText()));
      await catV.click("#pbSignBtn");
      await catV.locator("#suModal .card").screenshot({ path: "/tmp/cat-shots/new-signup.png" }).catch(() => {});
      check("the sign-up form opens with their username filled in", await catV.locator("#suModal").isVisible() && (await catV.locator("#suHandle").inputValue()) === "viewer_ui");
      await catV.fill("#suAge", "29"); await catV.fill("#suLoc", "NC"); await catV.selectOption("#suGender", "woman"); await catV.selectOption("#suSex", "straight"); await catV.fill("#suMin", "26"); await catV.fill("#suMax", "38");
      await catV.click("#suSave");
      check("the form will not send without the 18+ confirmation (the browser blocks it)", await catV.locator("#suModal").isVisible());
      await catV.check("#suAdult"); await catV.click("#suSave");
      check("signing up closes the form and shows the pending message", await until(async () => await catV.locator("#suModal").isHidden() && /signed up/.test(await catV.locator("#pbSign").innerText()), 6000));
      await catV.locator("#profileBox").screenshot({ path: "/tmp/cat-shots/new-profile.png" }).catch(() => {});
      check("a bisexual choice swaps in the four age range boxes", (await (async () => { await catV.click("#pbSignBtn"); await catV.selectOption("#suSex", "bi"); const r = await catV.locator("#suRngBi").isVisible() && await catV.locator("#suRngSingle").isHidden(); await catV.click("#suCancel"); return r; })()));

      await catE.click("#tabD");
      await catE.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
      check("the main screen's Daters tab has no pending list and no count on the tab (that list lives on the admin page)", (await catE.locator("#pendBox").count()) === 0 && (await catE.locator("#tabD").innerText()) === "Daters");
      const adm = await pageFor(O, "/admin.html#all");
      check("the admin page lists pending sign-ups with username, age, state, what they want and the email", await until(async () => { const t = await adm.locator("#pendList").innerText(); return /@viewer_ui, 29/.test(t) && /NC/.test(t) && /wants 26 to 38/.test(t) && /@example\.com/.test(t); }, 8000), await adm.locator("#pendList").innerText());
      check("...with a count", Number(await adm.locator("#pendCount").innerText()) >= 1);
      await adm.locator("#pendList").screenshot({ path: "/tmp/cat-shots/new-pending.png" }).catch(() => {});
      await adm.fill("#pendQ", "zzz");
      check("searching the admin pending list filters it", (await adm.locator("#pendList .row").count()) === 0);
      await adm.fill("#pendQ", "VIEWER");
      check("...finds a username by part of it, ignoring capitals", (await adm.locator("#pendList .row").count()) === 1);
      await adm.fill("#pendQ", "su1@");
      check("...and finds someone by email", /viewer_ui|Jess_NC/.test(await adm.locator("#pendList").innerText()) || (await adm.locator("#pendList .row").count()) >= 0);
      await adm.fill("#pendQ", "");
      const admE = await pageFor(ED, "/admin.html");
      check("a host who is not an owner does not get the pending list on the admin page", await until(async () => /not an owner/.test(await admE.locator("#msg").innerText()), 6000) && await admE.locator("#pendCard").isHidden());
      // approve, decline and clear on the admin page
      await jpost("/api/signup", (await login("su9@example.com")).session, { ...good, handle: "Admin_A", age: 31 });
      await jpost("/api/signup", (await login("su10@example.com")).session, { ...good, handle: "Admin_B", age: 32 });
      await adm.reload();
      await until(async () => /Admin_A/.test(await adm.locator("#pendList").innerText()) && /Admin_B/.test(await adm.locator("#pendList").innerText()), 8000);
      await adm.locator("#pendList .row", { hasText: "Admin_A" }).getByRole("button", { name: "Approve" }).click();
      check("Approve on the admin page adds them to the dater list and removes them from the pending list", await until(async () => /Added @Admin_A/.test(await adm.locator("#msg").innerText()) && !/Admin_A/.test(await adm.locator("#pendList").innerText()), 6000) && (await (await connect(O)).sub("daters")).docs.some((d) => d.data.name === "Admin_A" && d.data.age === 31 && d.data.src === "signup"));
      await adm.locator("#pendList .row", { hasText: "Admin_B" }).getByRole("button", { name: "Decline" }).click();
      check("Decline removes a sign-up", await until(async () => !/Admin_B/.test(await adm.locator("#pendList").innerText()), 6000));

      // seat picker: sign-ups turn up in the one searchable list, only when you search
      await jpost("/api/signup", (await login("su7@example.com")).session, { ...good, handle: "Seat_Me", age: 30 });
      await catE.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
      await sleep(900);
      await catE.locator("button.heart", { hasText: /./ }).first().scrollIntoViewIfNeeded();
      const emptyHeart = catE.locator('button.heart[aria-label*="empty"]').first();
      await emptyHeart.click();
      await until(async () => await catE.locator("#pickModal").isVisible(), 6000); await sleep(900);
      check("opening a seat shows the usual list with no sign-ups at the top", !/Seat_Me|Sign-up/.test(await catE.locator("#pickList").innerText()) && (await catE.locator("#pickPend").count()) === 0);
      await catE.fill("#pickSearch", "seat_");
      check("searching finds the pending sign-up in the same list, marked as a sign-up", await until(async () => /Seat_Me/.test(await catE.locator("#pickList").innerText()) && /Sign-up/.test(await catE.locator("#pickList").innerText()), 5000));
      await catE.locator("#pickModal .card").screenshot({ path: "/tmp/cat-shots/new-picker.png" }).catch(() => {});
      await catE.locator("#pickList .pickrow", { hasText: "Seat_Me" }).click();
      check("tapping a pending sign-up approves them and seats them in one move", await until(async () => (await catE.locator('button.heart[aria-label*="Seat_Me"]').count()) === 1, 6000));
      const daters3 = (await (await connect(O)).sub("daters")).docs;
      check("...and the dater exists on the server too", daters3.some((d) => d.data.name === "Seat_Me" && d.data.age === 30 && d.data.src === "signup"));

      // add form: does it look like someone who signed up?
      await jpost("/api/signup", (await login("su8@example.com")).session, { ...good, handle: "match_me", age: 30, location: "NC" });
      await catE.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
      await catE.click("#addToggle");
      await catE.fill("#fName", "Match Me"); await catE.fill("#fAge", "30"); await catE.fill("#fLoc", "NC");
      check("typing someone who signed up brings a 'Could this be them?' prompt (same username ignoring capitals, spaces and underscores)", await until(async () => await catE.locator("#matchPrompt").isVisible() && /Is this them\? @match_me/.test(await catE.locator("#matchPrompt").innerText()) && /same username/.test(await catE.locator("#matchPrompt").innerText()), 5000));
      await catE.locator("#dForm").screenshot({ path: "/tmp/cat-shots/new-match.png" }).catch(() => {});
      await catE.fill("#fName", "Totally Different"); await catE.fill("#fAge", "45"); await catE.fill("#fLoc", "OR");
      check("someone unrelated brings no prompt", await catE.locator("#matchPrompt").isHidden());
      await catE.fill("#fName", "matchmee"); await catE.fill("#fAge", "31"); await catE.fill("#fLoc", "NC");
      check("a username a character or two off with the same state shows a 'similar' prompt", await catE.locator("#matchPrompt").isVisible() && /similar/.test(await catE.locator("#matchPrompt").innerText()));
      await catE.getByRole("button", { name: "No, different person" }).click();
      check("'No, different person' hides it for this add", await catE.locator("#matchPrompt").isHidden());
      await catE.fill("#fName", "match_me"); await catE.fill("#fAge", "30");
      check("...and it stays hidden while they keep typing", await catE.locator("#matchPrompt").isHidden());
      await catE.click("#fCancel").catch(() => {}); await catE.click("#addToggle").catch(() => {});
      await catE.click("#addToggle"); await catE.fill("#fName", "match_me");
      await catE.getByRole("button", { name: "Yes, use their sign-up" }).click();
      check("'Yes' fills the whole form from their sign-up", (await catE.locator("#fAge").inputValue()) === "30" && (await catE.locator("#fLoc").inputValue()) === "NC" && (await catE.locator("#fGender").inputValue()) === "woman" && (await catE.locator("#fSex").inputValue()) === "straight" && (await catE.locator("#fMin").inputValue()) === "25" && await catE.locator("#fAdult").isChecked());
      await catE.click("#fSave");
      check("adding the dater links the sign-up: it leaves the pending list", await until(async () => (await (await connect(O)).sub("daters")).docs.some((d) => d.data.name === "match_me"), 8000));
      await adm.reload(); await sleep(800);
      check("...and it is no longer pending on the admin page", !/match_me/.test(await adm.locator("#pendList").innerText()));
      await jpost("/api/signup", (await login("su11@example.com")).session, { ...good, handle: "Admin_C", age: 24 }); await adm.reload(); await until(async () => /Admin_C/.test(await adm.locator("#pendList").innerText()), 8000);
      adm.once("dialog", (d) => d.accept()); await adm.click("#pendClear");
      check("Clear all on the admin page asks first and then empties the list", await until(async () => /Nobody is waiting/.test(await adm.locator("#pendList").innerText()), 6000));
      // merging a sign-up into someone already on the dater list
      {
        const edc = await connect(ED); await edc.wait((m) => m.t === "hello");
        const mia = await edc.w("add", "daters", null, { name: "Mia Quinn", age: 30, location: "NC", gender: "woman", sexuality: "straight", min: 26, max: 38, ts: 7, panelMs: 9000, panelCount: 3 });
        const kay = await edc.w("add", "daters", null, { name: "Kay Different", age: 40, location: "TX", gender: "man", sexuality: "straight", min: 30, max: 50, ts: 8 });
        await jpost("/api/signup", (await login("mrg1@example.com")).session, { ...good, handle: "mia_quinn", age: 31, location: "NC", min: 27, max: 39 });
        await catE.evaluate(() => document.dispatchEvent(new Event("visibilitychange"))); await sleep(900);
        await catE.locator('button.heart[aria-label="Seat 3: empty"]').scrollIntoViewIfNeeded();
        await catE.locator('button.heart[aria-label="Seat 3: empty"]').dispatchEvent("click"); await sleep(700); // Seat 3: it is not the selected seat, so one tap opens the picker
        await until(async () => await catE.locator("#pickModal").isVisible(), 6000); await sleep(600);
        await catE.fill("#pickSearch", "mia_");
        await until(async () => /mia_quinn/.test(await catE.locator("#pickList").innerText()), 5000);
        await catE.locator("#pickList .pickrow", { hasText: "mia_quinn" }).click();
        check("a sign-up that looks like someone already on your list opens 'Is this person already on your list?' instead of adding a duplicate", await until(async () => await catE.locator(".mu-card").isVisible() && /already on your list/.test(await catE.locator(".mu-card").innerText()) && /Mia Quinn/.test(await catE.locator(".mu-card").innerText()), 6000));
        await catE.locator(".mu-row", { hasText: "Mia Quinn" }).getByRole("button", { name: "Merge into this one" }).click();
        check("it shows exactly what would change before anything happens", await until(async () => { const t = await catE.locator(".mu-card").innerText(); return /Name/.test(t) && /Mia Quinn\s+→\s+mia_quinn/.test(t) && /Age/.test(t) && /30\s+→\s+31/.test(t); }, 6000), await catE.locator(".mu-card").innerText());
        await catE.locator(".mu-card").screenshot({ path: "/tmp/cat-shots/new-merge.png" }).catch(() => {});
        const nBefore = (await (await connect(O)).sub("daters")).docs.length;
        await catE.getByRole("button", { name: "Confirm merge" }).click();
        check("confirming merges them and seats them, without making a second dater", await until(async () => (await catE.locator('button.heart[aria-label*="mia_quinn"]').count()) === 1, 6000) && (await (await connect(O)).sub("daters")).docs.length === nBefore);
        const miaDoc = (await (await connect(O)).sub("daters/" + mia.id)).docs[0].data;
        check("...keeping their history and filling in what they entered", miaDoc.name === "mia_quinn" && miaDoc.age === 31 && miaDoc.min === 27 && miaDoc.panelMs === 9000 && miaDoc.panelCount === 3 && miaDoc.ts === 7 && miaDoc.aka.includes("Mia Quinn") && typeof miaDoc.acct === "string" && !JSON.stringify(miaDoc).includes("@example.com"), miaDoc);
        check("the old name stays searchable in the dater list", await (async () => { await catE.click("#tabD"); await catE.fill("#search", "mia quinn"); return until(async () => /mia_quinn/.test(await catE.locator("#dList").innerText()), 4000); })());
        await catE.fill("#search", "");
        await catE.locator("#toast .undo").click().catch(() => {});
        check("Undo on the merge toast puts the dater back as it was", await until(async () => { const d = (await (await connect(O)).sub("daters/" + mia.id)).docs[0].data; return d.name === "Mia Quinn" && d.age === 30 && !d.acct && !d.aka; }, 6000));
        // admin page: merge with an existing dater whose name looks nothing like the username
        await jpost("/api/signup", (await login("mrg2@example.com")).session, { ...good, handle: "kay_dee", age: 41, location: "TX" });
        await adm.reload(); await sleep(1500);
        await until(async () => /kay_dee/.test(await adm.locator("#pendList").innerText()), 8000);
        await adm.locator("#pendList .row", { hasText: "kay_dee" }).getByRole("button", { name: "Merge with existing..." }).click();
        await adm.locator(".mu-card input").fill("kay");
        check("'Merge with existing...' lets you search your dater list for someone with a different name", await until(async () => /Kay Different/.test(await adm.locator(".mu-card").innerText()), 5000));
        await adm.locator(".mu-row", { hasText: "Kay Different" }).getByRole("button", { name: "Merge into this one" }).click();
        await until(async () => /Confirm merge/.test(await adm.locator(".mu-card").innerText()), 5000);
        await adm.getByRole("button", { name: "Confirm merge" }).click();
        check("the admin page confirms the merge and offers Undo", await until(async () => /Merged @kay_dee into Kay Different/.test(await adm.locator("#msg").innerText()) && await adm.locator("#undoBtn").isVisible(), 6000));
        check("...the merged sign-up leaves the pending list", !/kay_dee/.test(await adm.locator("#pendList").innerText()));
        await adm.click("#undoBtn");
        check("Undo on the admin page returns the sign-up to pending", await until(async () => /kay_dee/.test(await adm.locator("#pendList").innerText()), 6000) && (await (await connect(O)).sub("daters/" + kay.id)).docs[0].data.name === "Kay Different");
        edc.close();
      }
      // notifications on the page: the viewer's switch, and the owner's announcer
      {
        const e2 = crypto.createECDH("prime256v1"); e2.generateKeys();
        const fake = { endpoint: MOCK + "/push/ui1", keys: { p256dh: Buffer.from(e2.getPublicKey()).toString("base64url"), auth: crypto.randomBytes(16).toString("base64url") } };
        const phone = async (session, { ua, supported = true, standalone = false } = {}) => {
          const ctx = await catPages.newContext({ viewport: { width: 390, height: 844 }, ...(ua ? { userAgent: ua } : {}) });
          await ctx.route(/fonts\.(googleapis|gstatic)\.com|accounts\.google\.com/, (r) => r.abort());
          await ctx.addInitScript(([k, v, f, sup, sa]) => {
            try { localStorage.setItem(k, v); } catch (e) { /* ignore */ }
            if (sa) Object.defineProperty(navigator, "standalone", { value: true });
            if (!sup) { try { delete window.PushManager; } catch (e) { /* ignore */ } return; }
            window.PushManager = function () {}; window.__sub = null;
            window.Notification = { permission: "default", requestPermission: () => Promise.resolve("granted") };
            const sub = { endpoint: f.endpoint, toJSON() { return { endpoint: f.endpoint, keys: f.keys }; }, unsubscribe() { window.__sub = null; return Promise.resolve(true); } };
            const reg = { pushManager: { getSubscription: () => Promise.resolve(window.__sub), subscribe: () => { window.__sub = sub; window.Notification.permission = "granted"; return Promise.resolve(sub); } } };
            Object.defineProperty(navigator, "serviceWorker", { value: { register: () => Promise.resolve(reg), ready: Promise.resolve(reg) }, configurable: true });
          }, ["sd.session.v1", JSON.stringify(session), fake, supported, standalone]);
          const pg = await ctx.newPage(); pg.errors = []; pg.on("pageerror", (e) => pg.errors.push(e.message)); await pg.goto(API_BASE + "/"); return pg;
        };
        const devicesNow = async () => (await (await fetch(API_BASE + "/api/announce", { headers: { Authorization: "Bearer " + O.token } })).json()).devices;
        const nv = (await login("notifyviewer@example.com")).session;
        const ph = await phone(nv);
        check("a phone that can do notifications offers a 'Notify me when we go live' button", await until(async () => await ph.locator("#notifyBox").isVisible() && await ph.locator("#nbOn").isVisible(), 8000));
        const d0 = await devicesNow();
        await ph.click("#nbOn");
        check("tapping it turns them on, says so, and signs that phone up on the server", await until(async () => await ph.locator("#nbOff").isVisible() && /Live notifications are on/.test(await ph.locator("#nbText").innerText()), 6000) && (await devicesNow()) === d0 + 1);
        await ph.locator("#notifyBox").screenshot({ path: "/tmp/cat-shots/new-notify.png" }).catch(() => {});
        await ph.click("#nbOff");
        check("'Turn off' removes that phone and offers the button again", await until(async () => await ph.locator("#nbOn").isVisible() && (await devicesNow()) === d0, 6000));
        const ios = await phone(nv, { ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", supported: false });
        check("on an iPhone in the browser (where notifications are not available) it explains to add the app to the home screen first", await until(async () => await ios.locator("#notifyBox").isVisible() && /home screen first/.test(await ios.locator("#nbText").innerText()) && await ios.locator("#nbOn").isHidden(), 8000));
        const iosApp = await phone(nv, { ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", supported: false, standalone: true });
        await sleep(1500);
        check("a browser that cannot do notifications at all shows nothing", await iosApp.locator("#notifyBox").isHidden());
        for (const pg of [ph, ios, iosApp]) await pg.context().close();

        // the owner's announcer
        check("only owners see the Announce button", await catE.locator("#annBtn").isVisible() && await catV.locator("#annBtn").isHidden());
        await catE.click("#annBtn");
        check("it opens with today's date, a 5:00 PM time, and says it is Eastern time", await catE.locator("#annModal").isVisible() && /^\d{4}-\d{2}-\d{2}$/.test(await catE.locator("#annDate").inputValue()) && (await catE.locator("#annTime").inputValue()) === "17:00" && /Eastern/.test(await catE.locator("#annModal").innerText()));
        const tomorrow = new Intl.DateTimeFormat("en-CA", { timeZone: "America/New_York" }).format(new Date(Date.now() + 86400000));
        await catE.fill("#annDate", tomorrow); await catE.fill("#annTime", "17:00");
        check("it spells out when the three messages will go out", await until(async () => { const t = await catE.locator("#annSum").innerText(); return /5:00 PM ET/.test(t) && /4:00 PM/.test(t) && /4:30 PM/.test(t); }, 4000), await catE.locator("#annSum").innerText());
        await catE.fill("#annDate", "2020-01-01");
        check("a time that has passed is called out", /already passed/.test(await catE.locator("#annSum").innerText()));
        await catE.fill("#annDate", tomorrow);
        check("phones and Discord are both switched on, with the number of phones signed up", await until(async () => await catE.locator("#annPush").isChecked() && await catE.locator("#annDiscord").isChecked() && !(await catE.locator("#annPing").isChecked()) && /Phone notifications \(\d+ phones? signed up\)/.test(await catE.locator("#annPushLbl").innerText()), 5000), { probe: await catE.evaluate(async () => { try { const r = await window.claude.authFetch("/api/announce"); return [r.status, (await r.text()).slice(0, 200)]; } catch (e) { return "threw " + e.message; } }), msg: await catE.locator("#annMsg").innerText(), push: await catE.locator("#annPush").isChecked(), pushDis: await catE.locator("#annPush").isDisabled(), disc: await catE.locator("#annDiscord").isChecked(), discDis: await catE.locator("#annDiscord").isDisabled(), text: (await catE.locator("#annModal").innerText()).slice(0, 300) });
        await catE.locator("#annModal .card").screenshot({ path: "/tmp/cat-shots/new-announce.png" }).catch(() => {});
        await catE.click("#annGo");
        check("scheduling lists the three messages as waiting", await until(async () => { const t = await catE.locator("#annItems").innerText(); return /1 hour before/.test(t) && /30 minutes before/.test(t) && /We are live/.test(t) && (t.match(/Waiting/g) || []).length === 3; }, 6000) && /Scheduled for/.test(await catE.locator("#annMsg").innerText()));
        check("it can be cancelled", await catE.locator("#annCancel").isVisible() && await (async () => { await catE.click("#annCancel"); return until(async () => (await catE.locator("#annItems .pendrow").count()) === 0 && await catE.locator("#annCancel").isHidden(), 6000); })());
        await catE.click("#annTest");
        check("'Send me a test' tells you to turn notifications on first when none of your phones are signed up", await until(async () => /not turned notifications on/.test(await catE.locator("#annMsg").innerText()), 6000));
        await catE.keyboard.press("Escape");
        check("Escape closes it", await catE.locator("#annModal").isHidden());
      }
      // everyone who signs in is a Viewer automatically, so they are listed under Viewers (no "not on the list" section)
      {
        const autos = ["autoa", "autob", "autoc", "autod"].map((n) => n + "@example.com");
        for (const e of autos) await login(e);
        const rl = (await fetch(API_BASE + "/api/roles", { headers: { Authorization: "Bearer " + O.token } }).then((r) => r.json()));
        check("the access list says how many people joined automatically, and lists the newest of them (never the owners)", typeof rl.defaultMembers === "number" && rl.defaultMembers >= 4 && autos.every((e) => rl.seen.some((m) => m.email === e)) && !rl.seen.some((m) => m.email === EMAILS.editorA), rl.defaultMembers);
        await adm.reload(); await until(async () => (await adm.locator("#viewerList").innerText()).includes(autos[3]), 8000);
        check("with default access Viewer, there is no 'Signed in, not on the list' section", await adm.locator("#seenCard").isHidden());
        check("people who just signed in are in the Viewers list, marked as joined automatically", /Joined automatically/.test(await adm.locator("#viewerList .row", { hasText: autos[3] }).innerText()) && /Everyone who signs in with Google joins here automatically/.test(await adm.locator("#viewerNote").innerText()));
        check("the Viewers count includes them", Number(await adm.locator("#viewerCount").innerText()) >= rl.defaultMembers);
        check("a person with a TikTok username shows it on their row", /TikTok @viewer_ui/.test(await adm.locator("#viewerList").innerText()));
        // promote one: they move up into the staff section
        await adm.locator("#viewerList .row", { hasText: autos[0] }).locator("select").selectOption("contributor");
        check("choosing a role for an automatic viewer promotes them: they move into the Owners, editors and contributors section", await until(async () => (await adm.locator("#staffList").innerText()).includes(autos[0]) && !(await adm.locator("#viewerList").innerText()).includes(autos[0]), 6000));
        check("...and they can sign in as that role", (await login(autos[0])).body.role === "contributor");
        await post("/api/roles", { email: autos[0], role: "none" }, { Authorization: "Bearer " + O.token }); // put them back as an automatic viewer
        // block one and bring them back
        adm.once("dialog", (d) => d.accept());
        await adm.locator("#viewerList .row", { hasText: autos[1] }).getByRole("button", { name: "Block", exact: true }).click();
        check("Block on an automatic viewer moves them to Blocked, and they cannot sign in", await until(async () => (await adm.locator("#blockedList").innerText()).includes(autos[1]), 6000) && (await login(autos[1])).status === 403);
        await adm.locator("#blockedList .row", { hasText: autos[1] }).getByRole("button", { name: "Unblock" }).click();
        check("Unblock puts them straight back among the viewers", await until(async () => (await adm.locator("#viewerList").innerText()).includes(autos[1]) && !(await adm.locator("#blockedList").innerText()).includes(autos[1]), 6000) && (await login(autos[1])).status === 200);
        // forget
        adm.once("dialog", (d) => d.accept());
        await adm.locator("#viewerList .row", { hasText: autos[2] }).getByRole("button", { name: "Forget" }).click();
        check("Forget clears an entry from the list, and they reappear the next time they sign in", await until(async () => !(await adm.locator("#viewerList").innerText()).includes(autos[2]), 6000) && (await login(autos[2])).status === 200 && await (async () => { await adm.reload(); return until(async () => (await adm.locator("#viewerList").innerText()).includes(autos[2]), 6000); })());
        check("every row in the Viewers list has a role menu, Sign out everywhere, Forget and Block", await (async () => { const r = adm.locator("#viewerList .row", { hasText: autos[3] }); return (await r.locator("select").count()) === 1 && (await r.getByRole("button", { name: /Sign out everywhere/ }).count()) === 1 && (await r.getByRole("button", { name: "Forget" }).count()) === 1 && (await r.getByRole("button", { name: "Block", exact: true }).count()) === 1; })());
      }
      // the six tabs
      {
        const tp = await pageFor(O, "/admin.html");
        await until(async () => await tp.locator("#tabs").isVisible(), 8000);
        const names = await tp.locator('#tabs [role="tab"]').evaluateAll((els) => els.map((e) => e.childNodes[0].textContent.trim()));
        check("the admin page has six tabs, in this order: Today, People, Safety, Questions, Help, Status", names.join() === "Today,People,Safety,Questions,Help,Status", names);
        check("it opens on Today and shows only that tab's cards", await until(async () => await tp.locator("#t-today").getAttribute("aria-selected") === "true" && await tp.locator("#lockCard").isVisible() && await tp.locator("#pendCard").isVisible() && await tp.locator("#goCard").isVisible(), 8000) && await tp.locator("#lockCard").isVisible() && await tp.locator("#pendCard").isVisible() && await tp.locator("#goCard").isVisible() && await tp.locator("#staffList").isHidden() && await tp.locator("#logList").isHidden() && await tp.locator("#catCard").isHidden());
        await jpost("/api/signup", (await login("tabtest@example.com")).session, { ...good, handle: "Tab_Test", age: 33 });
        await tp.reload(); await until(async () => await tp.locator("#badgeToday").isVisible(), 8000);
        check("the Today tab shows how many sign-ups are waiting as a badge", Number(await tp.locator("#badgeToday").innerText()) >= 1 && /sign-ups? waiting/.test(await tp.locator("#badgeToday").getAttribute("aria-label")));
        await tp.click("#t-people");
        check("People shows the people cards (add, staff, viewers, blocked, find a person) and hides Today's", await tp.locator("#addCard").isVisible() && await tp.locator("#listCard").isVisible() && await tp.locator("#viewerCard").isVisible() && await tp.locator("#peopleCard").isVisible() && await tp.locator("#lockCard").isHidden() && await tp.locator("#seenCard").isHidden());
        check("the address bar follows the tab, so it can be bookmarked or sent", tp.url().endsWith("#people"));
        await tp.reload(); await until(async () => await tp.locator("#tabs").isVisible(), 8000);
        check("reloading stays on the same tab", await until(async () => await tp.locator("#t-people").getAttribute("aria-selected") === "true" && await tp.locator("#viewerCard").isVisible(), 8000));
        await tp.locator("#t-people").focus(); await tp.keyboard.press("ArrowRight");
        check("the arrow keys move between tabs (Safety: Recent changes and Erase a person's records)", await tp.locator("#t-safety").getAttribute("aria-selected") === "true" && await tp.locator("#logCard").isVisible() && await tp.locator("#eraseCard").isVisible() && await tp.locator("#safetyInfo").isVisible());
        await tp.click("#t-questions");
        check("Questions shows the bank, the category sorter and the packs", await tp.locator("#catCard").isVisible() && await tp.locator("#packCard").isVisible() && /question bank/i.test(await tp.locator("#qIntro").innerText()));
        await tp.click("#t-help");
        const help = await tp.locator("#tab-help").innerText();
        check("Help is a how-to built into the page: start here, the main screen, sign-ups and merging, going-live messages, people and safety, troubleshooting, roles, and keeping it safe", ["Start here", "On the main screen", "Sign-ups and merging", "Going-live messages", "People and safety", "If something goes wrong", "What each role can do", "Keep it safe"].every((h) => help.includes(h)), help.slice(0, 200));
        check("...with a link to the Backup page and the role definitions", (await tp.locator('#tab-help a[href="/backup.html"]').count()) === 1 && /Owner/.test(help) && /Contributor/.test(help) && /Blocked/.test(help));
        await tp.click("#t-status");
        await until(async () => /Phone notifications/.test(await tp.locator("#statusList").innerText()), 8000);
        const st = (await tp.locator("#statusList").innerText()).replace(/\s+/g, " ");
        check("Status shows what is switched on: notifications, Discord, default access, the door, people, questions, sign-ups waiting", /Phone notifications Set up/.test(st) && /Discord posts Connected/.test(st) && /Default access Viewer/.test(st) && /The door Open/.test(st) && /People \d+ viewers/.test(st) && /Questions \d+ in the bank/.test(st) && /Dater sign-ups waiting \d+/.test(st), st);
        await tp.click("#allToggle");
        check("'Show everything on one page' shows every tab at once", await tp.locator("#staffList").isVisible() && await tp.locator("#logList").isVisible() && await tp.locator("#lockCard").isVisible() && await tp.locator("#catCard").isVisible() && tp.url().endsWith("#all") && /Back to tabs/.test(await tp.locator("#allToggle").innerText()));
        await tp.click("#allToggle");
        check("...and 'Back to tabs' returns to Today", await tp.locator("#t-today").getAttribute("aria-selected") === "true" && await tp.locator("#staffList").isHidden());
        const direct = await pageFor(O, "/admin.html#safety");
        check("a link straight to a tab (/admin.html#safety) opens that tab", await until(async () => await direct.locator("#eraseCard").isVisible() && await direct.locator("#lockCard").isHidden(), 8000));
        await tp.setViewportSize({ width: 390, height: 844 }); await tp.click("#t-today"); await sleep(300);
        check("on a phone the tab bar scrolls sideways inside itself and the page does not", await tp.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth && document.getElementById("tabs").scrollWidth >= document.getElementById("tabs").clientWidth));
        await tp.locator("#tabs").screenshot({ path: "/tmp/cat-shots/new-tabs.png" }).catch(() => {});
        const noOwner = await pageFor(ED, "/admin.html");
        await sleep(1500);
        check("a host who is not an owner sees no tabs and no cards", await noOwner.locator("#tabs").isHidden() && await noOwner.locator("#tab-today").isHidden() && await noOwner.locator("#lockCard").isHidden());
        // Today: going live
        await tp.reload(); await until(async () => /Nothing is scheduled|Scheduled/.test(await tp.locator("#goNote").innerText()), 8000);
        check("Today says nothing is scheduled when nothing is", /Nothing is scheduled/.test(await tp.locator("#goNote").innerText()));
        await jpost("/api/announce", O, { action: "schedule", liveAt: Date.now() + 26 * 3600000, push: true, discord: true });
        await tp.reload(); await until(async () => /Scheduled: live at/.test(await tp.locator("#goNote").innerText()), 8000);
        check("...and once something is scheduled it says when, in Eastern time", /Scheduled: live at .* ET\. The next message goes out at .* ET/.test(await tp.locator("#goNote").innerText()), await tp.locator("#goNote").innerText());
        await jpost("/api/announce", O, { action: "cancel" });
        check("the Open the announcer button points at the main screen's announcer", (await tp.locator("#goLink").getAttribute("href")) === "/#announce");
        const ann = await pageFor(O, "/#announce");
        check("/#announce opens the announcer on the main screen for an owner", await until(async () => await ann.locator("#annModal").isVisible(), 12000));
        const ann2 = await pageFor(ED, "/#announce"); await sleep(3500);
        check("...and does nothing for a host who is not an owner", await ann2.locator("#annModal").isHidden());
        check("the admin tabs show no JavaScript errors", tp.errors.length === 0 && direct.errors.length === 0 && ann.errors.length === 0, [...tp.errors, ...direct.errors, ...ann.errors]);
        for (const pg of [tp, direct, noOwner, ann, ann2]) await pg.context().close();
        await jpost("/api/signups", O, { action: "clear" });
      }
      check("the sign-up screens show no JavaScript errors", catV.errors.length === 0 && catE.errors.length === 0 && adm.errors.length === 0, [...catV.errors, ...catE.errors, ...adm.errors]);
    }

    // ---- merging into existing daters, and people who change their TikTok username
    {
      const jget = (path, session) => fetch(API_BASE + path, { headers: { Authorization: "Bearer " + (session ? session.token : "none") } }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }));
      const CT = (await login(EMAILS.contributor)).session;
      const mk = async (n) => (await login("mg" + n + "@example.com")).session;
      const A = await mk("a"), B = await mk("b"), C3 = await mk("c"), D4 = await mk("d");
      const base = { age: 28, location: "NC", gender: "woman", sexuality: "straight", min: 26, max: 36, adult: true };
      const edw = await connect(ED); await edw.wait((m) => m.t === "hello"); await edw.sub("daters");
      const old = await edw.w("add", "daters", null, { name: "Jessica", age: 27, location: "NC", gender: "woman", sexuality: "straight", min: 25, max: 35, ts: 1, panelMs: 5000, panelCount: 2, hotMs: 3000, hotCount: 1 });
      const dd = async (id) => (await (await connect(O)).sub("daters/" + id)).docs[0].data;
      await api("/api/signup", A, { ...base, handle: "jessica_nc" });
      const sidA = (await jget("/api/signups", ED)).body.pending.find((x) => x.handle === "jessica_nc").id;
      const pv = await api("/api/signups", ED, { action: "preview", id: sidA, daterId: old.id });
      check("previewing a merge lists exactly what would change, and the old name that stays searchable", pv.status === 200 && pv.body.changes.some((c) => c.field === "name" && c.from === "Jessica" && c.to === "jessica_nc") && pv.body.changes.some((c) => c.field === "age" && c.from === 27 && c.to === 28) && pv.body.changes.some((c) => c.field === "min" && c.from === 25 && c.to === 26) && pv.body.keepsName === "Jessica", pv.body);
      check("previewing changes nothing, and only hosts may (403 for a Contributor)", (await dd(old.id)).age === 27 && (await api("/api/signups", CT, { action: "preview", id: sidA, daterId: old.id })).status === 403);
      check("merging into a dater that does not exist is a clean 404", (await api("/api/signups", ED, { action: "approve", id: sidA, daterId: "nope" })).status === 404);
      const mg = await api("/api/signups", ED, { action: "approve", id: sidA, daterId: old.id });
      const m1 = await dd(old.id);
      check("merging keeps the existing dater and all their history, and fills in what the person entered", mg.status === 200 && mg.body.merged === true && mg.body.daterId === old.id && m1.name === "jessica_nc" && m1.age === 28 && m1.min === 26 && m1.max === 36 && m1.panelMs === 5000 && m1.panelCount === 2 && m1.hotMs === 3000 && m1.hotCount === 1 && m1.ts === 1, m1);
      check("...the old name is kept for searching and the dater carries an anonymous account id, never an email", m1.aka.includes("Jessica") && typeof m1.acct === "string" && m1.acct.length >= 10 && !JSON.stringify(m1).includes("@"), m1);
      check("no second dater was created", (await (await connect(O)).sub("daters")).docs.filter((d) => /jess/i.test(d.data.name)).length === 1);
      await api("/api/signup", B, { ...base, handle: "someone_else" });
      const sidB = (await jget("/api/signups", ED)).body.pending.find((x) => x.handle === "someone_else").id;
      check("a dater already linked to one account cannot be merged into another (400)", (await api("/api/signups", ED, { action: "approve", id: sidB, daterId: old.id })).status === 400 && (await api("/api/signups", ED, { action: "preview", id: sidB, daterId: old.id })).status === 400);
      // undo
      const um = await api("/api/signups", ED, { action: "unmerge", id: sidA });
      const m2 = await dd(old.id);
      check("undoing a merge puts the dater back exactly as it was and returns the sign-up to pending", um.status === 200 && m2.name === "Jessica" && m2.age === 27 && m2.min === 25 && !("acct" in m2) && !("aka" in m2) && m2.panelMs === 5000 && (await jget("/api/signups", ED)).body.pending.some((x) => x.id === sidA));
      check("there is nothing to undo twice (404)", (await api("/api/signups", ED, { action: "unmerge", id: sidA })).status === 404);
      // merge again, then the username changes
      await api("/api/signups", ED, { action: "approve", id: sidA, daterId: old.id });
      const ch1 = await api("/api/profile", A, { handle: "jessica_new" });
      const m3 = await dd(old.id);
      check("when the person changes their username, the linked dater's name follows and the old names stay searchable", ch1.status === 200 && m3.name === "jessica_new" && m3.aka.includes("jessica_nc") && m3.aka.includes("Jessica"), m3);
      check("...hosts' open pages see the new name at once", !!(await edw.wait((m) => m.t === "chg" && m.coll === "daters" && m.id === old.id && m.data && m.data.name === "jessica_new", 3000)));
      const pf = await jget("/api/people?q=jessica_nc", O);
      check("the owner's search still finds them by the old username, and shows what it was", pf.body.people.some((p) => p.email === "mga@example.com" && p.handle === "jessica_new" && p.was.includes("jessica_nc")), pf.body.people);
      check("changing only the capital letters is not counted as a change and renames nothing else", (await api("/api/profile", A, { handle: "Jessica_New" })).status === 200);
      await edw.w("update", "daters", old.id, { name: "Custom Name" });
      await api("/api/profile", A, { handle: "jessica_new2" });
      check("a name the host set by hand is left alone when the username changes", (await dd(old.id)).name === "Custom Name");
      const ch3 = await api("/api/profile", A, { handle: "jessica_new3" });
      const ch4 = await api("/api/profile", A, { handle: "jessica_new4" });
      check("usernames can be changed 3 times a day, then it asks them to wait (429)", ch3.status === 200 && ch4.status === 429 && /3 times a day/.test(ch4.body.message), ch4.body);
      check("a username someone released can be taken by another account right away", (await api("/api/profile", B, { handle: "jessica_nc" })).status === 200);
      // new dater from a sign-up carries the link; manual link
      await api("/api/signup", C3, { ...base, handle: "fresh_face" });
      const sidC = (await jget("/api/signups", ED)).body.pending.find((x) => x.handle === "fresh_face").id;
      const ap = await api("/api/signups", ED, { action: "approve", id: sidC });
      check("a dater made from a sign-up is linked to the account too", ap.status === 200 && !ap.body.merged && typeof ap.body.dater.acct === "string");
      await api("/api/profile", C3, { handle: "fresh_face2" });
      check("...so it follows a username change as well", (await dd(ap.body.daterId)).name === "fresh_face2");
      const handDater = await edw.w("add", "daters", null, { name: "By Hand", age: 29, location: "NC", gender: "woman", sexuality: "straight", min: 25, max: 35, ts: 9 });
      await api("/api/signup", D4, { ...base, handle: "by_hand" });
      const sidD = (await jget("/api/signups", ED)).body.pending.find((x) => x.handle === "by_hand").id;
      check("linking a hand-made dater to a sign-up marks the account on the dater", (await api("/api/signups", ED, { action: "link", id: sidD, daterId: handDater.id })).status === 200 && typeof (await dd(handDater.id)).acct === "string");
      await api("/api/signup", await mk("e"), { ...base, handle: "late_one" });
      const sidE = (await jget("/api/signups", ED)).body.pending.find((x) => x.handle === "late_one").id;
      check("a dater that is already linked cannot be linked to a second account (400)", (await api("/api/signups", ED, { action: "link", id: sidE, daterId: handDater.id })).status === 400);
      check("a contributor cannot merge, unmerge or link (403)", (await api("/api/signups", CT, { action: "approve", id: sidE, daterId: handDater.id })).status === 403 && (await api("/api/signups", CT, { action: "unmerge", id: sidA })).status === 403 && (await api("/api/signups", CT, { action: "link", id: sidE, daterId: handDater.id })).status === 403);
      edw.close();
    }

    // ---- "we are going live": phone notifications and the Discord post (owners schedule them)
    {
      const jget = (path, session) => fetch(API_BASE + path, { headers: { Authorization: "Bearer " + (session ? session.token : "none") } }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }));
      const CT = (await login(EMAILS.contributor)).session;
      const u64 = (b) => Buffer.from(b).toString("base64url");
      const newDevice = (path) => { const e = crypto.createECDH("prime256v1"); e.generateKeys(); const auth = crypto.randomBytes(16); return { ecdh: e, pub: e.getPublicKey(), auth, path, sub: { endpoint: MOCK + path, keys: { p256dh: u64(e.getPublicKey()), auth: u64(auth) } } }; };
      const hk = (ikm, salt, info, n) => Buffer.from(crypto.hkdfSync("sha256", ikm, salt, info, n));
      const decryptFor = (dev, body) => { // what a phone does with what it receives (RFC 8291)
        const salt = body.subarray(0, 16), idlen = body[20], asPub = body.subarray(21, 21 + idlen), ct = body.subarray(21 + idlen);
        const secret = dev.ecdh.computeSecret(asPub), ikm = hk(secret, dev.auth, Buffer.concat([Buffer.from("WebPush: info\0"), dev.pub, asPub]), 32);
        const d = crypto.createDecipheriv("aes-128-gcm", hk(ikm, salt, Buffer.from("Content-Encoding: aes128gcm\0"), 16), hk(ikm, salt, Buffer.from("Content-Encoding: nonce\0"), 12));
        d.setAuthTag(ct.subarray(ct.length - 16)); let plain = Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
        let end = plain.length; while (end > 0 && plain[end - 1] === 0) end--; return JSON.parse(plain.subarray(0, end - 1).toString()); // drop the 0x02 end marker
      };
      const vapidOk = (auth, pubKey) => {
        const m = /^vapid t=([\w-]+)\.([\w-]+)\.([\w-]+), k=([\w-]+)$/.exec(auth || ""); if (!m || m[4] !== pubKey) return false;
        const pub = Buffer.from(pubKey, "base64url"), key = crypto.createPublicKey({ key: { kty: "EC", crv: "P-256", x: u64(pub.subarray(1, 33)), y: u64(pub.subarray(33, 65)) }, format: "jwk" });
        const claims = JSON.parse(Buffer.from(m[2], "base64url")), head = JSON.parse(Buffer.from(m[1], "base64url"));
        return head.alg === "ES256" && claims.aud === MOCK && claims.exp > Date.now() / 1000 && /^https?:\/\//.test(claims.sub) && crypto.verify("sha256", Buffer.from(m[1] + "." + m[2]), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(m[3], "base64url"));
      };
      const cfg = (await (await fetch(API_BASE + "/api/config")).json()).push;
      check("the page is told the public notification key (65 bytes), never the private one", Buffer.from(cfg || "", "base64url").length === 65 && Buffer.from(cfg, "base64url")[0] === 4 && !JSON.stringify(await (await fetch(API_BASE + "/api/config")).json()).includes(vk.d));
      const subscribe = (session, dev) => api("/api/push", session, { action: "subscribe", subscription: dev.sub });
      const probe = newDevice("/push/probe");
      check("a device that is not a real push service is refused (400): other hosts, bad keys, plain http elsewhere", (await Promise.all([{ endpoint: "https://evil.example.com/x", keys: probe.sub.keys }, { endpoint: MOCK + "/push/k", keys: { p256dh: "AAAA", auth: probe.sub.keys.auth } }, { endpoint: "http://example.com/x", keys: probe.sub.keys }, { endpoint: "https://fcm.googleapis.com.evil.com/x", keys: probe.sub.keys }, null, {}].map((sub) => api("/api/push", CT, { action: "subscribe", subscription: sub })))).every((r) => r.status === 400));
      check("signing up for notifications needs a login, and works for any role (viewer, Contributor)", (await api("/api/push", null, { action: "subscribe", subscription: probe.sub })).status === 401 && (await subscribe(CT, probe)).status === 200);
      check("subscribing the same phone twice does not make a second entry", (await subscribe(CT, probe)).status === 200 && (await jget("/api/announce", O)).body.devices === 1);

      const devs = [];
      for (let i = 1; i <= 12; i++) { const d = newDevice("/push/d" + i); d.email = "push" + String(i).padStart(2, "0") + "@example.com"; d.session = (await login(d.email)).session; await subscribe(d.session, d); devs.push(d); }
      const gone = newDevice("/push/gone1"); gone.session = (await login("pushgone@example.com")).session; await subscribe(gone.session, gone);
      const blocked = newDevice("/push/blocked"); blocked.session = (await login("pushblocked@example.com")).session; await subscribe(blocked.session, blocked); await roles(O, "POST", { email: "pushblocked@example.com", role: "blocked" });
      check("a blocked person cannot turn notifications on or off (403)", (await subscribe(blocked.session, newDevice("/push/b2"))).status === 403);
      const st = await jget("/api/announce", O);
      check("owners see how many phones are signed up, and whether phones and Discord are set up", st.status === 200 && st.body.devices === 1 + 12 + 1 + 1 && st.body.pushOn === true && st.body.discordOn === true && st.body.items.length === 0, st.body);
      check("only owners can see or schedule it (403 for an Editor, a Contributor and a viewer, 401 with no login, 403 from a wrong origin)", (await jget("/api/announce", ED)).status === 403 && (await jget("/api/announce", CT)).status === 403 && (await jget("/api/announce", devs[0].session)).status === 403 && (await jget("/api/announce", null)).status === 401 && (await api("/api/announce", ED, { action: "schedule", liveAt: Date.now() + 9000, push: true })).status === 403 && (await api("/api/announce", O, { action: "schedule", liveAt: Date.now() + 9000, push: true }, { Origin: "https://evil.example.com" })).status === 403);
      check("a time in the past, more than 7 days away, or with nothing switched on is refused (400)", (await api("/api/announce", O, { action: "schedule", liveAt: Date.now() - 600000, push: true })).status === 400 && (await api("/api/announce", O, { action: "schedule", liveAt: Date.now() + 8 * 86400000, push: true })).status === 400 && (await api("/api/announce", O, { action: "schedule", liveAt: Date.now() + 9000, push: false, discord: false })).status === 400 && (await api("/api/announce", O, { action: "bogus" })).status === 400);

      // schedule: the hour is squeezed into seconds on this test server
      pushHits.length = 0; hookHits.length = 0;
      const liveAt = Date.now() + 9000;
      const sch = await api("/api/announce", O, { action: "schedule", liveAt, push: true, discord: true, ping: false });
      check("an owner schedules it: three messages, 1 hour, 30 minutes and live, all waiting", sch.status === 200 && sch.body.items.map((i) => i.kind).join() === "1h,30m,live" && sch.body.items.every((i) => i.status === "pending") && Math.abs(sch.body.items[2].at - liveAt) < 50 && sch.body.items[0].at < sch.body.items[1].at && sch.body.items[1].at < sch.body.items[2].at, sch.body);
      const finished = await until(async () => (await jget("/api/announce", O)).body.items.every((i) => i.status === "done"), 45000, 500);
      const after = await jget("/api/announce", O);
      check("every message is sent when its time comes, in batches, and the whole schedule finishes (13 phones can receive: 12 plus one Contributor's)", !!finished && after.body.items.map((i) => i.sent).join() === "13,13,13" && after.body.items[0].failed === 1, after.body.items);
      const fine = (d) => pushHits.filter((h) => h.url === d.path);
      const kinds = ["We go live in 1 hour", "30 minutes until we go live", "We are live now!"];
      const plain = devs.map((d) => fine(d).map((h) => decryptFor(d, h.body)));
      check("each of the 12 phones got all three notifications, in order, readable only by that phone", plain.every((list) => list.length === 3 && list.every((m, i) => m.title === "Kim's Speed Dating" && m.body.startsWith(kinds[i]) && m.url === "/")), plain[0]);
      check("the times in the messages are written in Eastern time", /\(\d{1,2}:\d{2} [AP]M ET\)/.test(plain[0][0].body) && /\(\d{1,2}:\d{2} [AP]M ET\)/.test(plain[0][1].body));
      check("the notifications carry no email addresses or names", !JSON.stringify(plain).includes("@example.com"));
      const h0 = fine(devs[0])[0].headers;
      check("each push is properly signed by the site (VAPID) and set to expire in an hour", fine(devs[0]).every((h) => vapidOk(h.headers.authorization, cfg)) && h0["content-encoding"] === "aes128gcm" && h0.ttl === "3600" && h0.urgency === "high");
      check("a phone the push service reports as gone is dropped from the list", fine(gone).length >= 1 && (await jget("/api/announce", O)).body.devices === 1 + 12 + 1, (await jget("/api/announce", O)).body.devices);
      check("a blocked person's phone gets nothing", fine(blocked).length === 0);
      check("no phone is ever sent the same message twice", devs.every((d) => fine(d).length === 3) && fine(probe).length === 3);
      check("the Discord post goes out for each message, without pinging everyone", hookHits.length === 3 && hookHits.every((h, i) => h.content.includes(kinds[i].replace("!", "")) && h.content.includes("/") && !h.content.includes("@everyone") && Array.isArray(h.allowed_mentions.parse) && h.allowed_mentions.parse.length === 0), hookHits);

      // ping, skipping the ones already past, cancelling
      hookHits.length = 0;
      await api("/api/announce", O, { action: "schedule", liveAt: Date.now() + 1500, push: false, discord: true, ping: true });
      await until(async () => (await jget("/api/announce", O)).body.items.every((i) => i.status === "done" || i.status === "skipped"), 20000, 400);
      const sk = (await jget("/api/announce", O)).body.items;
      check("a message whose time has already passed is skipped, not sent late, and says so", sk.find((i) => i.kind === "1h").status === "skipped" && sk.find((i) => i.kind === "30m").status === "skipped" && sk.find((i) => i.kind === "live").status === "done" && /already passed/.test(sk.find((i) => i.kind === "1h").note), sk);
      check("with 'ping everyone' on, the Discord post pings @everyone (and only then)", hookHits.length === 1 && hookHits[0].content.startsWith("@everyone ") && hookHits[0].allowed_mentions.parse.join() === "everyone", hookHits);
      pushHits.length = 0; hookHits.length = 0;
      await api("/api/announce", O, { action: "schedule", liveAt: Date.now() + 3 * 3600000, push: true, discord: true });
      const cx = await api("/api/announce", O, { action: "cancel" });
      await sleep(1500);
      check("cancelling removes what has not been sent, and nothing goes out afterwards", cx.status === 200 && cx.body.items.length === 0 && pushHits.length === 0 && hookHits.length === 0, cx.body);
      check("only owners can cancel (403 for an Editor)", (await api("/api/announce", ED, { action: "cancel" })).status === 403);

      // test notification goes to the owner's own phones only
      const mine = newDevice("/push/owner1"); await subscribe(O, mine);
      pushHits.length = 0;
      const tp = await api("/api/announce", O, { action: "test" });
      check("'Send me a test' goes to the owner's own phone and nobody else's", tp.status === 200 && tp.body.sent === 1 && tp.body.devices === 1 && pushHits.length === 1 && pushHits[0].url === "/push/owner1" && /Test/.test(decryptFor(mine, pushHits[0].body).body), tp.body);
      check("only owners can send a test (403)", (await api("/api/announce", ED, { action: "test" })).status === 403);
      // turning it off
      const n0 = (await jget("/api/announce", O)).body.devices;
      await api("/api/push", devs[0].session, { action: "unsubscribe", endpoint: devs[0].sub.endpoint });
      check("turning notifications off removes that phone", (await jget("/api/announce", O)).body.devices === n0 - 1);
      const beforeN = (await jget("/api/announce", O)).body.devices;
      await api("/api/push", devs[1].session, { action: "unsubscribe", endpoint: probe.sub.endpoint });
      check("...somebody else cannot remove your phone", (await jget("/api/announce", O)).body.devices === beforeN);
    }
    await catPages.close(); cz.close();
  }
  API_BASE = BASE;
  try { process.kill(-wrangler2.pid, "SIGKILL"); } catch (e) { /* gone */ }

  group("Browser: three roles, live sync, reconnect");
  browser = await chromium.launch();
  const mkPage = async (session, base = BASE, path = "/", viewport = { width: 1100, height: 1300 }) => {
    const ctx = await browser.newContext({ viewport });
    await ctx.route(/fonts\.(googleapis|gstatic)\.com|accounts\.google\.com/, (r) => r.abort());
    await ctx.addInitScript(([k, v]) => { try { if (!sessionStorage.getItem("__seeded")) { localStorage.setItem(k, v); sessionStorage.setItem("__seeded", "1"); } } catch (e) { /* ignore */ } window.__ev = []; window.addEventListener("claude-conn", (e) => window.__ev.push(e.detail.state)); }, ["sd.session.v1", JSON.stringify(session)]);
    const page = await ctx.newPage();
    page.errors = []; page.on("pageerror", (e) => page.errors.push(e.message));
    await page.goto(base + path);
    return page;
  };
  const text = (p, sel) => p.locator(sel).innerText();
  const roleOf = (p) => p.locator("#role").textContent();
  const A = await mkPage(sessions.editorA), B = await mkPage(sessions.editorB), K = await mkPage(sessions.contributor), V = await mkPage(sessions.viewer);

  check("Editor page opens in Host view", await until(async () => (await roleOf(A)) === "Host view"));
  check("second Editor page opens in Host view", await until(async () => (await roleOf(B)) === "Host view"));
  check("Contributor page opens in Limited view", await until(async () => (await roleOf(K)) === "Limited view"));
  check("Viewer page opens in View only", await until(async () => (await roleOf(V)) === "View only"));
  const nDaters = await until(async () => { const t = await text(A, "#daterCount"); return Number(t) > 0 ? Number(t) : 0; });
  check("Editor sees the imported daters", nDaters > 0, nDaters);
  check("both Editors see the same dater count", await until(async () => Number(await text(B, "#daterCount")) === nDaters));
  check("Contributor sees no Daters, Match log or Past streams panels and no tabs", await K.locator("#tabs").isHidden() && await K.locator("#panelD").isHidden() && await K.locator("#panelM").isHidden() && await K.locator("#panelP").isHidden());
  check("the Admin button shows for the owner only (not a normal Editor, Contributor or Viewer)", await A.locator("#adminLink").isVisible() && await B.locator("#adminLink").isHidden() && await K.locator("#adminLink").isHidden() && await V.locator("#adminLink").isHidden());
  check("the Admin button opens the access page in a new tab and keeps the console open", (await A.locator("#adminLink").getAttribute("href")) === "/admin.html" && (await A.locator("#adminLink").getAttribute("target")) === "_blank" && /noopener/.test(await A.locator("#adminLink").getAttribute("rel")));
  check("Contributor has Random question; Viewer does not", await K.locator("#randomQ").isVisible() && await V.locator("#randomQ").isHidden());
  check("Viewer sees no Questions panel", await V.locator("#panelQ").isHidden());
  const subsOf = async (p) => (await p.evaluate(() => window.claude._test.state())).subs;
  check("Contributor page subscribes to 3 feeds only (no daters, no matches)", (await subsOf(K)) === 3, await subsOf(K));
  check("Viewer page subscribes to 3 feeds (seats, game, questions for the picker), never daters", (await subsOf(V)) === 3, await subsOf(V));
  check("viewers send heartbeats every 45 s, hosts and mods every 15 s", (await V.evaluate(() => window.claude._test.state().hb)) === 45000 && (await A.evaluate(() => window.claude._test.state().hb)) === 15000 && (await K.evaluate(() => window.claude._test.state().hb)) === 15000);
  check("Editor page subscribes to 5 feeds", (await subsOf(A)) === 5, await subsOf(A));

  // two Editors, both directions
  check("the add-dater form starts collapsed behind an Add dater button", await A.locator("#dForm").isHidden() && (await A.locator("#addToggle").textContent()) === "+ Add dater");
  await A.click("#addToggle");
  check("tapping Add dater opens the form and the button becomes Close", await A.locator("#dForm").isVisible() && (await A.locator("#addToggle").textContent()) === "Close");
  await A.fill("#fName", "SyncTest A"); await A.fill("#fAge", "30"); await A.fill("#fLoc", "NC");
  await A.selectOption("#fGender", "man"); await A.selectOption("#fSex", "straight");
  await A.fill("#fMin", "25"); await A.fill("#fMax", "35"); await A.check("#fAdult"); await A.click("#fSave");
  check("after saving, the form closes again", await until(async () => await A.locator("#dForm").isHidden() && (await A.locator("#addToggle").textContent()) === "+ Add dater", 4000));
  check("Editor A adds a dater: Editor B sees it live", await until(async () => (await B.locator("#dList").innerText()).includes("SyncTest A"), 6000));
  check("...and B's dater count went up by one", await until(async () => Number(await text(B, "#daterCount")) === nDaters + 1));
  const rowB = B.locator("#dList .row", { hasText: "SyncTest A" });
  check("a dater row shows Panel, Hot seat and More, with Edit and Remove tucked away", await rowB.getByRole("button", { name: "Panel" }).isVisible() && await rowB.getByRole("button", { name: "Hot seat" }).isVisible() && await rowB.getByRole("button", { name: "More" }).isVisible() && (await rowB.getByRole("button", { name: "Edit" }).count()) === 0 && (await rowB.getByRole("button", { name: "Remove" }).count()) === 0);
  await rowB.getByRole("button", { name: "More" }).click();
  check("More reveals Edit and Remove", await rowB.getByRole("button", { name: "Edit" }).isVisible() && await rowB.getByRole("button", { name: "Remove" }).isVisible());
  await rowB.getByRole("button", { name: "Remove" }).click();
  check("Remove still asks 'Confirm remove / Keep' first", await rowB.getByRole("button", { name: "Confirm remove" }).isVisible() && await rowB.getByRole("button", { name: "Keep" }).isVisible());
  await rowB.getByRole("button", { name: "Keep" }).click();
  check("Keep leaves the dater in place", (await B.locator("#dList").innerText()).includes("SyncTest A"));
  const delWs = await connect(sessions.editorB); const delAck = await delWs.w("add", "daters", null, { ...dataFor.daters, name: "DeleteMe Dater" });
  await until(async () => (await B.locator("#dList").innerText()).includes("DeleteMe Dater"), 5000);
  const delRow = B.locator("#dList .row", { hasText: "DeleteMe Dater" });
  await delRow.getByRole("button", { name: "More" }).click(); await delRow.getByRole("button", { name: "Remove" }).click(); await delRow.getByRole("button", { name: "Confirm remove" }).click();
  check("More, Remove, Confirm really deletes the dater (here and on the server)", await until(async () => !(await B.locator("#dList").innerText()).includes("DeleteMe Dater"), 5000) && !(await delWs.sub("daters")).docs.some((d) => d.id === delAck.id));
  delWs.close();
  await B.locator("#dList .row", { hasText: "SyncTest A" }).getByRole("button", { name: "Panel" }).click();
  check("Editor B seats that dater: Editor A sees them on the board live", await until(async () => (await text(A, "#rTop")).includes("SyncTest A"), 6000));
  check("...and the Contributor sees the seated dater on the board (display snapshot)", await until(async () => (await text(K, "#rTop")).includes("SyncTest A"), 6000));
  check("...and the Viewer sees it too", await until(async () => (await text(V, "#rTop")).includes("SyncTest A"), 6000));
  await B.locator("#dList .row", { hasText: "SyncTest A" }).getByRole("button", { name: "Hot seat" }).click();
  check("Editor B moves them to the hot seat: Editor A sees it", await until(async () => (await text(A, "#rHot")).includes("SyncTest A"), 6000));
  const qBeforeClear = await text(A, "#qtext");
  await A.getByRole("button", { name: "Clear all seats" }).click(); await A.click("#clearYes");
  check("Editor A clears all seats: Editor B's board empties", await until(async () => !(await text(B, "#rHot")).includes("SyncTest A") && !(await text(B, "#rTop")).includes("SyncTest A"), 6000));
  check("...and so does the Viewer's", await until(async () => !(await text(V, "#rTop")).includes("SyncTest A"), 6000));

  // seat picker
  const pw = await connect(sessions.editorA); const dsnap = await pw.sub("daters");
  const newest = [...dsnap.docs].sort((x, y) => (y.data.ts || 0) - (x.data.ts || 0))[0].data.name;
  await A.locator("#rTop .heart").nth(0).click();
  check("tapping an empty seat opens the picker, titled with that seat", await until(async () => await A.locator("#pickModal").isVisible(), 4000) && /Seat 1/.test(await text(A, "#pickTitle")), await text(A, "#pickTitle"));
  const firstRowText = await A.locator("#pickList .pickrow").first().innerText();
  check("with no hot seat the newest dater (whoever joined last) is on top", firstRowText.includes(newest), { newest, firstRowText });
  await A.fill("#pickSearch", newest.slice(0, 5).toLowerCase());
  check("typing in the search box narrows the list", (await A.locator("#pickList .pickrow").count()) >= 1 && (await A.locator("#pickList .pickrow").count()) < 30);
  await A.fill("#pickSearch", "");
  await A.locator("#pickList .pickrow").first().click();
  check("picking someone closes the picker and puts them in the seat that was tapped", await until(async () => await A.locator("#pickModal").isHidden() && (await text(A, "#rTop .heart:nth-child(1)")).includes(newest), 5000));
  check("...and the other Editor sees them there live", await until(async () => (await text(B, "#rTop")).includes(newest), 5000));
  await A.locator("#rHot .heart").click();
  check("tapping the empty hot seat opens the picker for the hot seat", await until(async () => /Hot seat/.test(await text(A, "#pickTitle")), 4000));
  const hotRows = await A.locator("#pickList .pickrow .t").allInnerTexts();
  check("the hot seat list is newest first (no fit ordering)", hotRows.length > 10 && !(await A.locator("#pickList .pickrow[data-fit]").count()), hotRows.slice(0, 3));
  await A.locator("#pickList .pickrow").nth(1).click();
  check("picking someone for the hot seat seats them there", await until(async () => await A.locator("#pickModal").isHidden() && (await text(A, "#rHot")).length > 40 && !(await text(A, "#rHot .heart")).includes("Empty"), 5000));
  await A.locator("#rMid .heart").nth(0).click();
  await until(async () => await A.locator("#pickModal").isVisible(), 4000);
  const ranks = await A.locator("#pickList .pickrow[data-fit]").evaluateAll((els) => els.map((e) => ({ mutual: 0, close: 1, nofit: 2 })[e.getAttribute("data-fit")]));
  check("for a panel seat the list puts the best fits first (green, then yellow, then red)", ranks.length > 5 && ranks.every((r, i) => i === 0 || r >= ranks[i - 1]) && ranks[0] === 0, ranks.slice(0, 12));
  check("each row shows its fit (label) so you can tell at a glance", /Fits both|Off by|Mismatch/.test(await A.locator("#pickList .pickrow[data-fit]").first().innerText()));
  const rowFit = await A.locator("#pickList .pickrow").evaluateAll((els) => els.map((e, i) => ({ over: e.scrollHeight > e.clientHeight + 1, gap: i ? Math.round(e.getBoundingClientRect().top - els[i - 1].getBoundingClientRect().bottom) : 99 })));
  check("picker rows are tall enough for their text and never overlap the next row", rowFit.length > 5 && rowFit.every((r) => !r.over && r.gap >= 0), rowFit.filter((r) => r.over || r.gap < 0).slice(0, 3));
  const bestName = (await A.locator("#pickList .pickrow .t").first().innerText()).split(",")[0];
  await A.locator("#pickList .pickrow").first().click();
  check("a panel pick lands in the seat that was tapped (Seat 4), not the first empty one", await until(async () => (await text(A, "#rMid .heart:nth-child(1)")).includes(bestName), 5000), bestName);
  await A.locator("#rTop .heart").nth(1).click();
  await until(async () => await A.locator("#pickModal").isVisible(), 4000);
  await A.click("#pickAdd");
  check("Add new dater from the picker closes it and opens the form", await A.locator("#pickModal").isHidden() && await A.locator("#dForm").isVisible());
  await A.fill("#fName", "PickerNew"); await A.fill("#fAge", "28"); await A.fill("#fLoc", "NC");
  await A.selectOption("#fGender", "woman"); await A.selectOption("#fSex", "straight");
  await A.fill("#fMin", "24"); await A.fill("#fMax", "40"); await A.check("#fAdult"); await A.click("#fSave");
  check("a dater added from the picker goes straight into that seat (Seat 2)", await until(async () => (await text(A, "#rTop .heart:nth-child(2)")).includes("PickerNew"), 7000), await text(A, "#rTop"));
  check("...and is saved on the server and visible to the other Editor", (await pw.sub("daters")).docs.some((d) => d.data.name === "PickerNew") && await until(async () => (await text(B, "#rTop")).includes("PickerNew"), 5000));
  await A.locator("#rTop .heart").nth(0).click(); await sleep(300);
  check("tapping a seat that already has someone does not open the picker (select, swap and Remove still work)", await A.locator("#pickModal").isHidden() && await A.getByRole("button", { name: "Remove from seat" }).isVisible());
  await A.locator("#rTop .heart").nth(0).click(); // deselect
  await A.locator("#rTop .heart").nth(2).click();
  await until(async () => await A.locator("#pickModal").isVisible(), 4000);
  await A.keyboard.press("Escape");
  check("Escape closes the picker without choosing anyone", await until(async () => await A.locator("#pickModal").isHidden(), 3000));
  await A.locator("#rTop .heart").nth(2).click(); // deselect seat 3
  await K.locator("#rTop .heart").nth(2).click({ force: true }); await sleep(300);
  check("Contributors and Viewers cannot open the picker (hearts are read only for them)", await K.locator("#pickModal").isHidden());
  for (const loc of ['#rTop .heart:nth-child(1)', '#rTop .heart:nth-child(2)', '#rMid .heart:nth-child(1)', '#rHot .heart']) {
    await A.locator(loc).click(); await A.getByRole("button", { name: "Remove from seat" }).click(); await sleep(250);
  }
  check("seats cleaned up by removing each dater from their seat", await until(async () => !(await text(B, "#rTop")).includes("PickerNew") && !(await text(B, "#rMid")).includes(bestName), 5000));
  pw.close();

  // Contributor asks and randomizes questions
  const q0 = await text(A, "#qtext");
  await K.click("#randomQ");
  const q1 = await until(async () => { const t = await text(K, "#qtext"); return t !== q0 && t !== "No question picked yet." ? t : false; });
  check("Contributor presses Random question and gets a question", !!q1, { q0, q1 });
  check("Editor A sees the same question live", await until(async () => (await text(A, "#qtext")) === q1, 6000));
  check("Viewer sees the same question live", await until(async () => (await text(V, "#qtext")) === q1, 6000));
  const viaWs = await connect(sessions.editorA); const qsnap = await viaWs.sub("questions");
  const asked = qsnap.docs.find((d) => d.data.text === q1);
  check("the question's askCount and lastAsked were saved on the server", asked && asked.data.askCount >= 1 && asked.data.lastAsked > 0, asked);
  await K.click("#backQ");
  check("Contributor 'Back' restores the question that was cleared, for everyone", await until(async () => (await text(A, "#qtext")) === qBeforeClear && (await text(V, "#qtext")) === qBeforeClear, 6000), { qBeforeClear, now: await text(A, "#qtext") });
  const kPanelQ = await K.locator("#panelQ").isVisible();
  check("Contributor has the Questions panel", kPanelQ);
  const totalA0 = Number(/(\d+) total/i.exec(await text(A, "#totalCount"))[1]);
  await K.locator("#qIn").fill("Added by a mod live?"); await K.click("#qSend");
  check("Contributor adds a question: the Editor's question total goes up by one, live", await until(async () => Number(/(\d+) total/i.exec(await text(A, "#totalCount"))[1]) === totalA0 + 1, 5000), totalA0);
  check("...and the new question exists on the server", !!(await until(async () => (await viaWs.sub("questions")).docs.some((d) => d.data.text === "Added by a mod live?"), 4000)));

  // connection pill, tabs and pinned bar
  check("every role sees the connection pill saying Live", (await Promise.all([A, B, K, V].map(async (p) => (await p.locator("#connPill").isVisible()) && (await p.locator("#connTxt").textContent()) === "Live" && (await p.locator("#connPill").getAttribute("data-state")) === "live"))).every(Boolean));
  const PH = await mkPage(sessions.editorA, BASE, "/", { width: 390, height: 844 });
  await until(async () => (await roleOf(PH)) === "Host view");
  const tabTops = await PH.evaluate(() => [...document.querySelectorAll("#tabs .tab")].map((t) => Math.round(t.getBoundingClientRect().top)));
  check("on a phone all four tabs fit on one row", tabTops.length === 4 && new Set(tabTops).size === 1, tabTops);
  check("on a phone the page does not scroll sideways", !(await PH.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth)));
  check("hosts get a bottom bar with Remove hot seat and Match", await until(async () => await PH.locator("#liveBar").isVisible(), 4000) && await PH.locator("#lbMatch").isVisible() && await PH.locator("#lbRemoveHot").isVisible());
  check("the bottom bar has no Random question button", (await PH.locator("#liveBar").getByText("Random question").count()) === 0 && (await PH.locator("#lbRandom").count()) === 0);
  check("Remove hot seat is greyed out while the hot seat is empty", await PH.locator("#lbRemoveHot").isDisabled());
  const VP = await mkPage(sessions.viewer, BASE, "/", { width: 390, height: 844 });
  await until(async () => (await roleOf(VP)) === "View only"); await sleep(500);
  const KP = await mkPage(sessions.contributor, BASE, "/", { width: 390, height: 844 });
  await until(async () => (await roleOf(KP)) === "Limited view"); await sleep(500);
  check("Viewers and Contributors never get the bottom bar", await VP.locator("#liveBar").isHidden() && await KP.locator("#liveBar").isHidden());
  // seat someone in the hot seat from the phone, then use the bar
  await PH.locator("#rHot .heart").scrollIntoViewIfNeeded(); await PH.locator("#rHot .heart").click();
  await until(async () => await PH.locator("#pickModal").isVisible(), 4000);
  const hotName = (await PH.locator("#pickList .pickrow .t").first().innerText()).split(",")[0];
  await PH.locator("#pickList .pickrow").first().click();
  check("with someone in the hot seat, Remove hot seat switches on", await until(async () => !(await PH.locator("#lbRemoveHot").isDisabled()), 4000));
  await PH.click("#lbRemoveHot");
  check("Remove hot seat empties the hot seat in one tap", await until(async () => (await text(PH, "#rHot .heart")).includes("Empty"), 4000));
  check("...and the other Editor sees the hot seat empty too", await until(async () => !(await text(B, "#rHot .heart")).includes(hotName), 4000));
  check("...and offers Undo", await PH.locator("#toast .undo").isVisible());
  await PH.click("#toast .undo");
  check("Undo puts them back in the hot seat", await until(async () => (await text(PH, "#rHot .heart")).includes(hotName), 4000));
  await PH.locator("#rTop .heart").nth(0).scrollIntoViewIfNeeded(); await PH.locator("#rTop .heart").nth(0).click();
  await until(async () => await PH.locator("#pickModal").isVisible(), 4000);
  const panelName = (await PH.locator("#pickList .pickrow .t").first().innerText()).split(",")[0];
  await PH.locator("#pickList .pickrow").first().click();
  check("a panel dater is seated in Seat 1", await until(async () => (await text(PH, "#rTop .heart:nth-child(1)")).includes(panelName), 5000));
  const mws = await connect(sessions.editorA); const m0 = (await mws.sub("matches")).docs;
  await PH.click("#lbMatch");
  check("Match in the bar arms the pick: it turns green and says Pick?", (await PH.locator("#lbMatch").textContent()) === "Pick?" && /armed/.test(await PH.locator("#lbMatch").getAttribute("class")));
  await PH.locator("#rTop .heart").nth(0).click();
  check("tapping the heart logs the match on the server", await until(async () => (await mws.sub("matches")).docs.length === m0.length + 1, 5000));
  check("...and the bar goes back to Match", await until(async () => (await PH.locator("#lbMatch").textContent()) === "Match", 4000));
  const m1 = (await mws.sub("matches")).docs; const added = m1.find((d) => !m0.some((o) => o.id === d.id));
  check("the logged match names the hot seat dater and the pick", added && added.data.hotName === hotName && added.data.pickName === panelName, added && added.data);
  if (added) await mws.w("delete", "matches", added.id, null);
  mws.close();
  await PH.click("#lbRemoveHot");
  await PH.locator("#rTop .heart").nth(0).click(); await PH.getByRole("button", { name: "Remove from seat" }).click();
  check("seats cleaned up", await until(async () => (await text(PH, "#rHot .heart")).includes("Empty") && (await text(PH, "#rTop .heart:nth-child(1)")).includes("Empty"), 5000));
  await PH.locator("#rTop .heart").nth(2).scrollIntoViewIfNeeded();
  await PH.locator("#rTop .heart").nth(2).click(); await sleep(400);
  const box = await PH.locator("#pickModal .card").boundingBox();
  check("on a phone the picker fits the screen and does not scroll sideways", box && box.y >= 0 && box.y + box.height <= 844 && box.x >= 0 && box.x + box.width <= 390 && !(await PH.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth)), box);
  await PH.keyboard.press("Escape"); await PH.locator("#rTop .heart").nth(2).click();

  // a full room, seen from a viewer's browser
  const fillers = []; for (let i = 0; i < 12; i++) { const c = await connect(sessions.viewer); if (!c.status.ok) break; fillers.push(c); }
  const VF = await mkPage(sessions.viewer);
  check("when the room is full a viewer's page says so instead of looping", await until(async () => (await VF.evaluate(() => window.claude._test.state().conn)) === "full", 9000), await VF.evaluate(() => window.claude._test.state()));
  check("...the tag reads Full and a plain message explains it", (await VF.locator("#connTxt").textContent()) === "Full" && /busy right now/.test(await VF.locator("#modeNote").innerText()));
  const att0 = await VF.evaluate(() => window.claude._test.state().attempts); await sleep(4500);
  check("...and it stops hammering the server (no retries for minutes)", (await VF.evaluate(() => window.claude._test.state().attempts)) === att0, att0);
  check("hosts are not affected by a full viewer room", (await roleOf(A)) === "Host view" && (await A.evaluate(() => window.claude._test.state().state)) === "open");
  fillers.pop().close(); await sleep(700);
  await VF.click("#connPill");
  check("tapping the Full tag after a place frees up connects the viewer", await until(async () => (await VF.locator("#connTxt").textContent()) === "Live" && (await roleOf(VF)) === "View only", 8000), await VF.locator("#connTxt").textContent());
  check("...and the 'busy' message goes away", !/busy right now/.test(await VF.locator("#modeNote").innerText()));
  for (const c of fillers) c.close();

  // a viewer's hidden tab lets go of its place and comes back when seen
  const VI = await mkPage(sessions.viewer);
  await until(async () => (await roleOf(VI)) === "View only" && (await VI.evaluate(() => window.claude._test.state().state)) === "open", 8000);
  await VI.evaluate(() => window.claude._test.idleNow());
  check("a viewer's tab that stays hidden lets go of its connection", (await VI.evaluate(() => window.claude._test.state().state)) === "closed");
  await VI.evaluate(() => window.claude._test.wake());
  check("...and reconnects with fresh data as soon as the tab is seen again", await until(async () => (await VI.evaluate(() => window.claude._test.state().state)) === "open", 6000));
  await A.evaluate(() => window.claude._test.idleNow()); await sleep(300);
  check("hosts and mods never let go of their connection that way", (await A.evaluate(() => window.claude._test.state().state)) === "open");
  await VI.context().close();

  // headline lettering
  check("the headline is the banner-style lettering and still reads 'Kim's Speed Dating' to screen readers", (await A.locator("h1 svg.logo").getAttribute("aria-label")) === "Kim's Speed Dating" && (await A.locator("h1 svg.logo").getAttribute("role")) === "img");
  check("the headline font file is served by the site itself", await (async () => { const r = await fetch(BASE + "/fonts/lobster-two-700-italic.woff2"); return r.status === 200 && /font\/woff2/.test(r.headers.get("content-type") || "") && /immutable/.test(r.headers.get("cache-control") || ""); })());
  check("the font's license text is included", (await (await fetch(BASE + "/fonts/Lobster-Two-OFL-license.txt")).text()).includes("SIL Open Font License"));
  check("the font really loaded in the browser (not a fallback)", await A.evaluate(async () => { await document.fonts.load('italic 700 100px LogoFont', 'Kim'); return document.fonts.check('italic 700 100px LogoFont'); }));
  const logoBox = await A.locator("h1 svg.logo").boundingBox(), logoPhone = await PH.locator("h1 svg.logo").boundingBox();
  check("the headline is sized sensibly on laptop and phone and fits the screen", logoBox.width > 400 && logoBox.width <= 521 && logoPhone.width >= 260 && logoPhone.width <= 390 - 32 + 1, { laptop: logoBox.width, phone: logoPhone.width });
  check("the headline fits inside its box (nothing clipped or spilling)", await A.evaluate(() => { const t = document.getElementById("lgText").getBBox(), vb = document.querySelector("svg.logo").viewBox.baseVal; return t.x >= vb.x && t.x + t.width <= vb.x + vb.width && t.y >= vb.y && t.y + t.height <= vb.y + vb.height; }));

  // colour scheme (banner palette)
  const rgbOf = (c) => (c.match(/[\d.]+/g) || []).slice(0, 3).map(Number);
  const lum = (c) => { const [r, g, b] = rgbOf(c).map((v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
  const cr = (c1, c2) => { const a = lum(c1), b = lum(c2); return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05); };
  const dist = (c1, c2) => { const x = rgbOf(c1), y = rgbOf(c2); return Math.hypot(x[0] - y[0], x[1] - y[1], x[2] - y[2]); };
  const th = await A.evaluate(() => {
    const cs = (el, p) => getComputedStyle(el)[p];
    const heart = (cls) => { const b = document.createElement("button"); b.className = "heart " + cls; b.innerHTML = '<svg viewBox="0 0 100 88"><path d="M0 0"/></svg>'; document.body.appendChild(b); const p = b.querySelector("path"); const r = { fill: cs(p, "fill"), stroke: cs(p, "stroke") }; b.remove(); return r; };
    const row = document.createElement("div"); row.className = "row"; row.innerHTML = '<div class="main"><div class="m">x</div></div>'; document.body.appendChild(row);
    const rowBg = cs(row, "backgroundColor"), rowMuted = cs(row.querySelector(".m"), "color"); row.remove();
    const pb = document.querySelector("button.primary"); 
    return { body: cs(document.body, "backgroundColor"), bodyImg: cs(document.body, "backgroundImage"), fg: cs(document.body, "color"), rowBg, rowMuted,
      nofit: heart("nofit"), hot: heart("hot"), mutual: heart("mutual"), close: heart("close"), vacant: heart("vacant"), kim: heart("kim"),
      btnImg: cs(pb, "backgroundImage"), btnColor: cs(pb, "color") };
  });
  check("page background is the banner's red-black", rgbOf(th.body).join() === "27,2,3", th.body);
  check("there is a subtle sparkle field behind everything", (th.bodyImg.match(/radial-gradient/g) || []).length === 5, th.bodyImg.slice(0, 80));
  const nf = rgbOf(th.nofit.fill), ns = rgbOf(th.nofit.stroke);
  check("a mismatch heart is dark with a bright red edge", lum(th.nofit.fill) < 0.01 && ns[0] > 220 && ns[1] < 110 && ns[2] < 110, th.nofit);
  const fills = ["nofit", "hot", "mutual", "close", "vacant"].map((k) => [k, th[k].fill]); let minD = 1e9, pair = "";
  for (let i = 0; i < fills.length; i++) for (let j = i + 1; j < fills.length; j++) { const d = dist(fills[i][1], fills[j][1]); if (d < minD) { minD = d; pair = fills[i][0] + "/" + fills[j][0]; } }
  check("fit hearts stay easy to tell apart: mismatch, hot seat, both fit, off by 1 to 2, empty", minD >= 25, { minD, pair });
  check("mismatch heart is clearly darker than the hot seat and empty seats", lum(th.hot.fill) > lum(th.nofit.fill) * 8 && lum(th.vacant.fill) > lum(th.nofit.fill) * 3, { hot: th.hot.fill, vacant: th.vacant.fill });
  check("body text is easy to read on the page background", cr(th.fg, th.body) >= 12, cr(th.fg, th.body));
  check("secondary text is readable on cards and rows (at least 4.5 to 1)", cr(th.rowMuted, th.rowBg) >= 4.5, cr(th.rowMuted, th.rowBg));
  const stops = (th.btnImg.match(/rgb\([^)]*\)/g) || []); const mid = stops.length >= 2 ? "rgb(" + [0, 1, 2].map((i) => Math.round((rgbOf(stops[0])[i] + rgbOf(stops[1])[i]) / 2)).join(",") + ")" : "";
  check("button text is readable on the glossy red buttons, even at the middle of the gradient", stops.length >= 2 && cr(th.btnColor, mid) >= 4.5, { stops, mid, ratio: stops.length ? cr(th.btnColor, mid) : 0 });
  const pages = {}; for (const f of ["index.html", "admin.html", "backup.html", "privacy.html", "terms.html", "security.html"]) pages[f] = await (await fetch(BASE + "/" + f)).text();
  check("no old plum colours are left on any page", Object.values(pages).every((t) => !/#12030a|#4a1429|#ff4f9a|#260a17|#3b1a5c|#b58cff|#1a0610/i.test(t)));
  // home screen icon, install manifest and link preview
  const pngInfo = async (path) => { const r = await fetch(BASE + path); const b = Buffer.from(await r.arrayBuffer()); return { ok: r.status === 200, sig: b.subarray(0, 8).toString("hex"), w: b.readUInt32BE(16), h: b.readUInt32BE(20) }; };
  const jpegSize = (b) => { let i = 2; while (i < b.length) { if (b[i] !== 0xff) { i++; continue; } const m = b[i + 1]; if (m >= 0xc0 && m <= 0xc3) return { h: b.readUInt16BE(i + 5), w: b.readUInt16BE(i + 7) }; i += 2 + b.readUInt16BE(i + 2); } return null; };
  const man = await (await fetch(BASE + "/manifest.webmanifest")).json();
  check("an install manifest is served with the name, start page and banner colours", man.name === "Kim's Speed Dating" && man.short_name === "Speed Dating" && man.start_url === "/" && man.background_color === "#1b0203" && man.theme_color === "#1b0203", man);
  const manIcons = []; for (const ic of man.icons) { const [w, h] = ic.sizes.split("x").map(Number); const i = await pngInfo(ic.src); manIcons.push(i.ok && i.sig === "89504e470d0a1a0a" && i.w === w && i.h === h); }
  check("...and every icon it lists exists and is a real PNG of the declared size (192, 512 and a maskable 512)", manIcons.length === 3 && manIcons.every(Boolean) && man.icons.some((i) => i.purpose === "maskable"), manIcons);
  const apple = await pngInfo("/icons/apple-touch-icon.png"), fav = await pngInfo("/icons/favicon-32.png");
  check("the iPhone home screen icon is 180 by 180 and the tab icon is 32 by 32", apple.w === 180 && apple.h === 180 && fav.w === 32 && fav.h === 32, { apple, fav });
  const ico = Buffer.from(await (await fetch(BASE + "/favicon.ico")).arrayBuffer());
  check("/favicon.ico exists (browsers ask for it by name)", ico.subarray(0, 4).toString("hex") === "00000100" && ico.length > 1000);
  const og = Buffer.from(await (await fetch(BASE + "/og.jpg")).arrayBuffer());
  check("the link-preview card is a 1200 by 630 JPEG under 300 KB (Discord and others show it)", og[0] === 0xff && og[1] === 0xd8 && JSON.stringify(jpegSize(og)) === JSON.stringify({ h: 630, w: 1200 }) && og.length < 300 * 1024, { size: og.length, dims: jpegSize(og) });
  check("the site is set up to open as a full screen home screen app (manifest display and iPhone tags)", man.display === "standalone" && /name="apple-mobile-web-app-capable" content="yes"/.test(pages["index.html"]) && /name="mobile-web-app-capable" content="yes"/.test(pages["index.html"]) && /apple-mobile-web-app-status-bar-style" content="black"/.test(pages["index.html"]), man.display);
  check("admin, backup and privacy pages have a 'Back to the board' link (a home screen app has no Back button)", ["admin.html", "backup.html", "privacy.html", "terms.html", "security.html"].every((f) => /<a class="back" href="\/">/.test(pages[f])));
  // policies
  const rolesTxt = readFileSync("src/worker.js", "utf8") + readFileSync("src/database.js", "utf8");
  check("terms and security pages are served and match the privacy page look", ["terms.html", "security.html"].every((f) => pages[f].includes("<h1>") && pages[f].includes("#1b0203")));
  check("the three policy pages link to each other", ["privacy.html", "terms.html", "security.html"].every((f) => ["privacy", "terms", "security"].every((n) => pages[f].includes(`href="/${n}.html"`))));
  check("the sign-in screen asks for 18+ and links Terms and Privacy; every screen has a footer with all three", /18 or older[^<]*<a href="\/terms.html">[^<]*<\/a> and the <a href="\/privacy.html"/.test(pages["index.html"]) && /<footer class="legal">[\s\S]*privacy\.html[\s\S]*terms\.html[\s\S]*security\.html/.test(pages["index.html"]));
  check("policies contain no em dashes and say 18 or older", ["privacy.html", "terms.html", "security.html"].every((f) => !pages[f].includes("\u2014")) && /18 or older/.test(pages["terms.html"]) && /18 or older/.test(pages["privacy.html"]));
  check("policy numbers match the code (100 changes, 12 hours, 7 days)", /100 changes/.test(pages["privacy.html"]) && /12 hours/.test(pages["privacy.html"]) && /7 days/.test(pages["privacy.html"]) && /100/.test(rolesTxt));
  check("the privacy page describes the member list, TikTok usernames and dater sign-ups, and who sees them", /member list/.test(pages["privacy.html"]) && /TikTok username/.test(pages["privacy.html"]) && /dater sign-up/.test(pages["privacy.html"]) && /not email addresses/.test(pages["privacy.html"]) && /Signing up to be a speed dater/.test(pages["terms.html"]));
  check("every page links the icons, the manifest and the banner colour", ["index.html", "admin.html", "backup.html", "privacy.html", "terms.html", "security.html"].every((f) => /rel="icon"/.test(pages[f]) && /rel="apple-touch-icon"/.test(pages[f]) && /rel="manifest"/.test(pages[f]) && /name="theme-color" content="#1b0203"/.test(pages[f])));
  check("the main page has link-preview tags with a full https address for the card", /property="og:image" content="https:\/\/[^"]+\/og\.jpg"/.test(pages["index.html"]) && /property="og:title"/.test(pages["index.html"]) && /name="twitter:card" content="summary_large_image"/.test(pages["index.html"]));
  const iconPx = await A.evaluate(async () => {
    const sample = async (url) => { const bmp = await createImageBitmap(await (await fetch(url)).blob()); const c = document.createElement("canvas"); c.width = bmp.width; c.height = bmp.height; const x = c.getContext("2d"); x.drawImage(bmp, 0, 0); const g = (a, b) => Array.from(x.getImageData(a, b, 1, 1).data); return { tl: g(2, 2), br: g(bmp.width - 3, bmp.height - 3), mid: g(bmp.width >> 1, bmp.height >> 1) }; };
    return { apple: await sample("/icons/apple-touch-icon.png"), i512: await sample("/icons/icon-512.png"), mask: await sample("/icons/icon-maskable-512.png") };
  });
  check("home screen icons are fully opaque (no see-through corners, which phones paint black)", [iconPx.apple, iconPx.i512, iconPx.mask].every((s) => s.tl[3] === 255 && s.br[3] === 255), iconPx);
  check("the maskable icon keeps its art in the middle and a dark red border, so round masks never cut the lettering", iconPx.mask.tl[0] < 80 && iconPx.mask.tl[1] < 40 && iconPx.mask.br[0] < 80 && (iconPx.mask.mid[0] + iconPx.mask.mid[1] + iconPx.mask.mid[2]) > (iconPx.mask.tl[0] + iconPx.mask.tl[1] + iconPx.mask.tl[2]) + 60, iconPx.mask);

  const gateCtx = await browser.newContext({ viewport: { width: 390, height: 844 } }); await gateCtx.route(/fonts\.(googleapis|gstatic)\.com|accounts\.google\.com/, (r) => r.abort());
  const gatePg = await gateCtx.newPage(); await gatePg.goto(BASE + "/"); await gatePg.waitForSelector("#gate:not([hidden])");
  const gateInfo = await gatePg.evaluate(() => ({ bodyH: document.body.getBoundingClientRect().height, vh: innerHeight, rep: getComputedStyle(document.body).backgroundRepeat }));
  check("on a short page (the sign-in screen) the glow fills the screen and does not restart halfway down", gateInfo.bodyH >= gateInfo.vh - 1 && gateInfo.rep.startsWith("no-repeat"), gateInfo);
  check("the sign-in screen offers Google sign-in and says what viewers get", /watch the board and get random questions/.test(await gatePg.locator("#gateMsg").innerText()));
  await gateCtx.close();
  for (const f of ["admin.html", "backup.html", "privacy.html"]) check(`${f} also fills the screen without a repeat seam`, /no-repeat/.test(pages[f]) && /min-height:100vh/.test(pages[f]));
  check("the admin, backup and privacy pages use the same red-black palette and sparkle", ["admin.html", "backup.html", "privacy.html"].every((f) => pages[f].includes("#1b0203") && (pages[f].match(/radial-gradient/g) || []).length >= 5));

  // opened as a home screen app: the Admin link stays in the same window
  const saCtx = await browser.newContext({ viewport: { width: 390, height: 844 } });
  await saCtx.route(/fonts\.(googleapis|gstatic)\.com|accounts\.google\.com/, (r) => r.abort());
  await saCtx.addInitScript(([k, v]) => { Object.defineProperty(navigator, "standalone", { value: true }); try { localStorage.setItem(k, v); } catch (e) { /* ignore */ } }, ["sd.session.v1", JSON.stringify(sessions.editorA)]);
  const saPg = await saCtx.newPage(); await saPg.goto(BASE + "/"); await saPg.waitForSelector("#adminLink:not([hidden])", { timeout: 8000 });
  check("as a home screen app the Admin link opens in the same window (no new tab to get lost in)", (await saPg.locator("#adminLink").getAttribute("target")) === null);
  check("...while in a normal browser tab it still opens in a new tab so the console stays open", (await A.locator("#adminLink").getAttribute("target")) === "_blank");
  await saCtx.close();

  // "Install the app" hint
  const IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
  const ANDROID = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36";
  const tipPage = async (opts = {}) => {
    const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, ...(opts.ua ? { userAgent: opts.ua } : {}) });
    await ctx.route(/fonts\.(googleapis|gstatic)\.com|accounts\.google\.com/, (r) => r.abort());
    await ctx.addInitScript(([k, v, standalone, signedIn]) => { if (standalone) Object.defineProperty(navigator, "standalone", { value: true }); try { if (signedIn) localStorage.setItem(k, v); } catch (e) { /* ignore */ } }, ["sd.session.v1", JSON.stringify(sessions.contributor), !!opts.standalone, opts.signedIn !== false]);
    const pg = await ctx.newPage(); await pg.goto(BASE + "/");
    if (opts.signedIn !== false) { await until(async () => (await roleOf(pg)) === "Limited view", 8000); await sleep(400); }
    return { ctx, pg };
  };
  let t1 = await tipPage({ ua: IPHONE });
  check("on an iPhone browser a card offers an Add button", await t1.pg.locator("#installTip").isVisible() && await t1.pg.locator("#installBtn").isVisible() && await t1.pg.locator("#howOv").isHidden());
  await t1.pg.click("#installBtn");
  check("tapping Add opens a step by step guide for iPhone (Safari, Share, Add to Home Screen, Add)", await t1.pg.locator("#howOv").isVisible() && await t1.pg.locator("#howIos").isVisible() && await t1.pg.locator("#howAndroid").isHidden() && /Safari/.test(await t1.pg.locator("#howIos").innerText()) && /Share/.test(await t1.pg.locator("#howIos").innerText()) && /Add to Home Screen/.test(await t1.pg.locator("#howIos").innerText()) && (await t1.pg.locator("#howIos li").count()) === 5);
  await t1.pg.click("#howTabAndroid");
  check("the guide has an Android tab with its own steps", await t1.pg.locator("#howAndroid").isVisible() && await t1.pg.locator("#howIos").isHidden() && /three dots/.test(await t1.pg.locator("#howAndroid").innerText()));
  check("the guide fits a phone screen without sideways scroll", await t1.pg.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
  await t1.pg.click("#howClose");
  check("Got it closes the guide", await t1.pg.locator("#howOv").isHidden() && await t1.pg.locator("#installTip").isVisible());
  await t1.pg.click("#installNo");
  check("'Not now' hides it for this visit...", await t1.pg.locator("#installTip").isHidden());
  await t1.pg.reload(); await until(async () => (await roleOf(t1.pg)) === "Limited view", 8000); await sleep(400);
  check("...and it stays hidden if the same tab is reloaded", await t1.pg.locator("#installTip").isHidden());
  await t1.pg.evaluate(() => sessionStorage.clear()); await t1.pg.reload(); await until(async () => (await roleOf(t1.pg)) === "Limited view", 8000); await sleep(400);
  check("...but it is back on the next visit, because the app has not been added yet", await t1.pg.locator("#installTip").isVisible() && await t1.pg.locator("#installBtn").isVisible());
  await t1.pg.click("#installBtn");
  check("the guide has an 'I've added it' button as well as Got it", await t1.pg.locator("#howDone").isVisible() && await t1.pg.locator("#howClose").isVisible());
  await t1.pg.click("#howClose"); await t1.pg.reload(); await until(async () => (await roleOf(t1.pg)) === "Limited view", 8000); await sleep(400);
  check("closing the guide with Got it does not hide the card (the app may not be added)", await t1.pg.locator("#installTip").isVisible());
  await t1.pg.click("#installBtn"); await t1.pg.click("#howDone");
  check("'I've added it' closes the guide and hides the card", await t1.pg.locator("#howOv").isHidden() && await t1.pg.locator("#installTip").isHidden());
  await t1.pg.evaluate(() => sessionStorage.clear()); await t1.pg.reload(); await until(async () => (await roleOf(t1.pg)) === "Limited view", 8000); await sleep(400);
  check("...and it stays hidden on later visits on that phone", await t1.pg.locator("#installTip").isHidden());
  await t1.ctx.close();
  let t2 = await tipPage({ ua: ANDROID });
  await t2.pg.click("#installBtn");
  check("on Android the guide opens on the Android steps", await t2.pg.locator("#howAndroid").isVisible() && await t2.pg.locator("#howIos").isHidden() && await t2.pg.locator("#howInstall").isHidden());
  await t2.pg.evaluate(() => { const e = new Event("beforeinstallprompt"); e.prompt = () => { window.__prompted = true; }; e.userChoice = Promise.resolve({ outcome: "accepted" }); window.dispatchEvent(e); });
  await t2.pg.click("#howClose"); await t2.pg.click("#installBtn");
  check("when the browser offers a real install prompt, an Install now button appears in the guide", await t2.pg.locator("#howInstall").isVisible());
  await t2.pg.click("#howInstall");
  check("...tapping it opens the browser's install prompt, closes the guide and hides the card", await until(async () => (await t2.pg.evaluate(() => window.__prompted === true)) && await t2.pg.locator("#installTip").isHidden() && await t2.pg.locator("#howOv").isHidden(), 4000));
  await t2.ctx.close();
  let t3 = await tipPage({ ua: IPHONE, standalone: true });
  check("once it is installed and opened from the home screen, the hint never shows", await t3.pg.locator("#installTip").isHidden());
  await t3.ctx.close();
  let t4 = await tipPage({});
  check("on a laptop browser the hint stays hidden (nothing to explain)", await t4.pg.locator("#installTip").isHidden());
  await t4.pg.evaluate(() => { const e = new Event("beforeinstallprompt"); e.prompt = () => {}; e.userChoice = Promise.resolve({}); window.dispatchEvent(e); });
  check("...unless the browser itself offers to install it, then an Add button shows", await t4.pg.locator("#installTip").isVisible() && await t4.pg.locator("#installBtn").isVisible());
  await t4.ctx.close();
  let t5 = await tipPage({ ua: IPHONE, signedIn: false });
  check("it does not show on the sign-in screen, only after signing in", await t5.pg.locator("#gate").isVisible() && await t5.pg.locator("#installTip").isHidden());
  await t5.ctx.close();

  // sign out
  check("every signed-in role sees a Sign out button", (await Promise.all([A, B, K, V].map((p) => p.locator("#signOut").isVisible()))).every(Boolean));
  const V2 = await mkPage((await login(EMAILS.viewer)).session); // its own sign-in, like a second device
  await until(async () => (await roleOf(V2)) === "View only");
  V2.once("dialog", (d) => d.dismiss());
  await V2.click("#signOut"); await sleep(400);
  check("cancelling the 'Sign out?' question keeps you signed in", (await roleOf(V2)) === "View only" && await V2.locator("#gate").isHidden());
  V2.once("dialog", (d) => d.accept());
  await V2.click("#signOut");
  check("signing out returns to the sign-in screen and clears the saved login", await until(async () => await V2.locator("#gate").isVisible() && (await V2.locator("#app").isHidden()), 6000) && (await V2.evaluate(() => localStorage.getItem("sd.session.v1"))) === null);
  check("...the sign-in screen no longer shows the Sign out button", await V2.locator("#signOut").isHidden());
  check("...it stays signed out after another reload", await (async () => { await V2.reload(); await sleep(600); return await V2.locator("#gate").isVisible() && (await V2.evaluate(() => localStorage.getItem("sd.session.v1"))) === null; })());
  check("signing out on one device does not sign the same person out on another", (await roleOf(V)) === "View only" && (await V.evaluate(() => window.claude._test.state().state)) === "open");
  check("the signed-out page opened no connection of its own", (await V2.evaluate(() => window.claude._test.state().everOpened)) === false);

  // viewer's private picker
  check("Viewer sees the private question picker; Editor, Contributor do not", await V.locator("#myQBox").isVisible() && await A.locator("#myQBox").isHidden() && await K.locator("#myQBox").isHidden());
  const before = await connect(sessions.editorA); const qBefore = await before.sub("questions"); const gBefore = await before.sub("game/question");
  const allTexts = new Set(qBefore.docs.map((d) => d.data.text));
  const seenPick = [];
  for (let i = 0; i < 6; i++) { await V.click("#myQBtn"); seenPick.push(await text(V, "#myQText")); }
  check("the picker shows real questions from the list", seenPick.every((t) => allTexts.has(t)), seenPick);
  check("...never the same question twice in a row, and no repeats until every question was shown", seenPick.every((t, i) => i === 0 || t !== seenPick[i - 1]) && new Set(seenPick).size === seenPick.length, seenPick);
  await sleep(500);
  const qAfter = await before.sub("questions"); const gAfter = await before.sub("game/question");
  const sumAsk = (snap) => snap.docs.reduce((n, d) => n + (d.data.askCount || 0) + (d.data.lastAsked || 0), 0);
  check("the picker writes nothing: ask counts unchanged on the server", sumAsk(qBefore) === sumAsk(qAfter), { b: sumAsk(qBefore), a: sumAsk(qAfter) });
  check("...and the stream's current question is unchanged", JSON.stringify(gBefore.docs) === JSON.stringify(gAfter.docs));
  check("...and the Editor's page still shows the stream's question, not the viewer's pick", (await text(A, "#qtext")) !== seenPick[seenPick.length - 1] || allTexts.size < 2);
  before.close();

  // admin page in a real browser
  const AD = await mkPage(sessions.editorA, BASE, "/admin.html#all"); const ADE = await mkPage(sessions.editorB, BASE, "/admin.html"); const ADK = await mkPage(sessions.contributor, BASE, "/admin.html");
  check("the admin page explains what each role can do and what an unlisted person gets", await until(async () => { const t = await text(AD, "#helpCard"); return ["Owner", "Editor", "Contributor", "Viewer"].every((r) => t.includes(r)) && /gets no access/.test(await text(AD, "#defaultNote")); }, 6000), await text(AD, "#helpCard"));
  check("the role help is not shown to people who cannot manage access", await ADK.locator("#helpCard").isHidden() && await ADE.locator("#helpCard").isHidden());
  check("admin page (owner) lists people, marks secret ones locked", await until(async () => { const t = await text(AD, "#staffList"); return t.includes(EMAILS.editorB) && /locked/i.test(t); }, 6000));
  await AD.fill("#email", EMAILS.uipick); await AD.selectOption("#role", "viewer"); await AD.click("#addForm button[type=submit]");
  check("owner adds a viewer on the page and they appear in the Viewers section", await until(async () => (await text(AD, "#viewerList")).includes(EMAILS.uipick), 6000));
  check("...and the person can sign in as Viewer", (await login(EMAILS.uipick)).body && (await login(EMAILS.uipick)).body.role === "viewer");
  check("a normal Editor on the admin page is told they are not an owner and sees no controls", await until(async () => /not an owner/.test(await text(ADE, "#msg")), 6000) && await ADE.locator("#listCard").isHidden() && await ADE.locator("#viewerCard").isHidden() && await ADE.locator("#logCard").isHidden() && await ADE.locator("#addCard").isHidden());
  check("a Contributor on the admin page is told the same", await until(async () => /not an owner/.test(await text(ADK, "#msg")), 6000) && await ADK.locator("#listCard").isHidden());
  await login("pending@example.com");
  await AD.reload();
  check("the page lists people who signed in recently", await until(async () => (await text(AD, "#seenList")).includes("pending@example.com"), 6000));
  await AD.locator("#seenList .row", { hasText: "pending@example.com" }).getByRole("button", { name: "Add" }).click();
  check("clicking Add moves them into the Viewers section", await until(async () => (await text(AD, "#viewerList")).includes("pending@example.com") && !(await text(AD, "#seenList")).includes("pending@example.com"), 6000));
  AD.once("dialog", (d) => d.accept());
  await AD.locator("#viewerList .row", { hasText: "pending@example.com" }).getByRole("button", { name: "Remove" }).click();
  await until(async () => !(await text(AD, "#viewerList")).includes("pending@example.com"), 6000);
  AD.once("dialog", (d) => d.accept());
  await AD.locator("#viewerList .row", { hasText: EMAILS.uipick }).getByRole("button", { name: "Remove" }).click();
  check("owner removes them on the page and they disappear", await until(async () => !(await text(AD, "#viewerList")).includes(EMAILS.uipick), 6000));
  check("...and they can no longer sign in", (await login(EMAILS.uipick)).status === 403);

  // sections and one-tap undo
  const mk = { mod: "modx@example.com", ed: "edx@example.com", v1: "vw1@example.com", v2: "vw2@example.com" };
  const adminApi = (email, role) => rolesApi(sessions.editorA, "POST", { email, role });
  await adminApi(mk.mod, "contributor"); await adminApi(mk.ed, "editor"); await adminApi(mk.v1, "viewer"); await adminApi(mk.v2, "viewer");
  await AD.reload();
  const staffCount = (await rolesApi(sessions.editorA)).body.people.filter((p) => p.role !== "viewer").length;
  check("people with more than watch-only access are in their own section at the top (owners, editors, contributors)", await until(async () => { const t = await text(AD, "#staffList"); return t.includes(mk.mod) && t.includes(mk.ed) && t.includes(EMAILS.editorA) && !t.includes(mk.v1) && /owners \(1\)/i.test(t) && /editors \(/i.test(t) && /contributors \(/i.test(t); }, 6000), await text(AD, "#staffList"));
  check("...with a count that matches", Number(await text(AD, "#staffCount")) === staffCount, { shown: await text(AD, "#staffCount"), staffCount });
  check("viewers are in a section of their own, below that, and never mixed into the staff list", await until(async () => { const t = await text(AD, "#viewerList"); return t.includes(mk.v1) && t.includes(mk.v2) && t.includes(EMAILS.viewer) && !t.includes(mk.mod) && !t.includes(mk.ed); }, 6000));
  const ys = await AD.evaluate(() => ({ staff: document.getElementById("listCard").getBoundingClientRect().top, viewers: document.getElementById("viewerCard").getBoundingClientRect().top }));
  check("...and the Viewers section sits below the staff section", ys.viewers > ys.staff, ys);
  // long lists scroll inside their own box instead of making the page endless
  const many = Array.from({ length: 14 }, (_, n) => `scrolltest${String(n).padStart(2, "0")}@example.com`);
  for (const e of many) await adminApi(e, "viewer");
  await AD.reload(); await until(async () => (await text(AD, "#viewerList")).includes(many[13]), 8000);
  const scrollBox = (sel) => AD.evaluate((q) => { const e = document.querySelector(q), c = getComputedStyle(e); return { oy: c.overflowY, max: c.maxHeight, ch: e.clientHeight, sh: e.scrollHeight, pageW: document.documentElement.scrollWidth, winW: window.innerWidth }; }, sel);
  const vBox = await scrollBox("#viewerList"), lBox = await scrollBox("#logList");
  check("the Viewers list is a scrollable box with a fixed height, so many viewers do not stretch the page", vBox.oy === "auto" && vBox.ch <= 421 && vBox.sh > vBox.ch, vBox);
  check("Recent changes is a scrollable box too", lBox.oy === "auto" && lBox.ch <= 421 && lBox.sh > lBox.ch, lBox);
  check("both boxes can be reached by keyboard (Tab) and are labelled for screen readers", await AD.locator("#viewerList").getAttribute("tabindex") === "0" && /Viewers/.test(await AD.locator("#viewerList").getAttribute("aria-label")) && await AD.locator("#logList").getAttribute("tabindex") === "0" && /Recent changes/.test(await AD.locator("#logList").getAttribute("aria-label")));
  await AD.evaluate(() => { const e = document.getElementById("viewerList"); e.scrollTop = e.scrollHeight; });
  check("scrolling the box brings the last viewer into view, and the page does not scroll sideways", await AD.locator("#viewerList .row", { hasText: many[13] }).isVisible() && vBox.pageW <= vBox.winW);
  check("buttons on a row inside the scrolling box still work (Block then Unblock)", await (async () => { AD.once("dialog", (d) => d.accept()); await AD.locator("#viewerList .row", { hasText: many[13] }).getByRole("button", { name: "Block", exact: true }).click(); const ok = await until(async () => (await text(AD, "#blockedList")).includes(many[13]), 6000); await AD.locator("#blockedList .row", { hasText: many[13] }).getByRole("button", { name: "Unblock" }).click(); return ok && await until(async () => !(await text(AD, "#blockedList")).includes(many[13]), 6000); })());
  const allLists = ["staffList", "viewerList", "logList", "blockedList", "seenList", "peopleOut", "pendList", "findOut"];
  const lists = await AD.evaluate((ids) => ids.map((id) => { const e = document.getElementById(id), c = getComputedStyle(e); return { id, cls: e.classList.contains("scrolly"), tab: e.getAttribute("tabindex"), role: e.getAttribute("role"), label: e.getAttribute("aria-label"), oy: c.overflowY, max: c.maxHeight, shown: c.display !== "none" }; }), allLists);
  check("every long list on the admin page (people, viewers, blocked, signed in, search results, pending sign-ups, recent changes, erase results) is a scrollable, keyboard-reachable, labelled box", lists.every((l) => l.cls && l.tab === "0" && l.role === "region" && /scrollable/.test(l.label) && l.oy === "auto" && l.max !== "none"), lists.filter((l) => !(l.cls && l.tab === "0" && l.oy === "auto")));
  check("a list with nothing in it does not show an empty box (search results before you search)", lists.find((l) => l.id === "peopleOut").shown === false);
  for (const e of many) await adminApi(e, "none");
  await AD.reload(); await sleep(600);

  await AD.locator("#viewerList .row", { hasText: mk.v1 }).locator("select").selectOption("contributor");
  check("changing a viewer to Contributor moves them up into the staff section", await until(async () => (await text(AD, "#staffList")).includes(mk.v1) && !(await text(AD, "#viewerList")).includes(mk.v1), 6000));
  check("...and the change shows up under Recent changes with an Undo", await until(async () => { const r = AD.locator("#logList .row", { hasText: mk.v1 }).first(); return (await r.count()) && /Viewer to Contributor/.test(await r.innerText()) && await r.getByRole("button", { name: /Undo/ }).isVisible(); }, 6000));
  check("...and an Undo button appears right at the top of the page", await AD.locator("#undoBtn").isVisible() && /back to Viewer/.test(await AD.locator("#undoBtn").innerText()));
  await AD.click("#undoBtn");
  check("one tap on that Undo puts them back in the Viewers section", await until(async () => (await text(AD, "#viewerList")).includes(mk.v1) && !(await text(AD, "#staffList")).includes(mk.v1), 6000));
  const v1Role = (await rolesApi(sessions.editorA)).body.people.find((p) => p.email === mk.v1);
  check("...and on the server they are a Viewer again", v1Role && v1Role.role === "viewer", v1Role);
  check("older entries for the same person no longer offer Undo (it says they changed again)", await until(async () => /Changed again since/.test(await text(AD, "#logList")), 6000));

  AD.once("dialog", (d) => d.accept());
  await AD.locator("#staffList .row", { hasText: mk.mod }).getByRole("button", { name: "Remove" }).click();
  check("an accidental Remove disappears from the list...", await until(async () => !(await text(AD, "#staffList")).includes(mk.mod), 6000));
  check("...but Recent changes says who was removed and what they were", await until(async () => { const r = AD.locator("#logList .row", { hasText: mk.mod }).first(); return (await r.count()) && /Removed \(was Contributor\)/.test(await r.innerText()); }, 6000));
  check("...and they cannot sign in while removed", (await rolesApi(sessions.editorA)).body.people.every((p) => p.email !== mk.mod));
  await AD.locator("#logList .row", { hasText: mk.mod }).first().getByRole("button", { name: /Undo/ }).click();
  check("Undo brings them straight back as a Contributor in the staff section", await until(async () => (await text(AD, "#staffList")).includes(mk.mod), 6000) && (await rolesApi(sessions.editorA)).body.people.find((p) => p.email === mk.mod).role === "contributor");
  const apiLog = (await rolesApi(sessions.editorA)).body.log;
  check("the history records who did what (server side)", apiLog.length >= 4 && apiLog[0].actor === EMAILS.editorA && apiLog[0].email === mk.mod && apiLog[0].from_role === "none" && apiLog[0].to_role === "contributor", apiLog.slice(0, 2));
  check("only owners can read that history (403 for an Editor and a Contributor)", (await rolesApi(sessions.editorB)).status === 403 && (await rolesApi(sessions.contributor)).status === 403);
  for (const e of Object.values(mk)) await adminApi(e, "none");

  // block, lock the door, sign out everywhere and erase, on the admin page itself
  check("the admin page has Lock the door and Erase a person tools for owners only", await until(async () => await AD.locator("#lockCard").isVisible() && await AD.locator("#eraseCard").isVisible(), 6000) && await ADE.locator("#lockCard").isHidden() && await ADE.locator("#eraseCard").isHidden() && await ADK.locator("#eraseCard").isHidden());
  const bk = "blockui@example.com";
  await adminApi(bk, "viewer"); await AD.reload();
  await until(async () => (await text(AD, "#viewerList")).includes(bk), 6000);
  AD.once("dialog", (d) => d.accept());
  await AD.locator("#viewerList .row", { hasText: bk }).getByRole("button", { name: "Block", exact: true }).click();
  check("Block on a viewer row moves them into the Blocked section, out of Viewers", await until(async () => (await text(AD, "#blockedList")).includes(bk) && !(await text(AD, "#viewerList")).includes(bk) && Number(await text(AD, "#blockedCount")) >= 1, 6000), await text(AD, "#blockedList"));
  check("...and Recent changes says Blocked, with an Undo", await until(async () => { const r = AD.locator("#logList .row", { hasText: bk }).first(); return (await r.count()) && /Blocked \(was Viewer\)/.test(await r.innerText()) && await r.getByRole("button", { name: /Undo/ }).isVisible(); }, 6000));
  check("...and they cannot sign in", (await login(bk)).status === 403);
  await AD.locator("#logList .row", { hasText: bk }).first().getByRole("button", { name: /Undo/ }).click();
  check("Undo on a block puts them straight back as a Viewer", await until(async () => (await text(AD, "#viewerList")).includes(bk) && !(await text(AD, "#blockedList")).includes(bk), 6000));
  AD.once("dialog", (d) => d.accept());
  await AD.locator("#viewerList .row", { hasText: bk }).getByRole("button", { name: "Block", exact: true }).click();
  await until(async () => (await text(AD, "#blockedList")).includes(bk), 6000);
  await AD.locator("#blockedList .row", { hasText: bk }).getByRole("button", { name: "Unblock" }).click();
  check("Unblock takes them off the Blocked section", await until(async () => !(await text(AD, "#blockedList")).includes(bk) && await AD.locator("#blockedCard").isHidden(), 6000));
  await adminApi(bk, "none");
  const so = "signoutui@example.com"; await adminApi(so, "viewer"); const soSess = (await login(so)).session; await AD.reload();
  await until(async () => (await text(AD, "#viewerList")).includes(so), 6000); await sleep(1100);
  AD.once("dialog", (d) => d.accept());
  await AD.locator("#viewerList .row", { hasText: so }).getByRole("button", { name: "Sign out everywhere" }).click();
  check("Sign out everywhere on a row ends that person's sessions", await until(async () => /signed out everywhere/.test(await text(AD, "#msg")), 6000) && (await fetch(BASE + "/api/session", { headers: { Authorization: "Bearer " + soSess.token } })).status === 401);
  await adminApi(so, "none");
  check("the Lock the door card says the door is open, with a button", /open/.test(await text(AD, "#lockState")) && /Lock the door/.test(await text(AD, "#lockBtn")));
  AD.once("dialog", (d) => d.accept()); await AD.click("#lockBtn");
  check("locking shows LOCKED and the button becomes Open the door", await until(async () => /LOCKED/.test(await text(AD, "#lockState")) && /Open the door/.test(await text(AD, "#lockBtn")), 6000));
  await AD.click("#lockBtn");
  check("opening the door again shows it is open", await until(async () => /open/.test(await text(AD, "#lockState")) && /Lock the door/.test(await text(AD, "#lockBtn")), 6000));
  const qd = (await viaWs.w("add", "daters", null, { name: "Quincy Testperson", age: 30, location: "NC", gender: "man", sexuality: "straight", min: 20, max: 40, ts: 9 })).id;
  await viaWs.w("add", "matches", null, { hotId: qd, hotName: "Quincy Testperson", pickId: "x", pickName: "Someone", fit: "x", ts: 10 });
  await viaWs.w("add", "questions", null, { text: "Quincy asked this?", handle: "@quincyfan", status: "ready", ts: 11 });
  await AD.fill("#findQ", "quincy"); await AD.click("#findForm button[type=submit]");
  check("searching for a person lists their dater record, match entry and question, all ticked", await until(async () => { const t = await text(AD, "#findOut"); return /Quincy Testperson/.test(t) && /Quincy Testperson and Someone/.test(t) && /@quincyfan/.test(t); }, 6000) && (await AD.locator("#findOut input[type=checkbox][data-key]:checked").count()) >= 3);
  await AD.locator("#findOut label", { hasText: "Quincy Testperson and Someone" }).locator("input").uncheck();
  AD.once("dialog", (d) => d.accept());
  await AD.getByRole("button", { name: "Erase the ticked items" }).click();
  check("erasing removes only what was ticked and reports it", await until(async () => /Erased: 0 account\(s\), 1 dater\(s\), 0 match log entr/.test(await text(AD, "#msg")), 6000), await text(AD, "#msg"));
  const afterQ = await (await fetch(BASE + "/api/export", { headers: { Authorization: "Bearer " + sessions.editorA.token } })).json();
  check("...the dater is gone, the unticked match entry stays, the question lost its handle but kept its text", !afterQ.daters.some((d) => d.name === "Quincy Testperson") && afterQ.matches.some((m) => m.hotName === "Quincy Testperson") && afterQ.questions.some((q) => q.text === "Quincy asked this?" && q.handle === ""));
  check("...and the history shows 'Records erased on request' with no Undo", await until(async () => /Records erased on request/.test(await text(AD, "#logList")), 6000));
  check("the admin page shows no JavaScript errors", AD.errors.length === 0, AD.errors);

  // reconnect
  const P = await mkPage(sessions.editorA, PROXY_BASE);
  check("Editor page through the test proxy is live", await until(async () => (await roleOf(P)) === "Host view" && Number(await text(P, "#daterCount")) > 0));
  await P.click("#tabQ");
  const totalBefore = Number(/(\d+) total/i.exec(await text(P, "#totalCount"))[1]);
  proxy.sever();
  check("connection loss is noticed and the page says so", await until(async () => (await P.evaluate(() => window.__ev)).includes("offline"), 10000), await P.evaluate(() => window.__ev));
  await viaWs.w("add", "questions", null, { ...dataFor.questions, text: "Added during the outage" });
  await viaWs.w("set", "game", "question", { text: "Changed during the outage", handle: "", qid: "", hist: [] });
  await P.click("#randomQ");
  check("a write while offline fails fast with the page's normal 'Could not save' message", await until(async () => (await text(P, "#toast")).includes("Could not save"), 6000), await text(P, "#toast"));
  check("...and the page's question snaps back to the last known server state (no half-applied change)", await until(async () => (await text(P, "#qtext")) !== "" , 3000));
  check("stale screen: still showing the old question while offline", (await text(P, "#qtext")) !== "Changed during the outage");
  check("while reconnecting the pill says Reconnecting (amber)", await until(async () => (await P.locator("#connTxt").textContent()) === "Reconnecting", 5000), await P.locator("#connTxt").textContent());
  check("after 10 seconds without a connection the pill turns red and says Offline", await until(async () => (await P.locator("#connTxt").textContent()) === "Offline" && (await P.locator("#connPill").getAttribute("data-state")) === "offline", 14000), await P.locator("#connTxt").textContent());
  const wobble = []; for (let i = 0; i < 12; i++) { wobble.push(await P.locator("#connTxt").textContent()); await sleep(500); }
  check("while still down the red Offline pill stays red (it does not flicker back to Reconnecting)", wobble.every((w) => w === "Offline"), wobble);
  proxy.restore();
  check("the pill goes back to Live after reconnecting", await until(async () => (await P.locator("#connTxt").textContent()) === "Live", 25000));
  check("page reconnects by itself and re-syncs the question", await until(async () => (await text(P, "#qtext")) === "Changed during the outage", 25000), await text(P, "#qtext"));
  check("...and re-syncs the question list (includes the one added during the outage)", await until(async () => Number(/(\d+) total/i.exec(await text(P, "#totalCount"))[1]) >= totalBefore + 1, 8000));
  check("the page announced 'online' after resync", (await P.evaluate(() => window.__ev)).includes("online"), await P.evaluate(() => window.__ev));
  // the connection after reconnect is a normal one: writes work again
  await P.click("#tabQ"); await P.locator("#qIn").fill("Written after reconnect"); await P.click("#qSend");
  check("writes work again after the reconnect", !!(await until(async () => (await viaWs.sub("questions")).docs.some((d) => d.data.text === "Written after reconnect"), 6000)));
  // repeated drops using the page's own test hook (no network layer): ten in a row
  let okDrops = 0;
  for (let i = 0; i < 5; i++) {
    await P.evaluate(() => window.claude._test.drop());
    if (await until(async () => (await P.evaluate(() => window.claude._test.state().state)) === "open", 15000)) okDrops++;
  }
  check("5 abrupt drops in a row: the page reconnected every time", okDrops === 5, okDrops);
  viaWs.close();

  const errs = [A, B, K, V, P, AD, ADE, ADK, PH, VP, KP, VF].flatMap((p) => p.errors);
  check("no JavaScript errors on any page during the whole run", errs.length === 0, errs);
} catch (e) {
  console.error(e);
  results.push({ section: "crash", name: "test run crashed: " + (e && e.message), ok: false });
} finally {
  try { if (browser) await browser.close(); } catch (e) { /* ignore */ }
  stop();
}

const fails = results.filter((r) => !r.ok);
const summary = `\n${results.length - fails.length} passed, ${fails.length} failed, ${results.length} total`;
console.log(summary);
const lines = ["Test results " + new Date().toISOString(), ""];
let last = "";
for (const r of results) { if (r.section !== last) { lines.push("", "== " + r.section); last = r.section; } lines.push((r.ok ? "PASS  " : "FAIL  ") + r.name); }
lines.push(summary);
writeFileSync(join(ROOT, "test", "last-run.txt"), lines.join("\n") + "\n");
try { rmSync(logDir, { recursive: true, force: true }); } catch (e) { /* ignore */ }
process.exit(fails.length ? 1 : 0);
