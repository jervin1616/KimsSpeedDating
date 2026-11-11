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

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

const PORT = 8799, PROXY_PORT = 8798;
const BASE = `http://127.0.0.1:${PORT}`;
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
  const r = await fetch(BASE + path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
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
      const headers = this.origin ? { Origin: this.origin } : {};
      this.ws = new WebSocket(BASE.replace("http", "ws") + "/api/ws", this.protocols || ["kim-v1", this.token], { headers });
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
let wrangler, jwksServer, proxy;
const logDir = mkdtempSync(join(tmpdir(), "kim-test-"));

function startJwks() {
  return new Promise((resolve) => {
    jwksServer = createServer((req, res) => {
      res.writeHead(200, { "content-type": "application/json", "cache-control": "public, max-age=300" });
      res.end(JSON.stringify({ keys: [goodJwk] }));
    }).listen(0, "127.0.0.1", () => resolve(jwksServer.address().port));
  });
}

async function startWrangler(jwksPort) {
  const vars = {
    GOOGLE_CLIENT_ID: CLIENT_ID, GOOGLE_JWKS_URL: `http://127.0.0.1:${jwksPort}/jwks`, SESSION_SECRET, ADMIN_KEY, ROLES,
    DEFAULT_ROLE: "none", ALLOWED_ORIGINS: `${PROXY_BASE},http://localhost:${PROXY_PORT}`,
  };
  const args = ["wrangler", "dev", "--port", String(PORT), "--ip", "127.0.0.1", "--inspector-port", "9239", "--persist-to", join(logDir, "state"), "--local"];
  for (const [k, v] of Object.entries(vars)) args.push("--var", `${k}:${v}`);
  wrangler = spawn("npx", args, { cwd: ROOT, env: { ...process.env, NO_PROXY: "127.0.0.1,localhost", no_proxy: "127.0.0.1,localhost", WRANGLER_SEND_METRICS: "false", CI: "1" }, detached: true });
  const out = [];
  wrangler.stdout.on("data", (d) => out.push(d.toString()));
  wrangler.stderr.on("data", (d) => out.push(d.toString()));
  const ok = await until(async () => (await fetch(BASE + "/api/config")).ok, 90000, 500);
  writeFileSync(join(logDir, "wrangler.log"), out.join(""));
  if (!ok) { console.error(out.join("").slice(-3000)); throw new Error("wrangler dev did not start"); }
  wrangler.log = out;
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
  await startWrangler(jwksPort);
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

  /* ===== roles admin ===== */
  group("Role assignment: owners, editors, the admin page API");
  const rolesApi = async (session, method = "GET", body, extra = {}) => {
    const r = await fetch(BASE + "/api/roles", { method, headers: { Authorization: "Bearer " + (session ? session.token : "none"), "content-type": "application/json", ...extra }, body: body ? JSON.stringify(body) : undefined });
    return { status: r.status, body: await r.json().catch(() => null) };
  };
  const loginRes = await login(EMAILS.editorA);
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
  check("on a phone the question is below the fold, so the pinned bar shows", await until(async () => await PH.locator("#liveBar").isVisible(), 4000));
  const qPhone0 = await text(PH, "#qtext");
  await PH.click("#lbRandom");
  check("Random question from the pinned bar works like the main button", await until(async () => { const t = await text(PH, "#qtext"); return t !== qPhone0 && t !== "No question picked yet." ? t : false; }, 5000));
  check("the bar shows the current question", await until(async () => (await text(PH, "#lbQ")) === (await text(PH, "#qtext")), 3000));
  await PH.locator("#qtext").scrollIntoViewIfNeeded();
  check("the pinned bar hides itself when the real question card is on screen", await until(async () => await PH.locator("#liveBar").isHidden(), 4000));
  const VP = await mkPage(sessions.viewer, BASE, "/", { width: 390, height: 844 });
  await until(async () => (await roleOf(VP)) === "View only"); await sleep(500);
  check("Viewers never get the pinned bar", await VP.locator("#liveBar").isHidden());
  const KP = await mkPage(sessions.contributor, BASE, "/", { width: 390, height: 844 });
  check("Contributors get the pinned bar on a phone", await until(async () => await KP.locator("#liveBar").isVisible(), 5000));
  await PH.locator("#rTop .heart").nth(2).scrollIntoViewIfNeeded();
  await PH.locator("#rTop .heart").nth(2).click(); await sleep(400);
  const box = await PH.locator("#pickModal .card").boundingBox();
  check("on a phone the picker fits the screen and does not scroll sideways", box && box.y >= 0 && box.y + box.height <= 844 && box.x >= 0 && box.x + box.width <= 390 && !(await PH.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth)), box);
  await PH.keyboard.press("Escape"); await PH.locator("#rTop .heart").nth(2).click();

  // sign out
  check("every signed-in role sees a Sign out button", (await Promise.all([A, B, K, V].map((p) => p.locator("#signOut").isVisible()))).every(Boolean));
  const V2 = await mkPage(sessions.viewer);
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
  const AD = await mkPage(sessions.editorA, BASE, "/admin.html"); const ADE = await mkPage(sessions.editorB, BASE, "/admin.html"); const ADK = await mkPage(sessions.contributor, BASE, "/admin.html");
  check("admin page (owner) lists people, marks secret ones locked", await until(async () => { const t = await text(AD, "#list"); return t.includes(EMAILS.editorB) && /locked/i.test(t); }, 6000));
  await AD.fill("#email", EMAILS.uipick); await AD.selectOption("#role", "viewer"); await AD.click("#addForm button[type=submit]");
  check("owner adds a person on the page and they appear in the list", await until(async () => (await text(AD, "#list")).includes(EMAILS.uipick), 6000));
  check("...and the person can sign in as Viewer", (await login(EMAILS.uipick)).body && (await login(EMAILS.uipick)).body.role === "viewer");
  check("a normal Editor on the admin page is told they are not an owner and sees no controls", await until(async () => /not an owner/.test(await text(ADE, "#msg")), 6000) && await ADE.locator("#listCard").isHidden() && await ADE.locator("#addCard").isHidden());
  check("a Contributor on the admin page is told the same", await until(async () => /not an owner/.test(await text(ADK, "#msg")), 6000) && await ADK.locator("#listCard").isHidden());
  await login("pending@example.com");
  await AD.reload();
  check("the page lists people who signed in recently", await until(async () => (await text(AD, "#seenList")).includes("pending@example.com"), 6000));
  await AD.locator("#seenList .row", { hasText: "pending@example.com" }).getByRole("button", { name: "Add" }).click();
  check("clicking Add moves them into People with the chosen role", await until(async () => (await text(AD, "#list")).includes("pending@example.com") && !(await text(AD, "#seenList")).includes("pending@example.com"), 6000));
  AD.once("dialog", (d) => d.accept());
  await AD.locator("#list .row", { hasText: "pending@example.com" }).getByRole("button", { name: "Remove" }).click();
  await until(async () => !(await text(AD, "#list")).includes("pending@example.com"), 6000);
  AD.once("dialog", (d) => d.accept());
  await AD.locator("#list .row", { hasText: EMAILS.uipick }).getByRole("button", { name: "Remove" }).click();
  check("owner removes them on the page and they disappear", await until(async () => !(await text(AD, "#list")).includes(EMAILS.uipick), 6000));
  check("...and they can no longer sign in", (await login(EMAILS.uipick)).status === 403);

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

  const errs = [A, B, K, V, P, AD, ADE, ADK, PH, VP, KP].flatMap((p) => p.errors);
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
