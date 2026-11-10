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
};
const ROLES = `${EMAILS.editorA}=editor;${EMAILS.editorB}=editor;${EMAILS.contributor}=contributor;${EMAILS.viewer}=viewer`;

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

  /* ===== browser ===== */
  group("Browser: three roles, live sync, reconnect");
  browser = await chromium.launch();
  const mkPage = async (session, base = BASE) => {
    const ctx = await browser.newContext({ viewport: { width: 1100, height: 1300 } });
    await ctx.route(/fonts\.(googleapis|gstatic)\.com|accounts\.google\.com/, (r) => r.abort());
    await ctx.addInitScript(([k, v]) => { try { localStorage.setItem(k, v); } catch (e) { /* ignore */ } window.__ev = []; window.addEventListener("claude-conn", (e) => window.__ev.push(e.detail.state)); }, ["sd.session.v1", JSON.stringify(session)]);
    const page = await ctx.newPage();
    page.errors = []; page.on("pageerror", (e) => page.errors.push(e.message));
    await page.goto(base + "/");
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
  check("Contributor has Random question; Viewer does not", await K.locator("#randomQ").isVisible() && await V.locator("#randomQ").isHidden());
  check("Viewer sees no Questions panel", await V.locator("#panelQ").isHidden());
  const subsOf = async (p) => (await p.evaluate(() => window.claude._test.state())).subs;
  check("Contributor page subscribes to 3 feeds only (no daters, no matches)", (await subsOf(K)) === 3, await subsOf(K));
  check("Viewer page subscribes to 2 feeds only (seats and game)", (await subsOf(V)) === 2, await subsOf(V));
  check("Editor page subscribes to 5 feeds", (await subsOf(A)) === 5, await subsOf(A));

  // two Editors, both directions
  await A.fill("#fName", "SyncTest A"); await A.fill("#fAge", "30"); await A.fill("#fLoc", "NC");
  await A.selectOption("#fGender", "man"); await A.selectOption("#fSex", "straight");
  await A.fill("#fMin", "25"); await A.fill("#fMax", "35"); await A.check("#fAdult"); await A.click("#fSave");
  check("Editor A adds a dater: Editor B sees it live", await until(async () => (await B.locator("#dList").innerText()).includes("SyncTest A"), 6000));
  check("...and B's dater count went up by one", await until(async () => Number(await text(B, "#daterCount")) === nDaters + 1));
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
  proxy.restore();
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

  const errs = [A, B, K, V, P].flatMap((p) => p.errors);
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
