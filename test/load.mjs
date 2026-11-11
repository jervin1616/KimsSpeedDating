// Load test (not part of "npm test"): hundreds of simulated viewers plus hosts against a local copy.
//   node test/load.mjs [viewers] [staff]
// Local numbers show the app's own limits (CPU, memory, fan-out). They are not a promise about Cloudflare's network.
import { spawn, spawnSync, execSync } from "node:child_process";
import { createServer } from "node:http";
import crypto from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import WebSocket from "ws";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const NV = Number(process.argv[2] || 400), NS = Number(process.argv[3] || 15);
const PORT = 8797, BASE = `http://127.0.0.1:${PORT}`;
const SECRET = crypto.randomBytes(32).toString("hex"), ADMIN = crypto.randomBytes(24).toString("hex");
const b64u = (x) => Buffer.from(typeof x === "string" ? x : JSON.stringify(x)).toString("base64url");
const now = () => Math.floor(Date.now() / 1000);
const session = (email) => { const body = b64u({ v: 1, e: email, i: now(), x: now() + 7200 }); return body + "." + crypto.createHmac("sha256", SECRET).update(body).digest("base64url"); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const pct = (a, p) => { const s = [...a].sort((x, y) => x - y); return s.length ? Math.round(s[Math.min(s.length - 1, Math.floor(s.length * p))]) : 0; };
const rss = () => { try { return Math.round(execSync("ps -eo rss,comm | grep -i workerd | awk '{s+=$1} END {print s}'").toString().trim() / 1024); } catch { return -1; } };

const dir = mkdtempSync(join(tmpdir(), "kim-load-"));
const jwks = createServer((q, r) => { r.writeHead(200, { "content-type": "application/json" }); r.end('{"keys":[]}'); }).listen(0, "127.0.0.1");
await sleep(200);
const vars = { GOOGLE_CLIENT_ID: "x.apps.googleusercontent.com", GOOGLE_JWKS_URL: `http://127.0.0.1:${jwks.address().port}/k`, SESSION_SECRET: SECRET, ADMIN_KEY: ADMIN, ROLES: "host@example.com=editor", DEFAULT_ROLE: "viewer", MAX_VIEWERS: String(NV), ALLOWED_ORIGINS: "" };
const args = ["wrangler", "dev", "--port", String(PORT), "--ip", "127.0.0.1", "--inspector-port", "9241", "--persist-to", join(dir, "state"), "--local"];
for (const [k, v] of Object.entries(vars)) args.push("--var", `${k}:${v}`);
const w = spawn("npx", args, { cwd: ROOT, env: { ...process.env, NO_PROXY: "127.0.0.1,localhost", WRANGLER_SEND_METRICS: "false", CI: "1" }, detached: true });
const stop = () => { try { process.kill(-w.pid, "SIGKILL"); } catch {} jwks.close(); };
process.on("exit", stop);
for (let i = 0; i < 180; i++) { try { if ((await fetch(BASE + "/api/config")).ok) break; } catch {} await sleep(500); }

// real data: the same 741 records
const imp = spawnSync("node", ["scripts/import.mjs", "--url", BASE, "--dir", "data"], { cwd: ROOT, env: { ...process.env, ADMIN_KEY: ADMIN }, encoding: "utf8" });
if (imp.status !== 0) { console.log("import failed (is the data folder present?):", imp.stderr); stop(); process.exit(1); }

const out = [];
const log = (s) => { out.push(s); console.log(s); };
const open = (email, wantSubs) => new Promise((resolve) => {
  const ws = new WebSocket(BASE.replace("http", "ws") + "/api/ws", ["kim-v1", session(email)], { headers: { Origin: BASE } });
  const c = { ws, ok: false, snaps: 0, chg: [], t0: 0 };
  ws.on("open", () => { c.ok = true; let n = 1; for (const p of wantSubs) ws.send(JSON.stringify({ t: "sub", sid: n++, path: p })); resolve(c); });
  ws.on("unexpected-response", (rq, rs) => { c.status = rs.statusCode; resolve(c); });
  ws.on("error", () => {});
  ws.on("message", (d) => { const s = d.toString(); if (s === "pong") { c.pong = Date.now(); return; } if (s.startsWith('{"t":"snap"')) c.snaps++; else if (s.startsWith('{"t":"chg"')) c.chg.push(Date.now()); });
});
async function openMany(prefix, n, subs, batch = 40) {
  const cs = []; for (let i = 0; i < n; i += batch) { const part = await Promise.all(Array.from({ length: Math.min(batch, n - i) }, (_, k) => open(`${prefix}${i + k}@example.com`, subs))); cs.push(...part); }
  return cs;
}
const viewerSubs = ["seats", "questions", "game/question"], staffSubs = ["daters", "matches", "seats", "questions", "game/question"];

log(`Load test: ${NV} viewers + ${NS} hosts/mods, MAX_VIEWERS=${NV}`);
log(`memory before: ${rss()} MB (all workerd processes)`);
let t = Date.now();
const viewers = await openMany("viewer", NV, viewerSubs);
log(`connect ${NV} viewers: ${((Date.now() - t) / 1000).toFixed(1)} s, refused: ${viewers.filter((v) => !v.ok).length}`);
await sleep(1500);
log(`  every viewer got its 3 snapshots: ${viewers.filter((v) => v.snaps === 3).length}/${NV}`);
log(`memory with ${NV} viewers: ${rss()} MB`);
const host = await open("host@example.com", staffSubs);
const staff = [host, ...(await openMany("host", NS - 1, staffSubs).catch(() => []))].filter(Boolean);
// the staff emails host0.. are default viewers by role, so count only the real host for writes; connect more as the editor
const more = []; for (let i = 0; i < NS - 1; i++) more.push(await open("host@example.com", staffSubs));
log(`connect ${more.length + 1} hosts/mods on top of the full viewer room: ${more.filter((m) => m.ok).length + 1} ok, refused: ${more.filter((m) => !m.ok).length}`);
const extraV = await open("lateviewer@example.com", viewerSubs);
log(`viewer number ${NV + 1} is refused: ${extraV.status === 503 ? "yes (503)" : "NO, status " + extraV.status}`);
await sleep(800);

async function write(op, coll, id, data) {
  return new Promise((resolve) => { const rid = Math.floor(Math.random() * 1e9); const h = (d) => { const s = d.toString(); if (s.includes('"rid":' + rid)) { host.ws.off("message", h); resolve(Date.now()); } }; host.ws.on("message", h); host.ws.send(JSON.stringify({ t: "w", rid, op, coll, id, data })); });
}
// one question change reaches every viewer
for (const v of viewers) v.chg = [];
t = Date.now();
await write("add", "questions", null, { text: "load probe", handle: "", status: "ready", ts: Date.now() });
await sleep(1500);
const lat = viewers.filter((v) => v.chg.length).map((v) => v.chg[0] - t);
log(`1 write -> reached ${lat.length}/${NV} viewers; delay p50 ${pct(lat, 0.5)} ms, p95 ${pct(lat, 0.95)} ms, max ${Math.max(...lat)} ms`);
// a realistic busy moment: 8 seat writes + question + match in a row
for (const v of viewers) v.chg = [];
t = Date.now();
for (const id of ["hot", "s1", "s2", "s3", "s4", "s5", "banner", "cohost"]) await write("set", "seats", id, { dater: null, view: null, since: null });
await write("set", "game", "question", { text: "busy moment", handle: "", qid: "", hist: [] });
const busyMs = Date.now() - t; await sleep(2500);
const got = viewers.filter((v) => v.chg.length >= 9).length;
log(`busy moment (9 writes back to back): host saw all acks in ${busyMs} ms; ${got}/${NV} viewers received all 9 updates; slowest viewer finished ${Math.max(...viewers.map((v) => (v.chg[8] || 0) - t))} ms after start`);
// heartbeats from everyone
const p0 = Date.now(); for (const v of viewers) v.ws.send("ping"); await sleep(1500);
log(`heartbeat: ${viewers.filter((v) => v.pong && v.pong >= p0).length}/${NV} answered; slowest ${Math.max(...viewers.map((v) => (v.pong || 0) - p0))} ms`);
log(`memory after traffic: ${rss()} MB`);
// everyone drops and comes back at once (worst case: network blip, or a deploy)
for (const v of viewers) v.ws.close(); await sleep(1500);
t = Date.now();
const back = await openMany("viewer", NV, viewerSubs, 100);
await sleep(1500);
log(`reconnect storm (all ${NV} at once): ${((Date.now() - t - 1500) / 1000).toFixed(1)} s, refused: ${back.filter((v) => !v.ok).length}, got snapshots: ${back.filter((v) => v.snaps === 3).length}/${NV}`);
log(`memory after storm: ${rss()} MB`);
for (const c of [...back, ...staff, ...more]) try { c.ws.close(); } catch {}
stop();
writeFileSync(join(ROOT, "test", "last-load.txt"), out.join("\n") + "\n");
process.exit(0);
