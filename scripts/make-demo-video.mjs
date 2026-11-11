#!/usr/bin/env node
// Records a short phone-sized tour of the VIEWER screen against a local copy of the app, using made-up people only.
//   node scripts/make-demo-video.mjs            -> docs/discord/viewer-tour.mp4
// Nothing real is touched: it starts its own throwaway local server and imports only the public question pack.
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import crypto from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import WebSocket from "ws";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright"); // installed globally in this environment (not a project dependency)
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PORT = 8796, BASE = `http://127.0.0.1:${PORT}`;
const SECRET = crypto.randomBytes(32).toString("hex"), ADMIN = crypto.randomBytes(24).toString("hex");
const b64u = (x) => Buffer.from(typeof x === "string" ? x : JSON.stringify(x)).toString("base64url");
const now = () => Math.floor(Date.now() / 1000);
const mint = (email) => { const body = b64u({ v: 1, e: email, i: now(), x: now() + 7200 }); return { token: body + "." + crypto.createHmac("sha256", SECRET).update(body).digest("base64url"), exp: now() + 7200, email }; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const dir = mkdtempSync(join(tmpdir(), "kim-demo-"));
const jwks = createServer((q, r) => { r.writeHead(200, { "content-type": "application/json" }); r.end('{"keys":[]}'); }).listen(0, "127.0.0.1");
await sleep(200);
const vars = { GOOGLE_CLIENT_ID: "x.apps.googleusercontent.com", GOOGLE_JWKS_URL: `http://127.0.0.1:${jwks.address().port}/k`, SESSION_SECRET: SECRET, ADMIN_KEY: ADMIN, ROLES: "owner@demo.test=owner", DEFAULT_ROLE: "viewer", MAX_VIEWERS: "50", ALLOWED_ORIGINS: "" };
const args = ["wrangler", "dev", "--port", String(PORT), "--ip", "127.0.0.1", "--inspector-port", "9242", "--persist-to", join(dir, "state"), "--local"];
for (const [k, v] of Object.entries(vars)) args.push("--var", `${k}:${v}`);
const w = spawn("npx", args, { cwd: ROOT, env: { ...process.env, NO_PROXY: "127.0.0.1,localhost", WRANGLER_SEND_METRICS: "false", CI: "1" }, detached: true });
const stop = () => { try { process.kill(-w.pid, "SIGKILL"); } catch {} jwks.close(); };
process.on("exit", stop);
for (let i = 0; i < 180; i++) { try { if ((await fetch(BASE + "/api/config")).ok) break; } catch {} await sleep(500); }

// the public question pack, sorted into categories
const imp = spawnSync("node", ["scripts/import.mjs", "--url", BASE, "--dir", "content"], { cwd: ROOT, env: { ...process.env, ADMIN_KEY: ADMIN }, encoding: "utf8" });
if (imp.status !== 0) { console.error(imp.stderr); stop(); process.exit(1); }
const owner = mint("owner@demo.test"), viewer = { ...mint("viewer@demo.test"), role: "viewer", owner: false };
const cat = await fetch(BASE + "/api/categorize", { method: "POST", headers: { Authorization: "Bearer " + owner.token, "content-type": "application/json" }, body: "{}" });
console.log("categories:", await cat.text());

// the "host": writes the board the viewer sees
const ws = new WebSocket(BASE.replace("http", "ws") + "/api/ws", ["kim-v1", owner.token], { headers: { Origin: BASE } });
await new Promise((r) => ws.on("open", r));
let rid = 1; const put = (coll, id, data) => ws.send(JSON.stringify({ t: "w", rid: rid++, op: "set", coll, id, data }));
const P = (name, age, loc, gs, rng, status, label) => ({ name, age, location: loc, gs, rng, status, label });
const seat = (key, view) => put("seats", key, { dater: view ? { id: key, name: view.name } : null, view, since: view ? Date.now() : null, ...(["banner", "cohost"].includes(key) ? { unlocked: false } : {}) });
const ask = (text) => put("game", "question", { text, handle: "", qid: "", hist: [] });
["hot", "s1", "s2", "s3", "s4", "s5", "banner", "cohost"].forEach((k) => seat(k, null));
ask("What's your idea of the perfect first date?");
await sleep(500);

const browser = await chromium.launch();
const SIZE = { width: 390, height: 844 };
const frameDir = join(dir, "frames"); mkdirSync(frameDir);
const ctx = await browser.newContext({
  viewport: SIZE, deviceScaleFactor: 2, hasTouch: true, isMobile: true,
  userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
});
await ctx.route(/fonts\.(googleapis|gstatic)\.com|accounts\.google\.com/, (r) => r.abort());
await ctx.addInitScript((sess) => {
  try { localStorage.setItem("sd.session.v1", JSON.stringify(sess)); } catch (e) { /* ignore */ }
  // captions, title cards and a ring that shows where a finger taps (only for the recording)
  const css = document.createElement("style");
  css.textContent = "#demoCap{pointer-events:none;position:fixed;left:12px;right:12px;bottom:14px;z-index:9999;background:rgba(20,2,3,.9);color:#fff;border:1px solid #ff4d6d;border-radius:14px;padding:12px 14px;font:600 17px/1.3 system-ui,sans-serif;text-align:center;box-shadow:0 6px 24px rgba(0,0,0,.5);transition:opacity .3s}"
    + "#demoCard{position:fixed;inset:0;z-index:10000;background:radial-gradient(circle at 50% 30%,#4a0710,#1b0203 70%);color:#fff;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;text-align:center;padding:24px;font-family:system-ui,sans-serif;transition:opacity .4s}"
    + "#demoCard h1{font:700 46px/1.05 LogoFont,system-ui,sans-serif;margin:0;color:#fff;text-shadow:0 0 18px #ff2d55}#demoCard p{margin:0;font-size:19px;color:#ffd5dc}"
    + ".demoTap{position:fixed;z-index:10001;width:46px;height:46px;margin:-23px 0 0 -23px;border-radius:50%;border:3px solid #fff;background:rgba(255,77,109,.45);pointer-events:none;animation:demoTap .6s ease-out forwards}@keyframes demoTap{from{transform:scale(.4);opacity:1}to{transform:scale(1.5);opacity:0}}";
  document.addEventListener("DOMContentLoaded", () => document.head.appendChild(css));
  window.__cap = (t) => { let e = document.getElementById("demoCap"); if (!t) { if (e) e.remove(); return; } if (!e) { e = document.createElement("div"); e.id = "demoCap"; document.body.appendChild(e); } e.textContent = t; };
  window.__card = (title, sub, sub2) => { let e = document.getElementById("demoCard"); if (!title) { if (e) { e.style.opacity = 0; setTimeout(() => e.remove(), 450); } return; } if (!e) { e = document.createElement("div"); e.id = "demoCard"; document.body.appendChild(e); } e.innerHTML = ""; for (const [tag, txt] of [["h1", title], ["p", sub], ["p", sub2]]) if (txt) { const n = document.createElement(tag); n.textContent = txt; e.appendChild(n); } };
  document.addEventListener("pointerdown", (ev) => { const d = document.createElement("div"); d.className = "demoTap"; d.style.left = ev.clientX + "px"; d.style.top = ev.clientY + "px"; document.body.appendChild(d); setTimeout(() => d.remove(), 700); }, true);
}, viewer);
const page = await ctx.newPage();
// Playwright's own recorder is 1x only (soft on phones), so grab the screencast frames ourselves at full 2x size.
const cdp = await ctx.newCDPSession(page);
const frames = []; let fi = 0;
let firstWall = 0, firstT = 0, lastT = 0;
cdp.on("Page.screencastFrame", (f) => {
  if (!frames.length) { firstWall = Date.now(); firstT = f.metadata.timestamp; }
  lastT = f.metadata.timestamp;
  const name = "f" + String(fi++).padStart(6, "0") + ".jpg";
  writeFileSync(join(frameDir, name), Buffer.from(f.data, "base64"));
  frames.push({ name, t: f.metadata.timestamp });
  cdp.send("Page.screencastFrameAck", { sessionId: f.sessionId }).catch(() => {});
});
await cdp.send("Page.startScreencast", { format: "jpeg", quality: 92, maxWidth: SIZE.width * 2, maxHeight: SIZE.height * 2, everyNthFrame: 1 });
const capEvents = []; // { wall, text } , drawn under the phone later (text null = clear)
const cap = async (t) => { capEvents.push({ wall: Date.now(), text: t || null }); };
const card = (a, b, c) => page.evaluate(([x, y, z]) => window.__card(x, y, z), [a, b, c]);
await page.goto(BASE + "/");
await page.waitForSelector("#app:not([hidden])", { timeout: 20000 });
await card("Kim's Speed Dating", "Your own question screen", "Free. Watch live and never run out of questions.");
await sleep(3400);
await card(); await sleep(500);

// 1. the board
await cap("1. Watch the board live: who is in the hot seat and who is on the panel");
await sleep(2200);
seat("hot", P("Jordan", 28, "NC", "M · Straight", ["Wants 24-34"], "hot", "")); await sleep(1300);
seat("s1", P("Ava", 26, "TX", "W · Straight", ["Wants 25-35"], "mutual", "Fits both")); await sleep(1100);
seat("s2", P("Riley", 24, "OH", "W · Bi", ["Men 24-30", "Women 22-28"], "close", "Off by 2 yrs")); await sleep(1100);
seat("s3", P("Sam", 36, "CA", "W · Straight", ["Wants 30-42"], "nofit", "Off by 5 yrs")); await sleep(1100);
seat("s4", P("Taylor", 29, "GA", "W · Straight", ["Wants 26-36"], "mutual", "Fits both")); await sleep(1500);
await cap("Green means they fit each other. Yellow is close. Red is not a match.");
await sleep(3600);
await cap("The question on the stream shows at the top");
ask("What's one thing you'd never do on a first date?"); await sleep(3200);

// 2. private random question
await cap("2. Need a question? Tap Random question for me. Only you see it");
await page.locator("#myQBox").scrollIntoViewIfNeeded(); await sleep(1500);
for (let i = 0; i < 3; i++) { await page.tap("#myQBtn"); await sleep(2100); }

// 3. categories
await cap("3. Pick a category to narrow it down");
const ring = async (sel) => page.evaluate((s) => { const e = document.querySelector(s); e.style.outline = "3px solid #ffd166"; e.style.borderRadius = "8px"; setTimeout(() => { e.style.outline = ""; }, 1400); }, sel);
await ring("#myCat"); await sleep(1300);
for (const k of ["wyr", "food", "flirty"]) { await page.selectOption("#myCat", k); await sleep(2300); }
await page.selectOption("#myCat", ""); await sleep(400);

// 4. live board moves on
await cap("4. The stream moves on and your screen follows. Nothing to refresh");
await page.evaluate(() => window.scrollTo({ top: 0, behavior: "smooth" })); await sleep(1100);
seat("s3", null); seat("s5", P("Casey", 27, "VA", "W · Straight", ["Wants 24-34"], "close", "Off by 1 yr")); await sleep(1600);
ask("If you could have dinner with anyone, who would it be?"); await sleep(3000);

// 5. install
await cap("5. Add it to your home screen like an app");
await page.evaluate(() => window.scrollTo({ top: 0, behavior: "smooth" })); await sleep(1400); await page.tap("#installBtn"); await sleep(3800);
await page.tap("#howTabAndroid"); await sleep(3000);
await page.tap("#howClose"); await sleep(600);
await cap(); await card("Kim's Speed Dating", "Free. Sign in with Google.", "18+ only. The link is pinned in the server.");
await sleep(3500);
await cdp.send("Page.stopScreencast").catch(() => {});
await ctx.close(); await browser.close();

// frames arrive only when the screen changes, so tell ffmpeg how long each one stays up
let list = "";
frames.forEach((f, i) => { const next = frames[i + 1]; list += `file '${f.name}'\nduration ${(next ? Math.max(0.01, next.t - f.t) : 0.6).toFixed(4)}\n`; });
list += `file '${frames[frames.length - 1].name}'\n`;
writeFileSync(join(frameDir, "list.txt"), list);
const D = lastT - firstT + 0.6;
console.log(frames.length + " frames, " + D.toFixed(1) + " s");

// ---- the picture around the phone: background, phone frame, and one caption image per caption
const W = 1080, H = 1920, BX = 189, BY = 70, BW = 702, BH = 1459, RING = 26; // phone body and its bezel
const SX = BX + RING, SY = BY + RING, SW = BW - 2 * RING, SH = BH - 2 * RING; // screen
const assets = join(dir, "assets"); mkdirSync(assets);
const art = await chromium.launch(); const ap = await art.newPage({ viewport: { width: W, height: H } });
const snap = async (html, file, box, transparent) => { await ap.setContent(html, { waitUntil: "load" }); await ap.screenshot({ path: join(assets, file), omitBackground: !!transparent, ...(box ? { clip: box } : {}) }); };
let sparks = ""; { let r = 7; const rnd = () => (r = (r * 16807) % 2147483647) / 2147483647; for (let i = 0; i < 70; i++) sparks += `<i style="left:${(rnd() * W).toFixed(0)}px;top:${(rnd() * H).toFixed(0)}px;width:${(2 + rnd() * 4).toFixed(1)}px;height:${(2 + rnd() * 4).toFixed(1)}px;opacity:${(0.2 + rnd() * 0.5).toFixed(2)}"></i>`; }
const base = `*{box-sizing:border-box;margin:0}body{width:${W}px;height:${H}px;position:relative;overflow:hidden;font-family:system-ui,"Segoe UI",Roboto,Arial,sans-serif}`;
await snap(`<style>${base}body{background:radial-gradient(circle at 50% 28%,#5a0a14 0%,#2a0508 55%,#140102 100%)}i{position:absolute;border-radius:50%;background:#ff7a93}.glow{position:absolute;left:${BX - 40}px;top:${BY - 30}px;width:${BW + 80}px;height:${BH + 60}px;border-radius:130px;background:rgba(255,45,85,.35);filter:blur(60px)}</style><body>${sparks}<div class="glow"></div></body>`, "bg.png");
await snap(`<style>${base}body{background:transparent}.ph{position:absolute;left:${BX}px;top:${BY}px;width:${BW}px;height:${BH}px;border-radius:92px;border:${RING}px solid #0d0d11;box-shadow:0 0 0 4px #5b5b66,0 0 0 7px #26262d}.isl{position:absolute;left:${(W - 96) / 2}px;top:${SY + 8}px;width:96px;height:26px;border-radius:13px;background:#000}.b{position:absolute;background:#3a3a44;border-radius:4px}</style><body><div class="ph"></div><div class="isl"></div><div class="b" style="left:${BX - 11}px;top:${BY + 250}px;width:7px;height:80px"></div><div class="b" style="left:${BX - 11}px;top:${BY + 350}px;width:7px;height:120px"></div><div class="b" style="left:${BX - 11}px;top:${BY + 490}px;width:7px;height:120px"></div><div class="b" style="left:${BX + BW + 4}px;top:${BY + 380}px;width:7px;height:170px"></div></body>`, "bezel.png", null, true);
// captions: collapse the events into on/off spans
const spans = []; const t0 = firstWall;
capEvents.forEach((e, i) => { if (!e.text) return; const start = Math.max(0, (e.wall - t0) / 1000), end = i + 1 < capEvents.length ? (capEvents[i + 1].wall - t0) / 1000 : D; spans.push({ start, end: Math.min(end, D), text: e.text }); });
const CY = BY + BH + 36, CH = H - CY - 40;
for (let i = 0; i < spans.length; i++) {
  const m = /^(\d)\.\s*(.*)$/.exec(spans[i].text), num = m ? m[1] : "", body = m ? m[2] : spans[i].text;
  const esc = (x) => x.replace(/&/g, "&amp;").replace(/</g, "&lt;");
  await snap(`<style>${base}body{background:transparent;width:${W}px;height:${CH}px}.c{position:absolute;left:60px;right:60px;top:0;bottom:0;display:flex;flex-direction:column;align-items:center;justify-content:flex-start;padding-top:22px;gap:14px;text-align:center}.n{width:58px;height:58px;border-radius:50%;background:#ff2d55;color:#fff;font:800 32px/58px system-ui,sans-serif;box-shadow:0 0 20px #ff2d55}.t{color:#fff;font:700 52px/1.18 system-ui,"Segoe UI",Roboto,Arial,sans-serif;text-shadow:0 2px 12px rgba(0,0,0,.6)}</style><body><div class="c">${num ? `<div class="n">${num}</div>` : ""}<div class="t">${esc(body)}</div></div></body>`, `cap${i}.png`, { x: 0, y: 0, width: W, height: CH }, true);
}
await art.close();

// ---- put it all together: video inside the phone, caption under the phone
mkdirSync(join(ROOT, "docs", "discord"), { recursive: true });
const out = join(ROOT, "docs", "discord", "viewer-tour.mp4");
const inputs = ["-f", "concat", "-safe", "0", "-i", join(frameDir, "list.txt"), "-loop", "1", "-i", join(assets, "bg.png"), "-loop", "1", "-i", join(assets, "bezel.png")];
spans.forEach((_, i) => inputs.push("-loop", "1", "-i", join(assets, `cap${i}.png`)));
let g = `[0:v]fps=30,scale=${SW}:${SH}:flags=lanczos[v];[1:v][v]overlay=${SX}:${SY}[a];[a][2:v]overlay=0:0[b0]`;
spans.forEach((sp, i) => { g += `;[b${i}][${3 + i}:v]overlay=0:${CY}:enable='between(t,${sp.start.toFixed(2)},${sp.end.toFixed(2)})'[b${i + 1}]`; });
g += `;[b${spans.length}]format=yuv420p[o]`;
const ff = spawnSync("ffmpeg", ["-y", ...inputs, "-filter_complex", g, "-map", "[o]", "-t", D.toFixed(2), "-c:v", "libx264", "-crf", "24", "-preset", "slow", "-movflags", "+faststart", "-an", out], { encoding: "utf8" });
if (ff.status !== 0) { console.error(ff.stderr.slice(-1200)); stop(); process.exit(1); }
console.log("wrote " + out);
stop(); rmSync(dir, { recursive: true, force: true }); process.exit(0);
