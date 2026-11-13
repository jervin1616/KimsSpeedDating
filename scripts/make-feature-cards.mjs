#!/usr/bin/env node
// Makes two shareable feature cards (PNG) for Discord: how to sign up as a speed dater, and how to turn on live notifications.
//   node scripts/make-feature-cards.mjs     -> docs/discord/card-speed-dater.png and docs/discord/card-notifications.png
// It runs a throwaway local copy of the app and takes real screenshots of the screens. No real people or data are involved.
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import crypto from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { chromium } = require("playwright");
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PORT = 8795, BASE = `http://127.0.0.1:${PORT}`;
const SECRET = crypto.randomBytes(32).toString("hex");
const b64u = (x) => Buffer.from(typeof x === "string" ? x : JSON.stringify(x)).toString("base64url");
const now = () => Math.floor(Date.now() / 1000);
const mint = (email) => { const body = b64u({ v: 1, e: email, i: now(), x: now() + 7200 }); return { token: body + "." + crypto.createHmac("sha256", SECRET).update(body).digest("base64url"), exp: now() + 7200, email, role: "viewer", owner: false }; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const dir = mkdtempSync(join(tmpdir(), "kim-cards-"));
const jwks = createServer((q, r) => { r.writeHead(200, { "content-type": "application/json" }); r.end('{"keys":[]}'); }).listen(0, "127.0.0.1");
await sleep(200);
const vk = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" });
const vars = { GOOGLE_CLIENT_ID: "x.apps.googleusercontent.com", GOOGLE_JWKS_URL: `http://127.0.0.1:${jwks.address().port}/k`, SESSION_SECRET: SECRET, ROLES: "owner@demo.test=owner", DEFAULT_ROLE: "viewer", MAX_VIEWERS: "50", ALLOWED_ORIGINS: "", VAPID_KEYS: [vk.x, vk.y, vk.d].join(".") };
const args = ["wrangler", "dev", "--port", String(PORT), "--ip", "127.0.0.1", "--inspector-port", "9243", "--persist-to", join(dir, "state"), "--local"];
for (const [k, v] of Object.entries(vars)) args.push("--var", `${k}:${v}`);
const w = spawn("npx", args, { cwd: ROOT, detached: true, env: { ...process.env, NO_PROXY: "127.0.0.1,localhost", WRANGLER_SEND_METRICS: "false", CI: "1" } });
const stop = () => { try { process.kill(-w.pid, "SIGKILL"); } catch {} jwks.close(); };
process.on("exit", stop);
for (let i = 0; i < 180; i++) { try { if ((await fetch(BASE + "/api/config")).ok) break; } catch {} await sleep(500); }

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, hasTouch: true, isMobile: true,
  userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1" });
await ctx.route(/fonts\.(googleapis|gstatic)\.com|accounts\.google\.com/, (r) => r.abort());
await ctx.addInitScript(() => { try { Object.defineProperty(Notification, "permission", { get: () => "default" }); } catch (e) {} }); // a fresh phone has not been asked yet
await ctx.addInitScript((sess) => { try { localStorage.setItem("sd.session.v1", JSON.stringify(sess)); localStorage.setItem("sd.installed", "1"); } catch (e) {} }, mint("viewer@demo.test"));
const page = await ctx.newPage();
await page.goto(BASE + "/");
await page.waitForSelector("#profileBox:not([hidden])", { timeout: 20000 });
await sleep(800);
await page.fill("#pbHandle", "@yourusername");
const shot = async (sel, name) => { const f = join(dir, name); await page.locator(sel).screenshot({ path: f }); return "data:image/png;base64," + readFileSync(f).toString("base64"); };
const imgProfile = await shot("#profileBox", "profile.png");
await page.click("#pbSignBtn");
await page.fill("#suHandle", "yourusername"); await page.fill("#suAge", "27"); await page.fill("#suLoc", "NC");
await page.selectOption("#suGender", "woman"); await page.selectOption("#suSex", "straight"); await page.fill("#suMin", "25"); await page.fill("#suMax", "35"); await page.check("#suAdult");
await sleep(300);
const imgForm = await shot("#suModal .card", "form.png");
await page.click("#suCancel");
await page.waitForSelector("#notifyBox:not([hidden])", { timeout: 10000 }).catch(() => {});
await page.locator("#notifyBox").scrollIntoViewIfNeeded();
const imgNotify = await page.locator("#notifyBox").isVisible() ? await shot("#notifyBox", "notify.png") : "";
const font = "data:font/woff2;base64," + readFileSync(join(ROOT, "public/fonts/lobster-two-700-italic.woff2")).toString("base64");

const css = `@font-face{font-family:Lobster;src:url(${font}) format("woff2");font-weight:700;font-style:italic}
*{box-sizing:border-box}body{margin:0;width:1080px;height:1350px;font-family:Inter,"Helvetica Neue",Arial,sans-serif;color:#fff;background:radial-gradient(circle at 50% 0%,#5a0a14 0%,#2a0508 50%,#140102 100%);position:relative;overflow:hidden}
.glow{position:absolute;left:-200px;top:-200px;width:700px;height:700px;border-radius:50%;background:rgba(255,45,85,.25);filter:blur(120px)}
.in{position:relative;padding:64px 70px;height:100%;display:flex;flex-direction:column}
.brand{font-family:Lobster;font-style:italic;font-weight:700;font-size:40px;color:#ff8fa8}
h1{font-family:Lobster;font-style:italic;font-weight:700;font-size:118px;line-height:1;margin:8px 0 10px;text-shadow:0 0 30px #ff2d55}
.sub{font-size:30px;color:#ffd5dc;margin:0 0 34px;max-width:900px}
.cols{display:grid;grid-template-columns:1fr 400px;gap:44px;flex:1;min-height:0}
.steps{display:flex;flex-direction:column;gap:24px}.s{display:grid;grid-template-columns:60px 1fr;gap:18px;align-items:start}
.n{width:56px;height:56px;border-radius:50%;background:#ff2d55;font-size:30px;font-weight:800;display:grid;place-items:center;box-shadow:0 0 22px rgba(255,45,85,.6)}
.t{font-size:31px;line-height:1.3}.t b{color:#fff}.t span{color:#ffd5dc;font-size:26px;display:block;margin-top:4px}
.shots{display:flex;flex-direction:column;gap:22px;align-items:center}.shots img{width:100%;border-radius:20px;border:2px solid rgba(255,255,255,.18);box-shadow:0 14px 40px rgba(0,0,0,.5)}
.note{display:flex;gap:14px;flex-wrap:wrap;margin-top:auto;padding-top:20px;font-size:25px;color:#ffd5dc}.pill{border:2px solid #ff4d6d;border-radius:999px;padding:8px 22px}
.banner{border-radius:22px;background:rgba(255,255,255,.95);color:#1d1a1b;padding:18px 22px;display:grid;grid-template-columns:64px 1fr;gap:16px;align-items:center;box-shadow:0 14px 40px rgba(0,0,0,.5);width:100%}
.banner .ic{width:64px;height:64px;border-radius:15px;background:linear-gradient(135deg,#8a1230,#ff2d55);display:grid;place-items:center;font-family:Lobster;font-style:italic;font-size:26px;color:#fff}
.banner b{font-size:22px;display:block}.banner span{font-size:22px}.cap{font-size:20px;color:#ffd5dc;text-align:center}`;
const card = (body) => `<style>${css}</style><body><div class="glow"></div><div class="in">${body}</div></body>`;
const steps = (list) => list.map((x, i) => `<div class="s"><div class="n">${i + 1}</div><div class="t">${x}</div></div>`).join("");

const c1 = card(`<div class="brand">Kim's Speed Dating</div><h1>Be a speed dater</h1><p class="sub">Want a seat on the show? Sign up in the app. The host approves you live.</p>
<div class="cols"><div class="steps">${steps([
  "<b>Open the app</b> and sign in with Google.",
  "<b>Add your TikTok username</b><span>It is how the host finds you.</span>",
  "<b>Tap \"Want to be a speed dater?\"</b><span>Add your age, state, and the ages you are looking for.</span>",
  "<b>Confirm you are 18 or older</b> and send it.",
  "<b>Watch for approval.</b> The host adds you live and you see \"You are on the speed dater list.\""])}</div>
<div class="shots"><img src="${imgProfile}"><img src="${imgForm}"></div></div>
<div class="note"><span class="pill">18+ only</span><span class="pill">State only, no addresses</span><span class="pill">Edit or withdraw anytime before approval</span></div>`);

const c2 = card(`<div class="brand">Kim's Speed Dating</div><h1>Never miss the start</h1><p class="sub">Get a heads up 1 hour before, 30 minutes before, and the moment we go live.</p>
<div class="cols"><div class="steps">${steps([
  "<b>iPhone:</b> open the app in Safari, tap Share, then <b>Add to Home Screen</b>. Open it from your home screen.<span>Needs iOS 16.4 or later.</span>",
  "<b>Android:</b> the browser works, or add it to your home screen.",
  "<b>Tap \"Notify me when we go live\"</b> and choose <b>Allow</b>.",
  "<b>That is it.</b> You will see the messages on your lock screen. Turn them off anytime in the app."])}</div>
<div class="shots">${imgNotify ? `<img src="${imgNotify}">` : ""}
<div class="banner"><div class="ic">KSD</div><div><b>Kim's Speed Dating</b><span>We go live in 1 hour (5:00 PM ET).</span></div></div>
<div class="banner"><div class="ic">KSD</div><div><b>Kim's Speed Dating</b><span>We are live now!</span></div></div>
<div class="cap">Example notifications</div></div></div>
<div class="note"><span class="pill">Free</span><span class="pill">Your choice, turn off anytime</span><span class="pill">Silent or Focus mode can hide them</span></div>`);

mkdirSync(join(ROOT, "docs", "discord"), { recursive: true });
const art = await browser.newPage({ viewport: { width: 1080, height: 1350 } });
for (const [html, name] of [[c1, "card-speed-dater.png"], [c2, "card-notifications.png"]]) { await art.setContent(html, { waitUntil: "load" }); await sleep(300); await art.screenshot({ path: join(ROOT, "docs", "discord", name) }); console.log("wrote docs/discord/" + name); }
await browser.close(); stop(); rmSync(dir, { recursive: true, force: true }); process.exit(0);
