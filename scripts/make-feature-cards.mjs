#!/usr/bin/env node
// Makes two shareable feature cards (PNG) for Discord: how to sign up as a speed dater, and how to turn on live notifications.
//   node scripts/make-feature-cards.mjs     -> six PNG cards in docs/discord/ (sign up as a speed dater, notifications, question button, the board, home screen, good to know)
// It runs a throwaway local copy of the app and takes real screenshots of the screens. No real people or data are involved.
import { spawn, spawnSync } from "node:child_process";
import WebSocket from "ws";
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
const vars = { GOOGLE_CLIENT_ID: "x.apps.googleusercontent.com", GOOGLE_JWKS_URL: `http://127.0.0.1:${jwks.address().port}/k`, SESSION_SECRET: SECRET, ROLES: "owner@demo.test=owner", ADMIN_KEY: crypto.randomBytes(24).toString("hex"), DEFAULT_ROLE: "viewer", MAX_VIEWERS: "50", ALLOWED_ORIGINS: "", VAPID_KEYS: [vk.x, vk.y, vk.d].join(".") };
const args = ["wrangler", "dev", "--port", String(PORT), "--ip", "127.0.0.1", "--inspector-port", "9243", "--persist-to", join(dir, "state"), "--local"];
for (const [k, v] of Object.entries(vars)) args.push("--var", `${k}:${v}`);
const w = spawn("npx", args, { cwd: ROOT, detached: true, env: { ...process.env, NO_PROXY: "127.0.0.1,localhost", WRANGLER_SEND_METRICS: "false", CI: "1" } });
const stop = () => { try { process.kill(-w.pid, "SIGKILL"); } catch {} jwks.close(); };
process.on("exit", stop);
for (let i = 0; i < 180; i++) { try { if ((await fetch(BASE + "/api/config")).ok) break; } catch {} await sleep(500); }

// sample show: the public question packs (sorted into categories) and made-up people on the board
const owner = mint("owner@demo.test");
const imp = spawnSync("node", ["scripts/import.mjs", "--url", BASE, "--dir", "content"], { cwd: ROOT, env: { ...process.env, ADMIN_KEY: vars.ADMIN_KEY }, encoding: "utf8" });
if (imp.status !== 0) { console.error(imp.stderr); stop(); process.exit(1); }
const ownerCall = (path) => fetch(BASE + path, { method: "POST", headers: { Authorization: "Bearer " + owner.token, "content-type": "application/json" }, body: path.includes("pack") ? '{"name":"hot-seat"}' : "{}" }).then((r) => r.text());
await ownerCall("/api/categorize"); await ownerCall("/api/pack");
const ws = new WebSocket(BASE.replace("http", "ws") + "/api/ws", ["kim-v1", owner.token], { headers: { Origin: BASE } });
await new Promise((r) => ws.on("open", r));
let rid = 1; const put = (coll, id, data) => ws.send(JSON.stringify({ t: "w", rid: rid++, op: "set", coll, id, data }));
const P = (name, age, loc, gs, rng, status, label) => ({ name, age, location: loc, gs, rng, status, label });
const seat = (key, view) => put("seats", key, { dater: view ? { id: key, name: view.name } : null, view, since: view ? Date.now() - 95000 : null, ...(["banner", "cohost"].includes(key) ? { unlocked: false } : {}) });
["banner", "cohost"].forEach((k) => seat(k, null));
seat("hot", P("Jordan", 28, "NC", "M \u00b7 Straight", ["Wants 24-34"], "hot", ""));
seat("s1", P("Ava", 26, "TX", "W \u00b7 Straight", ["Wants 25-35"], "mutual", "Fits both"));
seat("s2", P("Riley", 24, "OH", "W \u00b7 Bi", ["Men 24-30", "Women 22-28"], "close", "Off by 2 yrs"));
seat("s3", P("Sam", 36, "CA", "W \u00b7 Straight", ["Wants 30-42"], "nofit", "Off by 5 yrs"));
seat("s4", P("Taylor", 29, "GA", "W \u00b7 Straight", ["Wants 26-36"], "mutual", "Fits both"));
seat("s5", P("Casey", 27, "VA", "W \u00b7 Straight", ["Wants 24-34"], "close", "Off by 1 yr"));
put("game", "question", { text: "What's one thing you'd never do on a first date?", handle: "", qid: "", hist: [] });
await sleep(800);

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
await page.selectOption("#myCat", "dilemma"); await sleep(400);
const imgQuestion = await shot("#myQBox", "question.png");
const sb = await page.locator(".stage").boundingBox(), lb = await page.locator(".stage .legend").boundingBox();
const sy = await page.evaluate(() => window.scrollY);
await page.screenshot({ path: join(dir, "board.png"), fullPage: true, clip: { x: sb.x, y: sb.y + sy, width: sb.width, height: lb.y + lb.height - sb.y + 12 } }); // hearts and the colour key, not the question boxes below
const imgBoard = "data:image/png;base64," + readFileSync(join(dir, "board.png")).toString("base64");
// a phone that has not added the app yet sees the install card
const ctx2 = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, hasTouch: true, isMobile: true, userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1" });
await ctx2.route(/fonts\.(googleapis|gstatic)\.com|accounts\.google\.com/, (r) => r.abort());
await ctx2.addInitScript((sess) => { try { localStorage.setItem("sd.session.v1", JSON.stringify(sess)); } catch (e) {} }, mint("viewer2@demo.test"));
const pg2 = await ctx2.newPage(); await pg2.goto(BASE + "/"); await pg2.waitForSelector("#installTip:not([hidden])", { timeout: 20000 }); await sleep(500);
const shot2 = async (sel, name) => { const f = join(dir, name); await pg2.locator(sel).screenshot({ path: f }); return "data:image/png;base64," + readFileSync(f).toString("base64"); };
const imgInstall = await shot2("#installTip", "install.png");
await pg2.click("#installBtn"); await sleep(400);
const imgGuide = await shot2("#howOv .how", "guide.png");
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

const dot = (c) => `<span style="display:inline-block;width:22px;height:22px;border-radius:50%;background:${c};margin-right:10px;vertical-align:-3px"></span>`;
const c3 = card(`<div class="brand">Kim's Speed Dating</div><h1>Your own question button</h1><p class="sub">Stuck for something to ask? Get a question that only you can see.</p>
<div class="cols"><div class="steps">${steps([
  "<b>Open the app</b> and scroll to <b>Your own question</b>.",
  "<b>Tap \"Random question for me.\"</b> A new one every time.",
  "<b>Pick a category</b> to narrow it down.<span>First dates, flirty, would you rather, what would you do, confessions, hot takes and more.</span>",
  "<b>It is private.</b> It never changes what is on the stream."])}</div>
<div class="shots"><img src="${imgQuestion}"><div style="display:flex;flex-wrap:wrap;gap:10px;justify-content:center">${["First dates", "About your date", "Flirty", "Would you rather", "What would you do?", "Confessions & icks", "Hot takes & debates", "Deep & personal", "Food & drink", "Funny & silly"].map((x) => `<span class="pill" style="font-size:22px;padding:6px 16px">${x}</span>`).join("")}</div></div></div>
<div class="note"><span class="pill">Only you see it</span><span class="pill">16 categories</span><span class="pill">1,700+ questions</span></div>`);
const c4 = card(`<div class="brand">Kim's Speed Dating</div><h1>Read the board</h1><p class="sub">Who is on the date, who is waiting, and how well they fit. It updates live.</p>
<div class="cols"><div class="steps">${steps([
  "<b>The big heart at the bottom is the hot seat.</b> That is who is on the date right now.",
  "<b>The panel hearts are the people waiting</b> to be picked.",
  `<b>The colors show the fit</b> with the hot seat.<span>${dot("#2fd685")}Green: fits both<br>${dot("#ffd23f")}Yellow: close, off by 1 to 2 years<br>${dot("#ff4d6d")}Red: 3 or more years off, or a mismatch</span>`,
  "<b>Nothing to refresh.</b> It changes by itself."])}</div>
<div class="shots"><img src="${imgBoard}"></div></div>
<div class="note"><span class="pill">Live</span><span class="pill">View only</span><span class="pill">Only approved speed daters appear</span></div>`);
const c5 = card(`<div class="brand">Kim's Speed Dating</div><h1>Put it on your home screen</h1><p class="sub">One tap to open, full screen, no browser bars.</p>
<div class="cols"><div class="steps">${steps([
  "<b>Tap Add</b> on the install card in the app. It shows the steps for your phone.",
  "<b>iPhone:</b> open it in Safari, tap Share, then <b>Add to Home Screen</b>, then <b>Add</b>.",
  "<b>Android:</b> open it in Chrome, tap the menu (three dots), then <b>Install app</b> or <b>Add to Home screen</b>.",
  "<b>Open it from your home screen.</b> Then tap <b>I have added it</b> and the reminder goes away."])}</div>
<div class="shots"><img src="${imgInstall}"><img src="${imgGuide}"></div></div>
<div class="note"><span class="pill">Free</span><span class="pill">Works like an app</span><span class="pill">Needed for iPhone notifications</span></div>`);
const faq = [["Is it free?", "Yes. Just sign in with Google."], ["Do I need Gmail?", "No. Any email works if you have a Google account with it. Make one at accounts.google.com/signup and choose \"Use my existing email address.\""], ["Can I change anything on stream?", "No. It is view only."], ["I see \"Full.\"", "The room holds 500 at a time. Tap it and try again in a minute."], ["The pill says Offline.", "Your connection dropped. It reconnects by itself. Reload if it stays red."], ["What do you keep about me?", "Your email, and your TikTok username if you add one. Privacy and Terms are at the bottom of the page."]];
const c6 = card(`<div class="brand">Kim's Speed Dating</div><h1>Good to know</h1><p class="sub">Quick answers before you ask.</p>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:18px 26px;align-content:start">${faq.map(([q, a]) => `<div style="border:2px solid rgba(255,77,109,.55);border-radius:20px;padding:18px 24px;background:rgba(255,255,255,.04)"><div style="font-size:28px;font-weight:800;color:#fff;margin-bottom:4px">${q}</div><div style="font-size:24px;color:#ffd5dc;line-height:1.35">${a}</div></div>`).join("")}</div>
<div class="note"><span class="pill">Free</span><span class="pill">18+ only</span><span class="pill">View only</span></div>`);
mkdirSync(join(ROOT, "docs", "discord"), { recursive: true });
const art = await browser.newPage({ viewport: { width: 1080, height: 1350 } });
for (const [html, name] of [[c1, "card-speed-dater.png"], [c2, "card-notifications.png"], [c3, "card-question-button.png"], [c4, "card-board.png"], [c5, "card-home-screen.png"], [c6, "card-good-to-know.png"]]) { await art.setContent(html, { waitUntil: "load" }); await sleep(300); await art.screenshot({ path: join(ROOT, "docs", "discord", name) }); console.log("wrote docs/discord/" + name); }
await browser.close(); stop(); rmSync(dir, { recursive: true, force: true }); process.exit(0);
