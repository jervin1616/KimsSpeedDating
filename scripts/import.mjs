#!/usr/bin/env node
// Loads every .json file in the data folder into the Worker's database.
// Ids and every field are preserved. Safe to run more than once (it upserts by id).
//
//   ADMIN_KEY=... node scripts/import.mjs --url https://YOUR-WORKER.workers.dev [--dir data] [--dry-run]
//   add  --replace --yes  to first erase the collections found in the files (you must pass both flags)
//
// The key is read from the ADMIN_KEY environment variable so it never lands in your shell history
// as a command argument and is never printed.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const args = process.argv.slice(2);
const opt = (name, dflt) => { const i = args.indexOf("--" + name); return i >= 0 ? (args[i + 1] && !args[i + 1].startsWith("--") ? args[i + 1] : true) : dflt; };
const url = String(opt("url", "")).replace(/\/+$/, "");
const dir = String(opt("dir", "data"));
const dry = !!opt("dry-run", false);
const replace = !!opt("replace", false);
const yes = !!opt("yes", false);
const key = process.env.ADMIN_KEY || "";

function die(msg) { console.error("Error: " + msg); process.exit(1); }
if (!dry && !/^https?:\/\//.test(url)) die("Give the Worker address with --url https://YOUR-WORKER.workers.dev");
if (!dry && key.length < 24) die("Set the ADMIN_KEY environment variable (see DEPLOY.md).");
if (replace && !yes) die("--replace erases data. Add --yes to confirm you want that.");

const CHUNK = 100;
const docs = []; // { coll, id, data }
const seen = new Set();
function add(coll, id, data) {
  if (!id || typeof id !== "string") die(`A ${coll} record has no id.`);
  const k = coll + "/" + id;
  if (seen.has(k)) { console.warn("  duplicate skipped: " + k); return; }
  seen.add(k); docs.push({ coll, id, data });
}
function rows(coll, list) {
  for (const r of list) { const { id, ...rest } = r; add(coll, id, rest); }
}

let files;
try { files = readdirSync(dir).filter((f) => f.toLowerCase().endsWith(".json")).sort(); } catch (e) { die(`Cannot read the folder "${dir}".`); }
if (!files.length) die(`No .json files in "${dir}".`);

for (const f of files) {
  let j;
  try { j = JSON.parse(readFileSync(join(dir, f), "utf8")); } catch (e) { die(`${f} is not valid JSON.`); }
  console.log("Reading " + f);
  const base = f.replace(/\.json$/i, "").toLowerCase();
  if (Array.isArray(j)) { // a bare list named after its collection, e.g. daters.json
    if (["daters", "questions", "matches", "seats"].includes(base)) rows(base, j);
    else if (base === "streams") rows("seats", j);
    else console.warn("  skipped (a bare list needs a file name like daters.json)");
    continue;
  }
  for (const c of ["daters", "questions", "matches", "seats"]) if (Array.isArray(j[c])) rows(c, j[c]);
  if (Array.isArray(j.streams)) {
    for (const s of j.streams) { const { id, ...rest } = s; add("seats", id || "stream_" + rest.startedAt, rest); }
  }
  if (j.game && typeof j.game === "object") {
    const g = j.game.question && typeof j.game.question === "object" ? { ...j.game.question, hist: j.game.hist || [] } : j.game;
    add("game", "question", { text: g.text || "", handle: g.handle || "", qid: g.qid || "", hist: Array.isArray(g.hist) ? g.hist : [] });
  }
}

const tally = {};
for (const d of docs) tally[d.coll] = (tally[d.coll] || 0) + 1;
console.log("\nReady to import " + docs.length + " records: " + Object.entries(tally).map(([k, v]) => `${k} ${v}`).join(", "));
if (dry) { console.log("Dry run: nothing was sent."); process.exit(0); }

async function post(body) {
  const r = await fetch(url + "/api/import", { method: "POST", headers: { Authorization: "Bearer " + key, "content-type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) die(`The server refused (${r.status}): ${j.error || ""} ${j.message || ""}`.trim());
  return j;
}

let last = null;
if (replace) {
  const wipe = Object.keys(tally).filter((c) => c !== "game");
  console.log("Erasing first: " + wipe.join(", "));
  last = await post({ docs: [], wipe });
}
let done = 0;
for (let i = 0; i < docs.length; i += CHUNK) {
  last = await post({ docs: docs.slice(i, i + CHUNK) });
  done += last.written;
  process.stdout.write(`\rImported ${done} / ${docs.length}`);
}
console.log("\n\nThe database now holds: " + Object.entries(last.counts).map(([k, v]) => `${k} ${v}`).join(", "));
let bad = 0;
for (const [c, n] of Object.entries(tally)) if ((last.counts[c] || 0) < n) { bad++; console.error(`MISSING: ${c} expected at least ${n}, found ${last.counts[c] || 0}`); }
if (bad) process.exit(2);
console.log("Check passed: every collection has at least as many records as the files.");
