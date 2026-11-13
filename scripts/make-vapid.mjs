#!/usr/bin/env node
// Makes the key pair that "we are going live" phone notifications need. Run it on your own computer:
//   node scripts/make-vapid.mjs
// It prints ONE secret line. Save it with:  npx wrangler secret put VAPID_KEYS   (paste the line when asked)
// The public half is not secret and is sent to the page automatically. Nothing is written to any file.
import { webcrypto as crypto } from "node:crypto";
const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const j = await crypto.subtle.exportKey("jwk", kp.privateKey);
console.log("\nYour VAPID_KEYS secret (keep it private, do not paste it into a chat or commit it):\n");
console.log([j.x, j.y, j.d].join("."));
console.log("\nNext: run  npx wrangler secret put VAPID_KEYS  and paste the line above when it asks.\n");
