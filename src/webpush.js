// Web Push from a Worker, with nothing but WebCrypto: RFC 8291 (aes128gcm encryption) and RFC 8292 (VAPID).
const enc = new TextEncoder();

export function b64u(bytes) {
  let s = ""; for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function unb64u(str) {
  const pad = "=".repeat((4 - (str.length % 4)) % 4), bin = atob(String(str).replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out;
}
const cat = (...parts) => { const n = parts.reduce((a, p) => a + p.length, 0), o = new Uint8Array(n); let i = 0; for (const p of parts) { o.set(p, i); i += p.length; } return o; };

// VAPID_KEYS is "x.y.d" (three base64url parts, what scripts/make-vapid.mjs prints) or a JWK as JSON.
function vapidJwk(env) {
  const raw = String(env.VAPID_KEYS || "").trim();
  if (!raw) return null;
  try {
    if (raw.startsWith("{")) { const j = JSON.parse(raw); return j.x && j.y && j.d ? { kty: "EC", crv: "P-256", x: j.x, y: j.y, d: j.d, ext: true } : null; }
    const [x, y, d] = raw.split("."); return x && y && d ? { kty: "EC", crv: "P-256", x, y, d, ext: true } : null;
  } catch (e) { return null; }
}
export function pushConfigured(env) { return !!vapidJwk(env); }
export function vapidPublicKey(env) {
  const j = vapidJwk(env); return j ? b64u(cat(new Uint8Array([4]), unb64u(j.x), unb64u(j.y))) : "";
}

let keyCache = { raw: null, key: null };
async function signingKey(env) {
  const j = vapidJwk(env); const raw = JSON.stringify(j);
  if (keyCache.raw !== raw) keyCache = { raw, key: await crypto.subtle.importKey("jwk", j, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]) };
  return keyCache.key;
}
const jwtCache = new Map(); // audience -> { jwt, exp }; one signature per push service per half day
async function vapidAuth(env, audience, subject) {
  const now = Math.floor(Date.now() / 1000), hit = jwtCache.get(audience);
  let jwt;
  if (hit && hit.exp - now > 3600) jwt = hit.jwt;
  else {
    const exp = now + 12 * 3600, head = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" }))), body = b64u(enc.encode(JSON.stringify({ aud: audience, exp, sub: subject })));
    const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, await signingKey(env), enc.encode(head + "." + body));
    jwt = head + "." + body + "." + b64u(sig); jwtCache.set(audience, { jwt, exp });
  }
  return "vapid t=" + jwt + ", k=" + vapidPublicKey(env);
}

// Encrypts `payload` (bytes) for one subscription { p256dh, auth }. Returns the request body.
export async function encryptPayload(sub, payload) {
  const ua = unb64u(sub.p256dh), auth = unb64u(sub.auth);
  const uaKey = await crypto.subtle.importKey("raw", ua, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const eph = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPub = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const secret = await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, eph.privateKey, 256);
  const hkdf = async (ikm, salt, info, bits) => crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]), bits);
  const ikm = await hkdf(secret, auth, cat(enc.encode("WebPush: info\0"), ua, asPub), 256);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(ikm, salt, enc.encode("Content-Encoding: aes128gcm\0"), 128);
  const nonce = await hkdf(ikm, salt, enc.encode("Content-Encoding: nonce\0"), 96);
  const aes = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, cat(payload, new Uint8Array([2]))));
  return cat(salt, new Uint8Array([0, 0, 16, 0]), new Uint8Array([65]), asPub, ct);
}

// Sends one notification. Returns { ok, status, gone } and never throws.
export async function sendPush(env, sub, message, subject) {
  try {
    const url = new URL(sub.endpoint);
    const body = await encryptPayload(sub, enc.encode(JSON.stringify(message)));
    const res = await fetch(sub.endpoint, { method: "POST", headers: { "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", TTL: "3600", Urgency: "high", Authorization: await vapidAuth(env, url.origin, subject) }, body });
    try { await res.arrayBuffer(); } catch (e) { /* ignore */ }
    return { ok: res.status >= 200 && res.status < 300, status: res.status, gone: res.status === 404 || res.status === 410 };
  } catch (e) { return { ok: false, status: 0, gone: false }; }
}

// Only real push services (or the local test server when ALLOW_INSECURE_PUSH is set) may be called.
const HOSTS = [/(^|\.)googleapis\.com$/, /(^|\.)push\.services\.mozilla\.com$/, /(^|\.)push\.apple\.com$/, /(^|\.)notify\.windows\.com$/];
export function okEndpoint(env, endpoint) {
  try {
    const u = new URL(endpoint);
    if (env.ALLOW_INSECURE_PUSH === "1" && u.protocol === "http:" && (u.hostname === "127.0.0.1" || u.hostname === "localhost")) return true;
    return u.protocol === "https:" && u.username === "" && u.password === "" && HOSTS.some((r) => r.test(u.hostname)) && endpoint.length <= 600;
  } catch (e) { return false; }
}
export function okKeys(p256dh, auth) {
  try { const a = unb64u(p256dh), b = unb64u(auth); return a.length === 65 && a[0] === 4 && b.length === 16; } catch (e) { return false; }
}
