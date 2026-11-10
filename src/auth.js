// Google sign-in verification, role lookup, and our own signed session tokens.
import { LEVEL } from "./rules.js";

const enc = new TextEncoder();
const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"];
const MAX_SESSION_AGE_S = 7 * 24 * 3600; // a session can be refreshed for up to 7 days

export function b64uDecode(s) {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export function b64uEncode(bytes) {
  let bin = "";
  for (const b of new Uint8Array(bytes)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function jsonFromB64u(s) {
  return JSON.parse(new TextDecoder().decode(b64uDecode(s)));
}

/* ---------- roles ---------- */

// ROLES secret: "a@x.com=editor, b@y.com=contributor; c@z.com=viewer" (commas, semicolons or new lines)
// or a JSON object {"a@x.com":"editor"}.
let rolesCache = { raw: null, map: new Map() };
export function parseRoles(raw) {
  if (rolesCache.raw === raw) return rolesCache.map;
  const map = new Map();
  const put = (email, role) => {
    email = String(email || "").trim().toLowerCase();
    role = String(role || "").trim().toLowerCase();
    if (email && (role === "editor" || role === "contributor" || role === "viewer")) map.set(email, role);
  };
  const text = String(raw || "").trim();
  if (text.startsWith("{")) {
    try {
      const obj = JSON.parse(text);
      for (const [k, v] of Object.entries(obj)) put(k, v);
    } catch (e) { /* ignore: nobody gets access */ }
  } else {
    for (const part of text.split(/[,;\n]+/)) {
      const i = part.indexOf("=");
      if (i > 0) put(part.slice(0, i), part.slice(i + 1));
    }
  }
  rolesCache = { raw, map };
  return map;
}

export function defaultRole(env) {
  const r = String(env.DEFAULT_ROLE || "none").trim().toLowerCase();
  // The default role can never be editor, on purpose.
  return r === "viewer" || r === "contributor" ? r : "none";
}

export function roleFor(env, email) {
  const role = parseRoles(env.ROLES).get(String(email || "").toLowerCase());
  return role || defaultRole(env);
}

/* ---------- Google ID token ---------- */

let jwksCache = { keys: null, at: 0, expires: 0 };

async function loadJwks(env, force) {
  const now = Date.now();
  if (jwksCache.keys && !force && now < jwksCache.expires) return jwksCache.keys;
  if (jwksCache.keys && force && now - jwksCache.at < 60000) return jwksCache.keys; // do not hammer Google
  const res = await fetch(env.GOOGLE_JWKS_URL || GOOGLE_JWKS_URL);
  if (!res.ok) throw new Error("Could not load Google keys.");
  const body = await res.json();
  const m = /max-age=(\d+)/.exec(res.headers.get("cache-control") || "");
  const ttl = Math.min(Math.max(m ? Number(m[1]) : 3600, 300), 6 * 3600) * 1000;
  jwksCache = { keys: body.keys || [], at: now, expires: now + ttl };
  return jwksCache.keys;
}

// Returns { email, name } or throws Error("reason").
export async function verifyGoogleToken(idToken, env) {
  if (!env.GOOGLE_CLIENT_ID) throw new Error("Sign-in is not configured.");
  if (typeof idToken !== "string" || idToken.length > 5000) throw new Error("Bad token.");
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("Bad token.");
  let header, payload;
  try {
    header = jsonFromB64u(parts[0]);
    payload = jsonFromB64u(parts[1]);
  } catch (e) {
    throw new Error("Bad token.");
  }
  if (header.alg !== "RS256" || typeof header.kid !== "string") throw new Error("Bad token.");

  let keys = await loadJwks(env, false);
  let jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) {
    keys = await loadJwks(env, true);
    jwk = keys.find((k) => k.kid === header.kid);
  }
  if (!jwk) throw new Error("Unknown signing key.");
  const key = await crypto.subtle.importKey("jwk", { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64uDecode(parts[2]), enc.encode(parts[0] + "." + parts[1]));
  if (!ok) throw new Error("Bad signature.");

  const now = Math.floor(Date.now() / 1000);
  if (!GOOGLE_ISSUERS.includes(payload.iss)) throw new Error("Wrong issuer.");
  if (payload.aud !== env.GOOGLE_CLIENT_ID) throw new Error("Wrong audience.");
  if (typeof payload.exp !== "number" || payload.exp + 30 < now) throw new Error("Token expired.");
  if (typeof payload.iat === "number" && payload.iat - 300 > now) throw new Error("Token from the future.");
  if (payload.email_verified !== true && payload.email_verified !== "true") throw new Error("Email not verified.");
  if (typeof payload.email !== "string" || !payload.email.includes("@")) throw new Error("No email.");
  return { email: payload.email.toLowerCase(), name: typeof payload.name === "string" ? payload.name : "" };
}

/* ---------- our own session token ---------- */

async function hmacKey(env, usage) {
  const secret = String(env.SESSION_SECRET || "");
  if (secret.length < 32) throw new Error("SESSION_SECRET is missing or too short.");
  return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [usage]);
}

export function sessionHours(env) {
  const h = Number(env.SESSION_HOURS);
  return Number.isFinite(h) && h >= 1 && h <= 72 ? h : 12;
}

// iat = when the very first Google login happened (kept across refreshes).
export async function mintSession(env, email, iat) {
  const now = Math.floor(Date.now() / 1000);
  const payload = { v: 1, e: email, i: iat || now, x: now + Math.floor(sessionHours(env) * 3600) };
  const body = b64uEncode(enc.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(env, "sign"), enc.encode(body));
  return { token: body + "." + b64uEncode(sig), exp: payload.x, iat: payload.i };
}

// Returns { email, exp, iat } or null.
export async function verifySession(env, token) {
  if (typeof token !== "string" || token.length > 1000) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  try {
    const ok = await crypto.subtle.verify("HMAC", await hmacKey(env, "verify"), b64uDecode(parts[1]), enc.encode(parts[0]));
    if (!ok) return null;
    const p = jsonFromB64u(parts[0]);
    const now = Math.floor(Date.now() / 1000);
    if (p.v !== 1 || typeof p.e !== "string" || typeof p.x !== "number" || typeof p.i !== "number") return null;
    if (p.x <= now) return null;
    return { email: p.e, exp: p.x, iat: p.i };
  } catch (e) {
    return null;
  }
}

export function canRefresh(session) {
  return Math.floor(Date.now() / 1000) - session.iat < MAX_SESSION_AGE_S;
}

export async function safeEqual(a, b) {
  const x = enc.encode(String(a)), y = enc.encode(String(b));
  if (x.length !== y.length) return false;
  return crypto.subtle.timingSafeEqual(x, y);
}

export { LEVEL };
