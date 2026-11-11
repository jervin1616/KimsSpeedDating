// Access rules and input validation. Everything here is enforced on the server.

export const LEVEL = { none: 0, viewer: 1, contributor: 2, editor: 3 };

// Collections the app uses. Anything else is rejected.
// read / write = minimum role level needed.
export const RULES = {
  daters: { read: LEVEL.editor, write: LEVEL.editor, canAdd: true, max: 3000 },
  matches: { read: LEVEL.editor, write: LEVEL.editor, canAdd: true, max: 5000 },
  seats: { read: LEVEL.viewer, write: LEVEL.editor, canAdd: false, max: 400 },
  game: { read: LEVEL.viewer, write: LEVEL.contributor, canAdd: false, max: 1 },
  questions: { read: LEVEL.viewer, write: LEVEL.contributor, canAdd: true, max: 5000 },
};

// Question categories (the labels live in the page). 'chat' is for questions added by hand, 'other' is the fallback.
export const CATEGORY_KEYS = ["first", "date", "flirty", "love", "wyr", "tot", "funny", "food", "media", "travel", "memories", "deep", "life", "hot", "chat", "other"];

export const MAX_DOC_BYTES = 32 * 1024;
export const MAX_MESSAGE_BYTES = 64 * 1024;

const GENERIC_ID = /^[A-Za-z0-9_-]{1,64}$/;
const SEAT_ID = /^(hot|s[1-5]|banner|cohost|stream|stream_\d{10,16})$/;
const KEY = /^[A-Za-z0-9_]{1,40}$/;

export class RuleError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

export function isKnownCollection(coll) {
  return typeof coll === "string" && Object.prototype.hasOwnProperty.call(RULES, coll);
}

export function validDocId(coll, id) {
  if (typeof id !== "string") return false;
  if (coll === "seats") return SEAT_ID.test(id);
  if (coll === "game") return id === "question";
  return GENERIC_ID.test(id);
}

export function canRead(role, coll) {
  return isKnownCollection(coll) && LEVEL[role] >= RULES[coll].read;
}

export function canWrite(role, coll) {
  return isKnownCollection(coll) && LEVEL[role] >= RULES[coll].write;
}

// Parse "coll" or "coll/id". Returns null when the path is not valid.
export function parsePath(path) {
  if (typeof path !== "string" || path.length > 120) return null;
  const parts = path.split("/");
  if (parts.length < 1 || parts.length > 2) return null;
  const coll = parts[0];
  if (!isKnownCollection(coll)) return null;
  if (parts.length === 1) return { coll, id: null };
  if (!validDocId(coll, parts[1])) return null;
  return { coll, id: parts[1] };
}

function checkValue(v, depth) {
  if (v === null || typeof v === "boolean") return;
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new RuleError("failed-precondition", "Bad number.");
    return;
  }
  if (typeof v === "string") {
    if (v.length > 4000) throw new RuleError("failed-precondition", "Text too long.");
    return;
  }
  if (depth > 5) throw new RuleError("failed-precondition", "Too deeply nested.");
  if (Array.isArray(v)) {
    if (v.length > 1000) throw new RuleError("failed-precondition", "List too long.");
    for (const x of v) checkValue(x, depth + 1);
    return;
  }
  if (typeof v === "object") {
    const keys = Object.keys(v);
    if (keys.length > 60) throw new RuleError("failed-precondition", "Too many fields.");
    for (const k of keys) {
      if (!KEY.test(k) || k === "__proto__") throw new RuleError("failed-precondition", "Bad field name.");
      checkValue(v[k], depth + 1);
    }
    return;
  }
  throw new RuleError("failed-precondition", "Unsupported value.");
}

// Throws RuleError when the document is not acceptable. Returns the JSON text to store.
export function validateDoc(data) {
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new RuleError("failed-precondition", "A document must be an object.");
  }
  checkValue(data, 0);
  const text = JSON.stringify(data);
  if (text.length > MAX_DOC_BYTES) throw new RuleError("failed-precondition", "Document too large.");
  return text;
}

const ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz";
export function newId() {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let s = "";
  for (const b of bytes) s += ALPHABET[b % 36];
  return s;
}
