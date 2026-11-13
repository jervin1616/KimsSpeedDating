// Viewer profiles and dater sign-ups: shared checks (used by the server and by the tests).

// TikTok usernames are 2 to 24 letters, numbers, underscores and periods. Leading @ is optional.
export function normHandle(raw) {
  const h = String(raw == null ? "" : raw).trim().replace(/^@+/, "");
  return /^[A-Za-z0-9._]{2,24}$/.test(h) && !/^\.|\.$/.test(h) ? h : null;
}
export const handleKey = (h) => String(h).toLowerCase();

const GENDERS = ["man", "woman", "nonbinary"];
const SEXUALITIES = ["straight", "gay", "bi", "other"];
const isAge = (n) => Number.isInteger(n) && n >= 18 && n <= 99;
const toInt = (v) => (typeof v === "number" ? v : typeof v === "string" && /^\d{1,3}$/.test(v.trim()) ? parseInt(v, 10) : NaN);

// Checks a sign-up the same way the host's "Add dater" form checks a dater. Returns { ok, doc } or { ok:false, message }.
export function cleanSignup(b) {
  if (!b || typeof b !== "object") return { ok: false, message: "Nothing was sent." };
  const handle = normHandle(b.handle);
  if (!handle) return { ok: false, message: "Enter your TikTok username (2 to 24 letters, numbers, dots or underscores)." };
  const age = toInt(b.age);
  if (!isAge(age)) return { ok: false, message: "Age must be 18 or older." };
  const location = typeof b.location === "string" ? b.location.trim() : "";
  if (location.length < 2 || location.length > 20) return { ok: false, message: "Enter your state (2 to 20 characters)." };
  if (/\d{2,}.*\b(st|street|ave|avenue|road|rd|dr|drive|ln|lane|blvd)\b/i.test(location) || /\d/.test(location)) return { ok: false, message: "Use the state only, no city or street address." };
  if (!GENDERS.includes(b.gender)) return { ok: false, message: "Choose a gender." };
  if (!SEXUALITIES.includes(b.sexuality)) return { ok: false, message: "Choose a sexuality." };
  if (b.adult !== true) return { ok: false, message: "Confirm that you are 18 or older." };
  const doc = { name: handle, age, location, gender: b.gender, sexuality: b.sexuality };
  if (b.sexuality === "bi") {
    const r = { minM: toInt(b.minM), maxM: toInt(b.maxM), minW: toInt(b.minW), maxW: toInt(b.maxW) };
    if (!Object.values(r).every(isAge)) return { ok: false, message: "All age ranges must be 18 or older." };
    if (r.minM > r.maxM || r.minW > r.maxW) return { ok: false, message: "A minimum age cannot be higher than its maximum." };
    Object.assign(doc, r, { min: Math.min(r.minM, r.minW), max: Math.max(r.maxM, r.maxW) });
  } else {
    const min = toInt(b.min), max = toInt(b.max);
    if (!isAge(min) || !isAge(max)) return { ok: false, message: "Age range must be 18 or older." };
    if (min > max) return { ok: false, message: "Minimum age cannot be higher than maximum age." };
    Object.assign(doc, { min, max });
  }
  return { ok: true, handle, doc };
}
