// "We are going live" announcements: the three messages, and how a time is written for people (Eastern time).
export const STEPS = [["1h", 3600], ["30m", 1800], ["live", 0]]; // kind, seconds before going live
export const STEPS_TWO = [["1h", 3600], ["live", 0]]; // the daily default: no 30 minute message

// The Eastern calendar day ("2026-11-14") and wall time ("17:00") of a moment.
export function etDay(ms) { return new Intl.DateTimeFormat("en-CA", { timeZone: "America/New_York" }).format(new Date(ms)); }
export function etHm(ms) { return new Intl.DateTimeFormat("en-GB", { timeZone: "America/New_York", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).format(new Date(ms)); }

export function fmtEt(ms, withDay) {
  const o = withDay ? { weekday: "short", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" } : { hour: "numeric", minute: "2-digit" };
  return new Intl.DateTimeFormat("en-US", { timeZone: "America/New_York", ...o }).format(new Date(ms)).replace(/ /g, " ");
}

// { title, body, discord } for one step. `origin` is the site address.
// The 1 hour and 30 minute posts link to the TikTok profile (works whether or not the live is on); the live-now post links to the profile's /live page. Phone notifications open the app.
export const DISCORD_LINK = "https://www.tiktok.com/@kimbrrlee8";
export const DISCORD_LIVE_LINK = DISCORD_LINK + "/live"; // the "we are live now" post drops people straight into the live

export function messageFor(kind, liveAtMs, origin) {
  const t = fmtEt(liveAtMs) + " ET";
  const body = kind === "1h" ? `We go live in 1 hour (${t}).` : kind === "30m" ? `30 minutes until we go live (${t}).` : "We are live now!";
  return { title: "Kim's Speed Dating", body, discord: (kind === "live" ? "**We are live now!** ❤️‍🔥" : "**" + body + "** ❤️‍🔥") + "\n" + (kind === "live" ? DISCORD_LIVE_LINK : DISCORD_LINK) };
}

export function okWebhook(env, u) {
  try {
    const x = new URL(u);
    if (env.ALLOW_INSECURE_PUSH === "1" && x.protocol === "http:" && (x.hostname === "127.0.0.1" || x.hostname === "localhost")) return true;
    return x.protocol === "https:" && /^(discord|discordapp)\.com$/.test(x.hostname) && /^\/api\/webhooks\/\d+\/[\w-]+$/.test(x.pathname);
  } catch (e) { return false; }
}
