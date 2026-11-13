// Eastern time helpers for the "we are going live" scheduler (handles winter and summer time).
(function (g) {
  var ZONE = "America/New_York";
  function parts(ms) {
    var f = new Intl.DateTimeFormat("en-US", { timeZone: ZONE, hourCycle: "h23", year: "numeric", month: "numeric", day: "numeric", hour: "numeric", minute: "numeric" }), o = {};
    f.formatToParts(new Date(ms)).forEach(function (p) { o[p.type] = Number(p.value); });
    return o;
  }
  function offset(ms) { var p = parts(ms); return Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute) - Math.floor(ms / 60000) * 60000; } // ET minus UTC, in ms (negative)
  // "2026-12-15" and "17:00", read as Eastern time, to a UTC timestamp.
  function etToUtcMs(dateStr, timeStr) {
    var d = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateStr || ""), t = /^(\d{1,2}):(\d{2})$/.exec(timeStr || "");
    if (!d || !t) return NaN;
    var wall = Date.UTC(+d[1], +d[2] - 1, +d[3], +t[1], +t[2]), utc = wall - offset(wall);
    return wall - offset(utc);
  }
  function fmtEt(ms, withDay) {
    var o = withDay ? { weekday: "short", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" } : { hour: "numeric", minute: "2-digit" };
    return new Intl.DateTimeFormat("en-US", Object.assign({ timeZone: ZONE }, o)).format(new Date(ms)).replace(/ /g, " ");
  }
  function todayEt() { var p = parts(Date.now()); return p.year + "-" + String(p.month).padStart(2, "0") + "-" + String(p.day).padStart(2, "0"); }
  var api = { etToUtcMs: etToUtcMs, fmtEt: fmtEt, todayEt: todayEt };
  g.EtTime = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
