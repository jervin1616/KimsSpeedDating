// Decides whether a dater the host is adding looks like someone who signed up. Nothing is merged automatically:
// the host always confirms. Works in the browser (window.SignupMatch) and in the tests (require).
(function (g) {
  function key(h) { return String(h == null ? "" : h).toLowerCase().replace(/^@+/, "").replace(/[._\-\s]/g, ""); }
  function lev(a, b) {
    var prev = [], i, j;
    for (j = 0; j <= b.length; j++) prev[j] = j;
    for (i = 1; i <= a.length; i++) {
      var cur = [i];
      for (j = 1; j <= b.length; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a.charAt(i - 1) === b.charAt(j - 1) ? 0 : 1));
      prev = cur;
    }
    return prev[b.length];
  }
  var same = function (x, y) { return !!x && !!y && String(x).trim().toLowerCase() === String(y).trim().toLowerCase(); };
  // c = what the host typed { name, age, location }, s = a sign-up { handle, age, location }.
  // "strong" = same username ignoring @, capitals, dots and underscores. "possible" = a username a letter or two off,
  // or one that contains the other, AND the same state or an age within a year.
  function compare(c, s) {
    var a = key(c.name), b = key(s.handle);
    if (!a || !b) return null;
    if (a === b) return "strong";
    var shorter = Math.min(a.length, b.length);
    if (shorter < 4) return null;
    var close = lev(a, b) <= 2 || a.indexOf(b) >= 0 || b.indexOf(a) >= 0;
    var ageNear = Number(c.age) > 0 && Number(s.age) > 0 && Math.abs(Number(c.age) - Number(s.age)) <= 1;
    return close && (same(c.location, s.location) || ageNear) ? "possible" : null;
  }
  function findMatches(candidate, list, skip) {
    var out = [];
    (list || []).forEach(function (s) {
      if (skip && skip[s.id]) return;
      var level = compare(candidate, s);
      if (level) out.push({ signup: s, level: level });
    });
    out.sort(function (x, y) { return (x.level === "strong" ? 0 : 1) - (y.level === "strong" ? 0 : 1); });
    return out.slice(0, 3);
  }
  var api = { key: key, lev: lev, compare: compare, findMatches: findMatches };
  g.SignupMatch = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
