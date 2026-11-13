// Decides whether two people might be the same: a dater the host is adding (or already has) and someone who signed up.
// It scores how alike the names are (typos, sounds-alike spellings, a first name against a username, trailing numbers)
// and nudges the score with the state and age. Nothing is merged automatically: the host always confirms.
// Works in the browser (window.SignupMatch) and in the tests (loaded as a plain script).
(function (g) {
  var STATES = { alabama: "al", alaska: "ak", arizona: "az", arkansas: "ar", california: "ca", colorado: "co", connecticut: "ct", delaware: "de", florida: "fl", georgia: "ga", hawaii: "hi", idaho: "id", illinois: "il", indiana: "in", iowa: "ia", kansas: "ks", kentucky: "ky", louisiana: "la", maine: "me", maryland: "md", massachusetts: "ma", michigan: "mi", minnesota: "mn", mississippi: "ms", missouri: "mo", montana: "mt", nebraska: "ne", nevada: "nv", newhampshire: "nh", newjersey: "nj", newmexico: "nm", newyork: "ny", northcarolina: "nc", northdakota: "nd", ohio: "oh", oklahoma: "ok", oregon: "or", pennsylvania: "pa", rhodeisland: "ri", southcarolina: "sc", southdakota: "sd", tennessee: "tn", texas: "tx", utah: "ut", vermont: "vt", virginia: "va", washington: "wa", westvirginia: "wv", wisconsin: "wi", wyoming: "wy", districtofcolumbia: "dc" };
  function squash(s) { return String(s == null ? "" : s).toLowerCase().replace(/^@+/, "").normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]/g, ""); }
  function letters(s) { return squash(s).replace(/[0-9]/g, ""); }
  function key(h) { return squash(h); } // kept for the older callers
  // edit distance that counts a swapped pair of letters as one slip
  function dl(a, b) {
    var d = [], i, j;
    for (i = 0; i <= a.length; i++) { d[i] = [i]; }
    for (j = 0; j <= b.length; j++) d[0][j] = j;
    for (i = 1; i <= a.length; i++) for (j = 1; j <= b.length; j++) {
      var c = a.charAt(i - 1) === b.charAt(j - 1) ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c);
      if (i > 1 && j > 1 && a.charAt(i - 1) === b.charAt(j - 2) && a.charAt(i - 2) === b.charAt(j - 1)) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
    return d[a.length][b.length];
  }
  function ratio(a, b) { var m = Math.max(a.length, b.length); return m ? 1 - dl(a, b) / m : 0; }
  // a rough "how it sounds" code: Jessica / Jesica, Katherine / Catherine, Kaylee / Kailey
  function sound(w) {
    w = String(w).replace(/ph/g, "f").replace(/ck/g, "k").replace(/th/g, "t").replace(/kn|gn|wr/g, function (m) { return m.charAt(1); }).replace(/c(?=[eiy])/g, "s").replace(/c/g, "k").replace(/[zx]/g, "s").replace(/q/g, "k").replace(/ay|ey/g, "a").replace(/ie|y$/g, "i").replace(/w/g, "");
    var first = w.charAt(0), rest = w.slice(1).replace(/[aeiouyh]/g, "");
    return (first + rest).replace(/(.)\1+/g, "$1").slice(0, 7);
  }
  function tokens(s) { return String(s == null ? "" : s).toLowerCase().replace(/^@+/, "").split(/[^a-z0-9]+/).map(function (t) { return t.replace(/[0-9]/g, ""); }).filter(function (t) { return t.length >= 3; }); }
  function commonPrefix(a, b) { var i = 0; while (i < a.length && i < b.length && a.charAt(i) === b.charAt(i)) i++; return i; }

  // How alike two names are, 0 to 1, and why.
  function nameScore(a, b) {
    var A = squash(a), B = squash(b);
    if (!A || !B) return { s: 0, why: "" };
    if (A === B) return { s: 1, why: "same name" };
    var LA = letters(a), LB = letters(b);
    if (LA && LA === LB) return { s: 0.97, why: "same name (apart from numbers)" };
    var best = { s: 0, why: "" };
    function put(s, why) { if (s > best.s) best = { s: s, why: why }; }
    if (LA.length >= 3 && LB.length >= 3) {
      var r = ratio(LA, LB); if (r >= 0.7) put(r * 0.97, "spelled almost the same");
      var sh = LA.length <= LB.length ? LA : LB, lo = sh === LA ? LB : LA;
      if (lo.indexOf(sh) === 0) put(0.7 + 0.2 * (sh.length / lo.length), "one starts with the other");
      else if (lo.indexOf(sh) > 0) put(0.6 + 0.2 * (sh.length / lo.length), "one contains the other");
      var cp = commonPrefix(LA, LB); if (cp >= 4 && cp / sh.length >= 0.66) put(0.6 + 0.3 * (cp / sh.length), "starts the same way");
      if (Math.min(LA.length, LB.length) >= 4 && sound(LA) === sound(LB)) put(0.82, "sounds alike");
    }
    var ta = tokens(a), tb = tokens(b);
    ta.forEach(function (x) { tb.forEach(function (y) {
      if (x === y) put(0.88, "same first name or word");
      else { var rr = ratio(x, y); if (rr >= 0.75) put(rr * 0.9, "a word is spelled almost the same"); if (Math.min(x.length, y.length) >= 4 && sound(x) === sound(y)) put(0.8, "a word sounds alike"); if (y.indexOf(x) === 0 || x.indexOf(y) === 0) put(0.74, "a word starts the same"); }
    }); });
    return best;
  }
  function stateOf(s) { var k = squash(s); return STATES[k] || k; }

  // c = { name, age, location } (what the host typed, or a dater), s = { handle, age, location } (a sign-up).
  // Returns { level: "strong" | "possible" | null, score, reasons: [text] }.
  function score(c, s) {
    var n = nameScore(c.name, s.handle), reasons = [];
    if (n.s < 0.55) return { level: null, score: n.s, name: n.s, reasons: [] };
    var total = n.s; if (n.why) reasons.push(n.why);
    var st1 = stateOf(c.location), st2 = stateOf(s.location);
    if (st1 && st2 && st1 === st2) { total += 0.12; reasons.push("same state"); }
    var a1 = Number(c.age), a2 = Number(s.age);
    if (a1 > 0 && a2 > 0) {
      var gap = Math.abs(a1 - a2);
      if (gap === 0) { total += 0.12; reasons.push("same age"); } else if (gap <= 1) { total += 0.08; reasons.push("age within a year"); } else if (gap <= 2) total += 0.04; else if (gap > 6) total -= 0.08;
    }
    total = Math.min(1, total);
    return { level: n.s >= 0.97 ? "strong" : total >= 0.62 ? "possible" : null, score: total, name: n.s, reasons: reasons };
  }
  function compare(c, s) { return score(c, s).level; }
  function findMatches(candidate, list, skip, limit) {
    var out = [];
    (list || []).forEach(function (su) {
      if (skip && skip[su.id]) return;
      var r = score(candidate, su);
      if (r.level) out.push({ signup: su, level: r.level, score: r.score, name: r.name, reasons: r.reasons });
    });
    out.sort(function (x, y) { return (y.name - x.name) || (y.score - x.score); }); // the name counts most; state and age break ties
    return out.slice(0, limit || 3);
  }
  var api = { key: key, lev: dl, compare: compare, score: score, nameScore: nameScore, findMatches: findMatches, sound: sound };
  g.SignupMatch = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
