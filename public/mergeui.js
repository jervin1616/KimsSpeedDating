// "Is this the same person?" dialog, used by the admin page and the seat picker. It never merges by itself:
// it lists daters that look like the sign-up (or lets you search your list), shows exactly what would change, and waits for a tap.
(function (g) {
  var CSS = ".mu-ov{position:fixed;inset:0;background:rgba(0,0,0,.72);z-index:10000;display:flex;align-items:center;justify-content:center;padding:14px}"
    + ".mu-card{background:#240306;border:1px solid #6e1518;border-radius:16px;padding:18px;max-width:440px;width:100%;max-height:90vh;overflow:auto;display:flex;flex-direction:column;gap:12px;color:#f9e8e3;font:15px/1.4 system-ui,sans-serif}"
    + ".mu-card h2{margin:0;font-size:19px}.mu-card .mu-sub{color:#d9a39b;font-size:13px}"
    + ".mu-row{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:8px;border:1px solid #6e1518;border-radius:12px;padding:10px 12px}"
    + ".mu-row b{display:block}.mu-row span{color:#d9a39b;font-size:13px}"
    + ".mu-card button{font:inherit;font-weight:600;border-radius:10px;border:1px solid #6e1518;background:#3a0a0e;color:#f9e8e3;padding:8px 12px;cursor:pointer}"
    + ".mu-card button.mu-go{background:#ff2d55;border-color:#ff2d55;color:#fff}.mu-card input{font:inherit;padding:9px 11px;border-radius:10px;border:1px solid #6e1518;background:#1b0203;color:#f9e8e3;width:100%}"
    + ".mu-diff{display:flex;flex-direction:column;gap:6px}.mu-diff div{display:flex;justify-content:space-between;gap:10px;border-bottom:1px solid #4a0d12;padding-bottom:4px}"
    + ".mu-acts{display:flex;flex-wrap:wrap;gap:8px;justify-content:flex-end}";
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  function who(d) { return [d.location, d.gender, d.sexuality].filter(Boolean).join(" · "); }

  // Existing daters (not already linked to an account) that might be this sign-up, best first. Each name a dater has
  // (current name and old names) is tried, so a first name, a misspelling or a username with numbers on the end still turns up.
  function candidates(su, daters) {
    var M = g.SignupMatch, out = [];
    (daters || []).forEach(function (d) {
      if (d.acct) return;
      var best = null;
      [d.name].concat(Array.isArray(d.aka) ? d.aka : []).forEach(function (n) {
        var r = M.score({ name: su.handle, age: su.age, location: su.location }, { handle: n, age: d.age, location: d.location });
        if (r.level && (!best || r.name > best.name || (r.name === best.name && r.score > best.score))) best = r;
      });
      if (best) out.push({ d: d, level: best.level, score: best.score, name: best.name, reasons: best.reasons });
    });
    out.sort(function (a, b) { return (b.name - a.name) || (b.score - a.score); });
    return out.slice(0, 6);
  }

  // opts: { su, daters, searchOnly, preview(daterId) -> Promise<{changes, keepsName}> }. Resolves { action: "merge", daterId } | { action: "new" } | { action: "cancel" }.
  function open(opts) {
    if (!document.getElementById("mu-css")) { var st = el("style"); st.id = "mu-css"; st.textContent = CSS; document.head.appendChild(st); }
    return new Promise(function (resolve) {
      var ov = el("div", "mu-ov"), card = el("div", "mu-card"); ov.appendChild(card); ov.setAttribute("role", "dialog"); ov.setAttribute("aria-modal", "true");
      function done(r) { ov.remove(); document.removeEventListener("keydown", onKey); resolve(r); }
      function onKey(e) { if (e.key === "Escape") done({ action: "cancel" }); }
      document.addEventListener("keydown", onKey);
      ov.addEventListener("click", function (e) { if (e.target === ov) done({ action: "cancel" }); });
      var su = opts.su, daters = opts.daters || [];

      function pickScreen() {
        card.textContent = "";
        card.appendChild(el("h2", "", opts.searchOnly ? "Merge @" + su.handle + " into an existing dater" : "Is @" + su.handle + " already on your list?"));
        card.appendChild(el("div", "mu-sub", "Merging keeps the existing dater's history (panel and hot seat time, match log) and fills in the details they just entered."));
        var cands = opts.searchOnly ? [] : candidates(su, daters);
        if (cands.length) {
          card.appendChild(el("div", "mu-sub", "These look like the same person:"));
          cands.forEach(function (c) { card.appendChild(row(c.d, c.level === "strong" ? "very likely" : "possible", c.reasons)); });
        }
        card.appendChild(el("div", "mu-sub", cands.length ? "Someone else? Search your daters:" : "Search your daters:"));
        var q = el("input"); q.type = "search"; q.placeholder = "Name or state"; q.setAttribute("aria-label", "Search daters"); card.appendChild(q);
        var res = el("div"); res.style.cssText = "display:flex;flex-direction:column;gap:8px"; card.appendChild(res);
        q.oninput = function () {
          var t = q.value.trim().toLowerCase(); res.textContent = ""; if (!t) return;
          var hits = daters.filter(function (d) { return !d.acct && ([d.name, d.location].concat(d.aka || []).join(" ")).toLowerCase().indexOf(t) >= 0; }).slice(0, 8);
          if (!hits.length) res.appendChild(el("div", "mu-sub", "No unlinked daters match."));
          hits.forEach(function (d) { res.appendChild(row(d, "")); });
        };
        var acts = el("div", "mu-acts");
        var no = el("button", "", "Cancel"); no.type = "button"; no.onclick = function () { done({ action: "cancel" }); };
        acts.appendChild(no);
        if (!opts.searchOnly) { var nw = el("button", "mu-go", "No, add as a new dater"); nw.type = "button"; nw.onclick = function () { done({ action: "new" }); }; acts.appendChild(nw); }
        card.appendChild(acts);
      }
      function row(d, tag, reasons) {
        var r = el("div", "mu-row"), main = el("div");
        main.appendChild(el("b", "", d.name + ", " + d.age + (tag ? "  (" + tag + ")" : "")));
        main.appendChild(el("span", "", who(d) + (d.aka && d.aka.length ? " · also " + d.aka.join(", ") : "")));
        if (reasons && reasons.length) { var why = el("span", "", "Why: " + reasons.join(", ")); why.style.display = "block"; main.appendChild(why); }
        var b = el("button", "", "Merge into this one"); b.type = "button"; b.onclick = function () { diffScreen(d); };
        r.appendChild(main); r.appendChild(b); return r;
      }
      function diffScreen(d) {
        card.textContent = ""; card.appendChild(el("h2", "", "Merge @" + su.handle + " into " + d.name + "?")); card.appendChild(el("div", "mu-sub", "Checking what would change..."));
        Promise.resolve(opts.preview(d.id)).then(function (p) {
          card.textContent = "";
          card.appendChild(el("h2", "", "Merge @" + su.handle + " into " + p.dater.name + "?"));
          var diff = el("div", "mu-diff");
          if (!p.changes.length) diff.appendChild(el("div", "", "Nothing changes except linking the account."));
          p.changes.forEach(function (c) { var line = el("div"); line.appendChild(el("span", "", c.label)); line.appendChild(el("b", "", (c.from == null ? "none" : c.from) + "  →  " + (c.to == null ? "none" : c.to))); diff.appendChild(line); });
          card.appendChild(diff);
          if (p.keepsName) card.appendChild(el("div", "mu-sub", "\"" + p.keepsName + "\" stays searchable. You can undo the merge right after."));
          var acts = el("div", "mu-acts");
          var back = el("button", "", "Back"); back.type = "button"; back.onclick = pickScreen;
          var ok = el("button", "mu-go", "Confirm merge"); ok.type = "button"; ok.onclick = function () { done({ action: "merge", daterId: d.id }); };
          acts.appendChild(back); acts.appendChild(ok); card.appendChild(acts);
        }).catch(function (e) { card.textContent = ""; card.appendChild(el("h2", "", "Cannot merge")); card.appendChild(el("div", "mu-sub", e && e.message || "Something went wrong.")); var b = el("button", "", "Back"); b.type = "button"; b.onclick = pickScreen; card.appendChild(b); });
      }
      pickScreen(); document.body.appendChild(ov);
      var first = card.querySelector("button.mu-go") || card.querySelector("input"); if (first) first.focus();
    });
  }
  g.MergeUI = { candidates: candidates, open: open };
})(typeof window !== "undefined" ? window : globalThis);
