/*
 * Client shim: gives the page the same calls it used on the Claude runtime
 * (window.claude.use("db") and window.claude.use("user")), backed by our own
 * Cloudflare Worker over one WebSocket. No look or feature changes.
 *
 *   db.collection(n).onSnapshot(cb, err)   db.doc("coll/id").onSnapshot(cb, err)
 *   db.collection(n).doc(id).set / update / delete      db.collection(n).add(data)
 *   snapshot.docs[i].id / .data() / .exists        user.canEdit() / user.can("data.write")
 *
 * Writes never queue while offline: they fail fast so the page shows its usual
 * "Could not save" message and re-syncs. After a dropped connection the shim
 * reconnects with backoff and re-subscribes, which delivers full fresh snapshots.
 */
(function () {
  "use strict";

  var LS_KEY = "sd.session.v1";
  var LEVEL = { none: 0, viewer: 1, contributor: 2, editor: 3 };

  var session = null; // { token, exp (seconds), email, role }
  var info = { email: "", noAccess: false };
  var bootPromise = null;
  var configPromise = null;

  /* ---------- tiny helpers ---------- */

  function emit(state) {
    try { window.dispatchEvent(new CustomEvent("claude-conn", { detail: { state: state } })); } catch (e) { /* old browser */ }
  }
  function mkErr(code, message) {
    var e = new Error(message || code);
    e.serverCode = code;
    // The page shows "You do not have permission" for this exact code.
    e.code = code === "permission-denied" ? "invalid_argument" : code;
    return e;
  }
  function loadSession() {
    try {
      var s = JSON.parse(localStorage.getItem(LS_KEY) || "null");
      if (s && typeof s.token === "string" && typeof s.exp === "number") return s;
    } catch (e) { /* ignore */ }
    return null;
  }
  function saveSession() {
    try {
      if (session) localStorage.setItem(LS_KEY, JSON.stringify(session));
      else localStorage.removeItem(LS_KEY);
    } catch (e) { /* storage blocked: stay signed in for this tab only */ }
  }
  function nowS() { return Math.floor(Date.now() / 1000); }

  /* ---------- sign-in ---------- */

  function getConfig() {
    if (!configPromise) {
      configPromise = fetch("/api/config", { cache: "no-store" }).then(function (r) { return r.json(); }).catch(function () { configPromise = null; return { clientId: "" }; });
    }
    return configPromise;
  }

  function doBoot() {
    session = loadSession();
    if (session && session.exp <= nowS()) { session = null; saveSession(); }
    if (!session) return Promise.resolve(false);
    return fetch("/api/session", { headers: { Authorization: "Bearer " + session.token }, cache: "no-store" }).then(function (r) {
      if (r.ok) {
        return r.json().then(function (j) {
          session.role = j.role; session.owner = !!j.owner; session.email = j.email; session.exp = j.exp; saveSession();
          return true;
        });
      }
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (r.status === 403 && j && j.email) { info.email = j.email; info.noAccess = true; }
        session = null; saveSession();
        return false;
      });
    }).catch(function () {
      return true; // server not reachable right now: keep the stored login, the socket will keep retrying
    });
  }
  function boot() {
    if (!bootPromise) bootPromise = doBoot().then(function (ok) { if (ok) startRefreshTimer(); return ok; });
    return bootPromise;
  }

  function loadGis() {
    return new Promise(function (resolve, reject) {
      if (window.google && window.google.accounts && window.google.accounts.id) return resolve();
      var s = document.createElement("script");
      s.src = "https://accounts.google.com/gsi/client"; s.async = true;
      s.onload = function () { resolve(); };
      s.onerror = function () { reject(new Error("Could not load Google sign-in. Check your connection and reload.")); };
      document.head.appendChild(s);
    });
  }

  // Draws the Google button into `el`. `done({ ok, role, email, error })` runs after a login attempt.
  function signIn(el, done) {
    el.textContent = "";
    return Promise.all([getConfig(), loadGis().then(function () { return null; }, function (e) { return e; })]).then(function (r) {
      var cfg = r[0], gisErr = r[1];
      if (!cfg.clientId) { el.textContent = "Sign-in is not set up yet."; return; }
      if (gisErr) { el.textContent = gisErr.message; return; }
      window.google.accounts.id.initialize({
        client_id: cfg.clientId,
        cancel_on_tap_outside: false,
        callback: function (resp) {
          fetch("/api/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ credential: resp.credential }) })
            .then(function (res) { return res.json().then(function (j) { return { status: res.status, body: j }; }); })
            .then(function (x) {
              if (x.status === 200) {
                session = { token: x.body.token, exp: x.body.exp, email: x.body.email, role: x.body.role, owner: !!x.body.owner };
                saveSession(); info = { email: x.body.email, noAccess: false };
                bootPromise = Promise.resolve(true); authFailed = false; startRefreshTimer(); connectIfNeeded();
                done({ ok: true, role: session.role, email: session.email });
              } else if (x.status === 403 && x.body.error === "no_access") {
                info = { email: x.body.email, noAccess: true }; bootPromise = Promise.resolve(false);
                done({ ok: false, noAccess: true, email: x.body.email });
              } else {
                done({ ok: false, error: "Sign-in failed. Try again." });
              }
            })
            .catch(function () { done({ ok: false, error: "Could not reach the server. Try again." }); });
        },
      });
      window.google.accounts.id.renderButton(el, { theme: "filled_black", size: "large", shape: "pill", text: "signin_with" });
    });
  }

  function signOut() {
    session = null; saveSession(); bootPromise = Promise.resolve(false); authFailed = true;
    try { window.google.accounts.id.disableAutoSelect(); } catch (e) { /* not loaded */ }
    closeSocket();
  }

  /* ---------- keep the login fresh (so a long stream never gets signed out) ---------- */

  var refreshTimer = null;
  function startRefreshTimer() {
    clearTimeout(refreshTimer);
    if (!session) return;
    var left = session.exp - nowS();
    var delay = Math.max(5, Math.floor(left / 2)) * 1000;
    refreshTimer = setTimeout(refreshSession, delay);
  }
  function refreshSession() {
    if (!session) return;
    fetch("/api/refresh", { method: "POST", headers: { Authorization: "Bearer " + session.token }, cache: "no-store" }).then(function (r) {
      if (r.ok) {
        return r.json().then(function (j) {
          session.token = j.token; session.exp = j.exp; session.role = j.role; session.owner = !!j.owner; saveSession();
          if (state === "open" && sock) { try { sock.send(JSON.stringify({ t: "auth", token: j.token })); } catch (e) { /* reconnect will pick it up */ } }
          startRefreshTimer();
        });
      }
      sessionLost();
    }).catch(function () {
      refreshTimer = setTimeout(refreshSession, 60000); // offline: try again soon
    });
  }
  function sessionLost() {
    session = null; saveSession(); authFailed = true; bootPromise = Promise.resolve(false);
    closeSocket(); failPending("unavailable");
    emit("auth");
  }

  /* ---------- connection ---------- */

  var sock = null;
  var state = "closed"; // closed | connecting | open
  var authFailed = false;
  var backoff = 500;
  var retryTimer = null, stableTimer = null, hbTimer = null, offlineTimer = null, offlineRepeat = null;
  var wasOffline = false;
  var lastRx = 0;
  var subs = {}, nextSid = 1;
  var pending = {}, nextRid = 1;
  var waiters = [];
  var resyncLeft = 0;
  var everOpened = false;
  var everHello = false;

  function wsUrl() { return (location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/api/ws"; }

  function connectIfNeeded() {
    if (state === "closed" && session && !authFailed) connect();
  }

  function connect() {
    if (state !== "closed" || !session || authFailed) return;
    clearTimeout(retryTimer);
    state = "connecting";
    var ws, opened = false;
    try { ws = new WebSocket(wsUrl(), ["kim-v1", session.token]); } catch (e) { state = "closed"; scheduleRetry(); return; }
    sock = ws;
    ws.onopen = function () {
      if (sock !== ws) return;
      opened = true; state = "open"; everOpened = true; lastRx = Date.now();
      startHeartbeat();
      clearTimeout(stableTimer); stableTimer = setTimeout(function () { backoff = 500; }, 10000);
      var w = waiters; waiters = []; w.forEach(function (f) { f(true); });
      resubscribe();
    };
    ws.onmessage = function (ev) { if (sock !== ws) return; lastRx = Date.now(); onMessage(ev.data); };
    ws.onclose = function (ev) { if (sock !== ws) return; onClosed(ev.code, opened); };
    ws.onerror = function () { /* onclose follows */ };
  }

  function closeSocket() {
    clearTimeout(retryTimer); clearInterval(hbTimer);
    var ws = sock; sock = null; state = "closed";
    if (ws) { try { ws.close(1000); } catch (e) { /* ignore */ } }
  }

  function scheduleRetry(fast) {
    clearTimeout(retryTimer);
    var base = fast ? 250 : Math.min(backoff, 15000);
    var delay = Math.round(base * (0.7 + Math.random() * 0.6));
    backoff = Math.min(backoff * 2, 15000);
    retryTimer = setTimeout(connect, delay);
  }

  function markOffline() {
    if (wasOffline || offlineTimer) return;
    offlineTimer = setTimeout(function () {
      offlineTimer = null; wasOffline = true; emit("offline");
      offlineRepeat = setInterval(function () { if (wasOffline) emit("offline"); }, 5000);
    }, 2500);
  }
  function markOnline() {
    clearTimeout(offlineTimer); offlineTimer = null;
    clearInterval(offlineRepeat); offlineRepeat = null;
    if (wasOffline) { wasOffline = false; emit("online"); }
  }

  function onClosed(code, wasOpen) {
    sock = null; state = "closed";
    clearInterval(hbTimer);
    var w = waiters; waiters = []; w.forEach(function (f) { f(false); });
    failPending("unavailable");
    Object.keys(subs).forEach(function (k) { subs[k].ready = false; });
    if (code === 4403) { sessionLost(); return; }
    markOffline();
    if (code === 4401) { if (session && session.exp > nowS()) scheduleRetry(true); else sessionLost(); return; }
    if (!wasOpen) {
      // The upgrade itself was refused or failed. Find out whether our login is the reason.
      if (!session) return;
      fetch("/api/session", { headers: { Authorization: "Bearer " + session.token }, cache: "no-store" }).then(function (r) {
        if (r.status === 401 || r.status === 403) { if (r.status === 403) { sessionLost(); } else { refreshSession(); scheduleRetry(true); } }
        else scheduleRetry();
      }).catch(function () { scheduleRetry(); });
      return;
    }
    scheduleRetry(code === 1000 || code === 1001 ? true : false);
  }

  function startHeartbeat() {
    clearInterval(hbTimer);
    hbTimer = setInterval(function () {
      if (state !== "open" || !sock) return;
      if (Date.now() - lastRx > 40000) { try { sock.close(); } catch (e) { /* ignore */ } return; }
      try { sock.send("ping"); } catch (e) { /* close will follow */ }
    }, 15000);
  }

  // After the laptop wakes or the network returns, do not wait for the next timer.
  function nudge() {
    if (!session || authFailed) return;
    if (state === "closed") { clearTimeout(retryTimer); backoff = 500; connect(); return; }
    if (state === "open" && sock) {
      var s = sock, t0 = Date.now();
      try { s.send("ping"); } catch (e) { return; }
      setTimeout(function () { if (sock === s && state === "open" && lastRx < t0) { try { s.close(); } catch (e) { /* ignore */ } } }, 5000);
    }
  }
  window.addEventListener("online", nudge);
  document.addEventListener("visibilitychange", function () { if (!document.hidden) nudge(); });

  function failPending(code) {
    var p = pending; pending = {};
    Object.keys(p).forEach(function (k) { clearTimeout(p[k].t); p[k].rej(mkErr(code, "Not connected.")); });
  }

  function resubscribe() {
    var ids = Object.keys(subs);
    resyncLeft = ids.length;
    if (!resyncLeft) { markOnline(); return; }
    ids.forEach(function (k) { subs[k].ready = false; wire({ t: "sub", sid: subs[k].sid, path: subs[k].docId ? subs[k].coll + "/" + subs[k].docId : subs[k].coll }); });
  }
  function resyncStep() {
    if (resyncLeft > 0 && --resyncLeft === 0) markOnline();
  }

  function wire(obj) {
    if (state === "open" && sock) { try { sock.send(JSON.stringify(obj)); return true; } catch (e) { return false; } }
    return false;
  }

  /* ---------- incoming messages ---------- */

  function onMessage(data) {
    if (data === "pong") return;
    var m;
    try { m = JSON.parse(data); } catch (e) { return; }
    if (m.t === "hello") {
      if (session && m.role && (session.role !== m.role || !!session.owner !== !!m.owner)) {
        var changed = everHello;
        session.role = m.role; session.owner = !!m.owner; saveSession();
        if (changed) emit("role"); // someone changed this person's access while the page was open
      }
      everHello = true;
    } else if (m.t === "snap") {
      var sub = subs[m.sid];
      if (sub) {
        if (sub.docId) sub.mirror = m.docs.length ? m.docs[0].data : null;
        else { sub.mirror = new Map(); m.docs.forEach(function (d) { sub.mirror.set(d.id, d.data); }); }
        sub.ready = true; dispatch(sub);
      }
      resyncStep();
    } else if (m.t === "suberr") {
      var s2 = subs[m.sid];
      if (s2 && s2.err) { try { s2.err(mkErr(m.code, m.message)); } catch (e) { console.error(e); } }
      resyncStep();
    } else if (m.t === "chg") {
      Object.keys(subs).forEach(function (k) {
        var sub = subs[k];
        if (sub.coll !== m.coll) return;
        if (sub.docId) { if (sub.docId !== m.id) return; sub.mirror = m.data; }
        else if (m.data === null) sub.mirror.delete(m.id);
        else sub.mirror.set(m.id, m.data);
        if (sub.ready) dispatch(sub);
      });
    } else if (m.t === "ack") {
      var p = pending[m.rid];
      if (p) { clearTimeout(p.t); delete pending[m.rid]; p.res({ id: m.id }); }
    } else if (m.t === "err") {
      var p2 = pending[m.rid];
      if (p2) { clearTimeout(p2.t); delete pending[m.rid]; p2.rej(mkErr(m.code, m.message)); }
    }
  }

  /* ---------- snapshots ---------- */

  function copy(o) { return Object.assign({}, o); }
  function makeSnap(sub) {
    if (sub.docId) {
      var v = sub.mirror;
      return { id: sub.docId, exists: v !== null && v !== undefined, data: function () { return v ? copy(v) : undefined; } };
    }
    var docs = [];
    sub.mirror.forEach(function (val, id) { docs.push({ id: id, exists: true, data: function () { return copy(val); } }); });
    return { docs: docs, size: docs.length, empty: docs.length === 0, forEach: function (f) { docs.forEach(f); } };
  }
  function dispatch(sub) {
    if (sub.queued) return;
    sub.queued = true;
    Promise.resolve().then(function () {
      sub.queued = false;
      if (!subs[sub.sid] || !sub.ready) return;
      try { sub.cb(makeSnap(sub)); } catch (e) { console.error(e); }
    });
  }

  function subscribe(coll, docId, cb, err) {
    var sub = { sid: nextSid++, coll: coll, docId: docId, cb: cb, err: err, mirror: docId ? null : new Map(), ready: false, queued: false };
    subs[sub.sid] = sub;
    if (state === "open") { resyncLeft++; wire({ t: "sub", sid: sub.sid, path: docId ? coll + "/" + docId : coll }); }
    else connectIfNeeded();
    return function () { delete subs[sub.sid]; };
  }

  /* ---------- writes ---------- */

  function whenOpen(ms) {
    if (state === "open") return Promise.resolve(true);
    if (!session || authFailed) return Promise.resolve(false);
    if (state === "closed") { nudge(); return Promise.resolve(false); } // fail fast, but start reconnecting now
    return new Promise(function (resolve) {
      var done = false;
      function finish(v) { if (!done) { done = true; resolve(v); } }
      waiters.push(finish); setTimeout(function () { finish(false); }, ms);
    });
  }

  function write(op, coll, id, data) {
    return whenOpen(3000).then(function (ok) {
      if (!ok || state !== "open") throw mkErr("unavailable", "Not connected.");
      return new Promise(function (resolve, reject) {
        var rid = nextRid++;
        var t = setTimeout(function () { delete pending[rid]; reject(mkErr("deadline-exceeded", "Timed out.")); }, 15000);
        pending[rid] = { res: resolve, rej: reject, t: t };
        if (!wire({ t: "w", rid: rid, op: op, coll: coll, id: id, data: data })) {
          clearTimeout(t); delete pending[rid]; reject(mkErr("unavailable", "Not connected."));
        }
      });
    });
  }

  /* ---------- the db object the page uses ---------- */

  function DocRef(coll, id) { this.coll = coll; this.id = id; }
  DocRef.prototype.set = function (data) { return write("set", this.coll, this.id, data); };
  DocRef.prototype.update = function (data) { return write("update", this.coll, this.id, data); };
  DocRef.prototype.delete = function () { return write("delete", this.coll, this.id, null); };
  DocRef.prototype.onSnapshot = function (cb, err) { return subscribe(this.coll, this.id, cb, err); };

  function CollRef(name) { this.name = name; }
  CollRef.prototype.doc = function (id) { return new DocRef(this.name, id); };
  CollRef.prototype.add = function (data) { var c = this.name; return write("add", c, null, data).then(function (r) { return new DocRef(c, r.id); }); };
  CollRef.prototype.onSnapshot = function (cb, err) { return subscribe(this.name, null, cb, err); };

  var db = {
    collection: function (name) { return new CollRef(name); },
    doc: function (path) { var p = String(path).split("/"); return new DocRef(p[0], p[1]); },
    deleteField: function () { return { $delete: true }; }, // for update(); the page does not use it today
  };

  var user = {
    canEdit: function () { return Promise.resolve(!!session && session.role === "editor"); },
    can: function (perm) {
      var lvl = LEVEL[session ? session.role : "none"] || 0;
      return Promise.resolve(perm === "data.write" ? lvl >= LEVEL.contributor : lvl >= LEVEL.viewer);
    },
  };

  window.claude = {
    use: function (name) {
      return boot().then(function (ok) {
        if (name === "db") return ok ? db : null;
        if (name === "user") return ok ? user : null;
        return null;
      });
    },
    status: function () { return { signedIn: !!session, email: session ? session.email : info.email, role: session ? session.role : "none", owner: !!(session && session.owner), noAccess: !!info.noAccess }; },
    signIn: signIn,
    signOut: signOut,
    authFetch: function (url, opts) {
      opts = Object.assign({}, opts); opts.headers = Object.assign({}, opts.headers, { Authorization: "Bearer " + (session ? session.token : "") });
      return fetch(url, opts);
    },
    // For automated tests only.
    _test: {
      drop: function () { if (sock) { try { sock.close(); } catch (e) { /* ignore */ } } },
      state: function () { return { state: state, subs: Object.keys(subs).length, backoff: backoff, everOpened: everOpened }; },
    },
  };
})();
