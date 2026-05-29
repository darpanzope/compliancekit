// v1.5.1 — extracted from base.html inline <script> blocks. Inline
// scripts are blocked by the daemon's strict CSP (script-src 'self',
// no 'unsafe-inline'), which silently broke the No-FOUC theme
// bootstrap + Cmd+K palette factory in v1.5.0. Moving the same code
// to a same-origin asset file keeps the strict CSP intact.
//
// Load this file synchronously in <head> (no `defer`) — the theme
// bootstrap MUST run before first paint, and `cmdk` MUST be defined
// before Alpine fires its DOMContentLoaded sweep (Alpine itself
// loads with `defer`, so a non-deferred head script always wins).

(function () {
  // No-FOUC theme bootstrap. Reads the persisted theme choice (light
  // / dark / system) and applies the right class on <html> before
  // paint, so the first frame matches the operator's preference
  // instead of flashing the default. Matches the v1.2 HTML report
  // convention.
  try {
    var saved = localStorage.getItem('ck-theme') || 'system';
    var dark = saved === 'dark' ||
      (saved === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    if (dark) document.documentElement.classList.add('dark');
    document.documentElement.dataset.theme = saved;
  } catch (e) {}
})();

// v1.6 phase 1 — Live event-bus subscriber. Boots once at page load,
// connects to GET /api/v1/events (the v1.6 phase 0 SSE bus), exposes
// window.ck.events.on(type, callback) for per-page wiring. Auto-
// reconnects with cursor replay so a 30s wifi drop doesn't lose events.
//
// Per-page callers (scans list, findings explorer, providers status,
// home activity timeline) register handlers + mutate Alpine reactive
// state in place. No setInterval(fetch, 5000) anywhere — every live
// update originates from the bus.
//
// Connection state is exposed on window.ck.events.connected (boolean)
// so the chrome's nav bar can render a "reconnecting…" badge when the
// stream drops. Phase 7 fleshes out the UX; phase 1 lays the wire.
window.ck = window.ck || {};

// v1.10 phase 0/3 — ARIA live-region helper. Pushes a string into
// the polite (or assertive) announcer mounted in base.html. The v1.6
// SSE handlers + Cmd-K palette + form-success flashes all funnel
// here so screen-reader users hear the same updates sighted users
// see.
//
// Polite = wait for the user's current speech to finish (the default
// for everything except "scan failed" / "critical finding" alerts).
// Assertive = interrupt — reserved for must-hear events.
window.ck.announce = function (msg, opts) {
  if (!msg) return;
  var id = (opts && opts.assertive) ? 'ck-announcer-assertive' : 'ck-announcer';
  var el = document.getElementById(id);
  if (!el) return;
  // Toggling the textContent on a single node sometimes fails to fire
  // a re-announce when the message is identical. Clear first, then
  // set on the next tick — well-known a11y pattern.
  el.textContent = '';
  setTimeout(function () { el.textContent = msg; }, 50);
};

window.ck.events = (function () {
  var listeners = {};      // {type: [callback, ...]}
  var allListeners = [];   // wildcard handlers (receive every event)
  // v1.6 phase 7 — cursor persistence across tabs. localStorage
  // survives leader-election handoffs (the new leader reads the
  // last known ID + reconnects with ?since=<id> so the bus's 5-min
  // ring replays anything missed during the ~250ms election gap).
  var LAST_ID_KEY = 'ck-events-lastID';
  function loadLastID() {
    try { return parseInt(localStorage.getItem(LAST_ID_KEY) || '0', 10) || 0; } catch (_) { return 0; }
  }
  function saveLastID(id) {
    try { localStorage.setItem(LAST_ID_KEY, String(id)); } catch (_) {}
  }
  var lastID = loadLastID();
  var es = null;
  var stopped = false;
  // v1.6 phase 7 — exponential backoff with jitter. 1s → 2s → 4s →
  // 8s → 16s (cap 30s); ±20% jitter per attempt avoids the
  // thundering-herd problem if every tab reconnects after a daemon
  // restart.
  var reconnectAttempt = 0;
  var maxBackoffMs = 30000;
  function nextBackoff() {
    var base = Math.min(1000 * Math.pow(2, reconnectAttempt), maxBackoffMs);
    var jitter = base * (0.8 + Math.random() * 0.4); // ±20%
    reconnectAttempt++;
    return Math.floor(jitter);
  }
  var eventTypes = [
    'scan.queued', 'scan.started', 'scan.progress',
    'scan.completed', 'scan.failed', 'finding.created',
    'finding.resolved', 'webhook.received', 'auth.session.created',
  ];

  // v1.6 phase 3 — multi-tab BroadcastChannel sync. The leader tab
  // holds the only EventSource; followers receive events forwarded
  // through the channel. Saves daemon connection budget when an
  // operator has 6 dashboard tabs open. Election: each new tab
  // claim-queries; the existing leader responds; if no response in
  // 250ms the new tab becomes leader. Beforeunload-triggered
  // handoff yields cleanly so the next tab takes over without a
  // gap.
  var TAB_ID = Date.now() + '-' + Math.random().toString(36).slice(2);
  var bc = null;
  var leader = false;
  var leaderKnown = false;
  try { bc = new BroadcastChannel('ck-events'); } catch (e) { bc = null; }

  function emit(type, ev) {
    var bucket = listeners[type] || [];
    for (var i = 0; i < bucket.length; i++) {
      try { bucket[i](ev); } catch (e) { console.error('ck.events handler', type, e); }
    }
    for (var j = 0; j < allListeners.length; j++) {
      try { allListeners[j](ev); } catch (e) { console.error('ck.events * handler', e); }
    }
  }

  // v1.6 phase 7 — track how many events arrive in the first 2s
  // after reconnect; if >0, fire a "X events replayed while
  // disconnected" toast so operators know nothing was lost.
  var reconnectBacklogCount = 0;
  var reconnectBacklogTimer = null;
  function startReconnectBacklogWindow() {
    reconnectBacklogCount = 0;
    if (reconnectBacklogTimer) clearTimeout(reconnectBacklogTimer);
    reconnectBacklogTimer = setTimeout(function () {
      if (reconnectBacklogCount > 0 && window.ck.toastQueue) {
        if (window.ck.announce) {
          window.ck.announce('Replayed ' + reconnectBacklogCount + ' missed events; daemon connection restored.');
        }
        window.ck.toastQueue({
          variant: 'primary',
          title: 'Replayed ' + reconnectBacklogCount + ' missed event(s)',
          body: 'Daemon connection restored.',
          href: '/audit',
        });
      }
      reconnectBacklogCount = 0;
      reconnectBacklogTimer = null;
    }, 2000);
  }

  function connectSSE() {
    if (stopped) return;
    var url = '/api/v1/events?since=' + lastID;
    try { es = new EventSource(url); } catch (e) { scheduleReconnect(); return; }
    es.onopen = function () {
      api.connected = true;
      reconnectAttempt = 0; // reset backoff on a clean connect
      startReconnectBacklogWindow();
    };
    es.onerror = function () {
      api.connected = false;
      try { es.close(); } catch (_) {}
      scheduleReconnect();
    };
    eventTypes.forEach(function (t) {
      es.addEventListener(t, function (e) {
        try {
          var payload = JSON.parse(e.data);
          if (payload.id) {
            lastID = payload.id;
            saveLastID(lastID);
          }
          reconnectBacklogCount++;
          // Leader fans out to follower tabs first, then local emit.
          if (leader && bc) {
            bc.postMessage({ kind: 'event', type: t, payload: payload });
          }
          emit(t, payload);
        } catch (err) { console.error('ck.events parse', t, err); }
      });
    });
  }

  function scheduleReconnect() {
    if (stopped) return;
    setTimeout(function () { if (leader) connectSSE(); }, nextBackoff());
  }

  // BroadcastChannel message handler. Receives leader election +
  // event fan-out from the current leader.
  if (bc) {
    bc.onmessage = function (msg) {
      var d = msg.data || {};
      if (d.kind === 'event') {
        // Follower path — never opens EventSource locally.
        if (d.payload && d.payload.id) lastID = d.payload.id;
        emit(d.type, d.payload);
        api.connected = true; // mirror leader's status
        return;
      }
      if (d.kind === 'claim_query') {
        if (leader) bc.postMessage({ kind: 'i_am_leader', tabId: TAB_ID });
        return;
      }
      if (d.kind === 'i_am_leader') {
        leaderKnown = true;
        api.connected = true;
        return;
      }
      if (d.kind === 'leader_leaving') {
        // Run election again — first tab to claim wins.
        leaderKnown = false;
        leader = false;
        attemptLeadership();
      }
    };
  }

  function attemptLeadership() {
    if (stopped) return;
    if (!bc) { // no BroadcastChannel — every tab is its own leader
      leader = true;
      connectSSE();
      return;
    }
    leaderKnown = false;
    bc.postMessage({ kind: 'claim_query', tabId: TAB_ID });
    setTimeout(function () {
      if (!leaderKnown) {
        leader = true;
        bc.postMessage({ kind: 'i_am_leader', tabId: TAB_ID });
        connectSSE();
      }
    }, 250);
  }

  // Yield leadership cleanly on tab close so the next tab can claim
  // without a gap.
  window.addEventListener('beforeunload', function () {
    if (leader && bc) bc.postMessage({ kind: 'leader_leaving', tabId: TAB_ID });
  });

  var api = {
    connected: false,
    on: function (type, callback) {
      if (type === '*') { allListeners.push(callback); return; }
      (listeners[type] = listeners[type] || []).push(callback);
    },
    stop: function () {
      stopped = true;
      if (es) es.close();
      if (bc) bc.close();
    },
    // Test/debug: expose whether this tab is the leader.
    isLeader: function () { return leader; },
  };

  // Boot on DOMContentLoaded so the EventSource doesn't race the
  // initial page render. /login pages skip — no auth cookie yet.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      if (!document.body || document.body.dataset.loginPage === '1') return;
      attemptLeadership();
    });
  } else {
    if (document.body && document.body.dataset.loginPage !== '1') attemptLeadership();
  }

  return api;
})();

// v1.6 phase 1 — per-page live-event Alpine factories. Each page
// referenced by `x-data="…Live()"` exposes a small reactive store
// the bus pushes events into. The chrome's live-status pill is its
// own inline x-data (in base.html); these factories are for page-
// specific widgets that count or surface incoming events.

// scansLive — bumps a `banner` counter for every scan.* event +
// patches the visible row's status pill in place when possible.
// Used by /scans and /scans/new templates.
function scansLive() {
  return {
    banner: 0,
    bind: function () {
      var self = this;
      ['scan.queued', 'scan.started', 'scan.completed', 'scan.failed'].forEach(function (t) {
        window.ck.events.on(t, function (ev) {
          var row = document.querySelector('[data-scan-id="' + ev.entity_id + '"]');
          if (!row) { self.banner++; return; }
          var pill = row.querySelector('[data-status-pill]');
          if (pill) {
            // Replace just the status pill in place. Keeps the row
            // identity stable so animations + click handlers carry.
            // v1.18 phase 11 — mirrors the ck-status-pill markup in
            // scans.html so the SSE in-place swap keeps the design-system
            // status-pill styling.
            var html = '';
            if (t === 'scan.completed') {
              html = '<span data-status-pill class="ck-pill ck-status-pill ck-status-completed"><span class="ck-status-dot"></span>completed</span>';
            } else if (t === 'scan.started') {
              html = '<span data-status-pill class="ck-pill ck-status-pill ck-status-running"><span class="ck-status-dot animate-pulse"></span>running</span>';
            } else if (t === 'scan.failed') {
              html = '<span data-status-pill class="ck-pill ck-status-pill ck-status-failed"><span class="ck-status-dot"></span>failed</span>';
            } else { // queued
              html = '<span data-status-pill class="ck-pill ck-status-pill ck-status-pending"><span class="ck-status-dot"></span>queued</span>';
            }
            pill.outerHTML = html;
          }
        });
      });
    },
  };
}

// v1.6 phase 4 — toast system. Mounted once at body level via
// base.html `x-data="toastSystem()"`. Subscribes to the ck.events
// bus + pushes toast objects into a reactive list. Cap at 5
// visible; auto-dismiss at 8s; click anywhere on the toast to
// dismiss early. Toast color is severity-driven (destructive for
// critical findings, success for scan completion, primary for
// webhook receipt).
function toastSystem() {
  return {
    toasts: [],
    nextId: 0,
    bind: function () {
      var self = this;
      // Register a global push so non-Alpine callers (the v1.6
      // phase 7 reconnect-backlog notice; future log-tail alerts)
      // can drop a toast without a separate Alpine context.
      window.ck = window.ck || {};
      window.ck.toastQueue = function (t) { self.push(t); };
      window.ck.events.on('finding.created', function (ev) {
        var sev = ev.data && ev.data.severity;
        if (sev !== 'critical') return; // only critical-severity findings toast
        self.push({
          variant: 'destructive',
          title: 'Critical finding',
          body: (ev.data.check_id || '') + ' on ' + (ev.data.resource || '—'),
          href: '/findings?severity=critical',
        });
        // v1.10 phase 3 — assertive announcement for must-hear events.
        window.ck.announce(
          'New critical finding: ' + (ev.data.check_id || '') + ' on ' + (ev.data.resource || 'unknown resource'),
          { assertive: true });
      });
      window.ck.events.on('scan.completed', function (ev) {
        var dur = ev.data && ev.data.duration_ms ? ' in ' + ev.data.duration_ms + 'ms' : '';
        self.push({
          variant: 'success',
          title: 'Scan completed' + dur,
          body: ev.entity_id ? 'Scan ' + ev.entity_id.slice(0, 8) : '',
          href: ev.entity_id ? '/scans/' + ev.entity_id : '/scans',
        });
        window.ck.announce('Scan completed' + dur + '.');
        // v1.18 phase 12 — magic moment: a fresh scan that closes with
        // zero critical findings fires confetti + a celebration toast.
        // critical === -1 means the count is unknown (query failed) so
        // we stay quiet.
        var crit = ev.data && typeof ev.data.critical === 'number' ? ev.data.critical : -1;
        if (crit === 0) {
          window.ck.confetti();
          window.ck.toast({ variant: 'success', title: 'Zero critical findings 🎉', message: 'This scan closed clean. Nice work.' });
          window.ck.announce('Scan closed with zero critical findings.', { assertive: true });
        }
      });
      window.ck.events.on('scan.failed', function (ev) {
        self.push({
          variant: 'destructive',
          title: 'Scan failed',
          body: (ev.data && ev.data.error) || 'See /scans for detail',
          href: ev.entity_id ? '/scans/' + ev.entity_id : '/scans',
        });
        window.ck.announce('Scan failed. ' + ((ev.data && ev.data.error) || ''),
          { assertive: true });
      });
      window.ck.events.on('webhook.received', function (ev) {
        self.push({
          variant: 'primary',
          title: 'Webhook received',
          body: (ev.data && ev.data.source) || ev.entity_id || '',
          href: '/audit',
        });
        window.ck.announce('Webhook received from ' + ((ev.data && ev.data.source) || 'unknown'));
      });
    },
    push: function (t) {
      t.id = ++this.nextId;
      this.toasts.push(t);
      // Cap at 5 — drop the oldest if we'd exceed.
      while (this.toasts.length > 5) this.toasts.shift();
      var self = this;
      setTimeout(function () { self.dismiss(t.id); }, 8000);
    },
    dismiss: function (id) {
      this.toasts = this.toasts.filter(function (t) { return t.id !== id; });
    },
  };
}

// v1.6 phase 8 — activity timeline. Wildcard-subscribes to every
// event on the bus + maintains a 50-line ring of "what just
// happened" entries. Each entry renders as one row in a vertical
// timeline; clicking opens the related entity. Per-type filter
// dropdown narrows the list client-side.
function activityTimeline() {
  return {
    entries: [],
    filter: 'all',
    bind: function () {
      var self = this;
      window.ck.events.on('*', function (ev) {
        var entry = {
          id: ev.id || Date.now(),
          type: ev.type || '',
          at: ev.at,
          entity: ev.entity_id || '',
          href: self.hrefFor(ev),
        };
        self.entries.unshift(entry); // newest on top
        while (self.entries.length > 50) self.entries.pop();
      });
    },
    visible: function () {
      var self = this;
      if (self.filter === 'all') return self.entries;
      return self.entries.filter(function (e) { return e.type === self.filter; });
    },
    hrefFor: function (ev) {
      var t = ev.type || '';
      if (t.indexOf('scan.') === 0) return '/scans/' + ev.entity_id;
      if (t.indexOf('finding.') === 0) return '/findings/' + ev.entity_id + '/detail';
      if (t === 'webhook.received') return '/audit';
      return '/audit';
    },
    typeClass: function (t) {
      if (t === 'finding.created') return 'text-destructive';
      if (t === 'scan.completed' || t === 'finding.resolved') return 'text-success';
      if (t === 'scan.failed') return 'text-destructive';
      if (t === 'scan.started' || t === 'scan.progress') return 'text-warning';
      if (t === 'webhook.received') return 'text-primary';
      return 'text-muted-foreground';
    },
    formatTime: function (iso) {
      try { return new Date(iso).toLocaleTimeString(); } catch (_) { return ''; }
    },
  };
}

// findingsLive — bumps a `banner` counter on every finding.created
// event. The /findings page's filter context can't safely auto-
// inject a row without disrupting the cursor-paginated scroll;
// surfacing a "N new — refresh" banner is the clearest UX.
function findingsLive() {
  return {
    banner: 0,
    bind: function () {
      var self = this;
      window.ck.events.on('finding.created', function () { self.banner++; });
      window.ck.events.on('finding.resolved', function () { self.banner++; });
    },
  };
}

// v1.6 phase 6 — admin log tail. Opens a dedicated EventSource
// against /admin/logs/stream (separate from the main /api/v1/events
// bus so log volume doesn't compete with finding events). Maintains
// a capped in-memory line list + follow-tail auto-scroll.
function logsTail() {
  return {
    lines: [],
    connected: false,
    paused: false,
    follow: true,
    es: null,
    bind: function () {
      var self = this;
      var es = new EventSource('/admin/logs/stream');
      self.es = es;
      es.onopen = function () { self.connected = true; };
      es.onerror = function () {
        self.connected = false;
        try { es.close(); } catch (_) {}
        // Auto-reconnect after 2s.
        setTimeout(function () { self.bind(); }, 2000);
      };
      es.addEventListener('log', function (e) {
        if (self.paused) return;
        try {
          var line = JSON.parse(e.data);
          self.lines.push(line);
          // Cap at 2000 to keep DOM size sane on a busy daemon.
          while (self.lines.length > 2000) self.lines.shift();
          if (self.follow) {
            self.$nextTick(function () {
              var el = self.$refs.scroll;
              if (el) el.scrollTop = el.scrollHeight;
            });
          }
        } catch (_) {}
      });
    },
    formatTime: function (iso) {
      try { return new Date(iso).toLocaleTimeString(); } catch (_) { return iso; }
    },
    levelClass: function (level) {
      switch ((level || '').toUpperCase()) {
        case 'ERROR': return 'bg-destructive/10 text-destructive';
        case 'WARN': return 'bg-warning/10 text-warning';
        case 'INFO': return 'bg-primary/10 text-primary';
        case 'DEBUG': return 'bg-muted text-muted-foreground';
        default: return 'bg-muted text-muted-foreground';
      }
    },
  };
}

// v1.19 phase 6 — "/" opens the global search palette from anywhere,
// the way GitHub + Linear do. Guarded so it only fires when the user
// isn't typing into a field (otherwise "/" would hijack every text
// input). Dispatches ck-cmdk-open; the palette component listens.
document.addEventListener('keydown', function (e) {
  if (e.key !== '/' || e.metaKey || e.ctrlKey || e.altKey) return;
  var t = e.target;
  if (t && (/^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName) || t.isContentEditable)) return;
  e.preventDefault();
  window.dispatchEvent(new CustomEvent('ck-cmdk-open'));
});

// Cmd+K / "/" global search palette factory. Referenced from base.html
// as `x-data="cmdk()"`. Vanilla Alpine — no extra JS library. Mounted
// at body level so every authenticated page can open it.
//
// v1.19 phase 6 — upgraded from the v1.5 flat palette to the global
// search index (GET /api/v1/search): results are grouped by type,
// keyboard-navigable (↑/↓ + Enter), and recent queries persist in
// localStorage. An empty query shows recent + index suggestions so the
// palette is useful before the first keystroke.
var ckRecentSearchKey = 'ck-recent-search';
function cmdk() {
  return {
    visible: false,
    query: '',
    groups: [],   // [{type, label, items:[SearchResult]}]
    flat: [],     // flattened items, in display order, for keyboard nav
    sel: 0,
    recent: [],
    typeLabels: {
      finding: 'Findings', resource: 'Resources', scan: 'Scans',
      user: 'Users', waiver: 'Waivers', setting: 'Settings', doc: 'Docs',
    },
    typeOrder: ['finding', 'resource', 'scan', 'user', 'waiver', 'setting', 'doc'],
    open: function () {
      this.visible = true;
      this.loadRecent();
      this.run();
      this.$nextTick(function () {
        if (this.$refs.input) this.$refs.input.select();
      }.bind(this));
    },
    close: function () { this.visible = false; },
    loadRecent: function () {
      try { this.recent = JSON.parse(localStorage.getItem(ckRecentSearchKey) || '[]'); }
      catch (e) { this.recent = []; }
    },
    saveRecent: function (q) {
      q = (q || '').trim();
      if (!q) return;
      var list = (this.recent || []).filter(function (x) { return x !== q; });
      list.unshift(q);
      this.recent = list.slice(0, 5);
      try { localStorage.setItem(ckRecentSearchKey, JSON.stringify(this.recent)); } catch (e) {}
    },
    run: async function () {
      try {
        var r = await fetch('/api/v1/search?q=' + encodeURIComponent(this.query) + '&limit=30',
          { headers: { 'Accept': 'application/json' } });
        if (!r.ok) { this.groups = []; this.flat = []; return; }
        var data = await r.json();
        this.groupResults(data.results || []);
      } catch (e) { this.groups = []; this.flat = []; }
    },
    groupResults: function (results) {
      var byType = {};
      results.forEach(function (it) { (byType[it.type] = byType[it.type] || []).push(it); });
      var groups = [], flat = [];
      this.typeOrder.forEach(function (t) {
        if (byType[t] && byType[t].length) {
          groups.push({ type: t, label: this.typeLabels[t] || t, items: byType[t] });
          byType[t].forEach(function (it) { flat.push(it); });
        }
      }.bind(this));
      this.groups = groups;
      this.flat = flat;
      this.sel = 0;
    },
    move: function (delta) {
      if (!this.flat.length) return;
      this.sel = (this.sel + delta + this.flat.length) % this.flat.length;
      this.$nextTick(function () {
        var el = document.querySelector('[data-cmdk-idx="' + this.sel + '"]');
        if (el && el.scrollIntoView) el.scrollIntoView({ block: 'nearest' });
      }.bind(this));
    },
    go: function () {
      var it = this.flat[this.sel];
      if (!it) return;
      this.saveRecent(this.query);
      window.location.href = it.href;
    },
    pickRecent: function (q) { this.query = q; this.run(); },
    idxOf: function (group, i) {
      // Global flat index of item i within group (groups render in order).
      var n = 0;
      for (var g = 0; g < this.groups.length; g++) {
        if (this.groups[g] === group) return n + i;
        n += this.groups[g].items.length;
      }
      return n + i;
    },
    badge: function (type) { return (type || '?').slice(0, 3); },
  };
}

// ruleEditor is the v1.9 phase 3 rule-builder Alpine factory.
// Reads initial state from data-* attributes on the form element so
// the strict CSP (no inline <script>) stays intact. The hidden
// condition_json + actions_json textareas mirror the live state on
// every keystroke so form submit carries the canonical JSON encoding.
function ruleEditor() {
  return {
    trigger: 'finding.created',
    conditionKinds: [],
    actionKinds: [],
    terms: [],
    actionsList: [{ kind: 'notify', params: '{}' }],
    init() {
      var el = this.$root;
      this.trigger = el.dataset.trigger || 'finding.created';
      this.conditionKinds = (el.dataset.conditionKinds || '').split(',').filter(Boolean);
      this.actionKinds = (el.dataset.actionKinds || '').split(',').filter(Boolean);
      try {
        var cond = JSON.parse(el.dataset.conditionJson || '{}');
        var found = [];
        var walk = function (node) {
          if (!node) return;
          if (node.term) {
            var p = node.term.params || {};
            var key = Object.keys(p)[0] || '';
            found.push({
              kind: node.term.kind || 'severity',
              paramKey: key,
              paramVal: key ? (Array.isArray(p[key]) ? p[key].join(',') : String(p[key])) : '',
              negate: !!node.term.negate,
            });
            return;
          }
          (node.children || []).forEach(walk);
        };
        walk(cond);
        this.terms = found;
      } catch (e) {}
      try {
        var acts = JSON.parse(el.dataset.actionsJson || '[]');
        if (acts.length > 0) {
          this.actionsList = acts.map(function (a) {
            return { kind: a.kind || 'notify', params: JSON.stringify(a.params || {}) };
          });
        }
      } catch (e) {}
    },
    get conditionJSON() {
      if (!this.terms.length) return '{}';
      var children = this.terms.map(function (t) {
        var params = {};
        if (t.paramKey) {
          var v = t.paramVal;
          if (v.indexOf(',') >= 0) v = v.split(',').map(function (x) { return x.trim(); });
          else if (!isNaN(Number(v)) && v !== '') v = Number(v);
          params[t.paramKey] = v;
        }
        return { term: { kind: t.kind, params: params, negate: t.negate } };
      });
      if (children.length === 1) return JSON.stringify(children[0]);
      return JSON.stringify({ op: 'and', children: children });
    },
    get actionsJSON() {
      return JSON.stringify(this.actionsList.map(function (a) {
        var p = {};
        try { p = JSON.parse(a.params || '{}'); } catch (e) {}
        return { kind: a.kind, params: p };
      }));
    },
    addTerm: function () {
      this.terms.push({ kind: 'severity', paramKey: 'min', paramVal: 'high', negate: false });
    },
    removeTerm: function (i) { this.terms.splice(i, 1); },
    addAction: function () { this.actionsList.push({ kind: 'notify', params: '{}' }); },
    removeAction: function (i) { this.actionsList.splice(i, 1); },
  };
}

// ckChrome is the v1.10 chrome-level Alpine factory replacing the
// inline x-data on the authenticated layout div. Owns theme +
// high-contrast + sidebar state. Extracted because the inline
// definition was getting long enough to make CSP debugging painful.
function ckChrome() {
  return {
    sidebarOpen: true,
    mobileMenuOpen: false,
    theme: 'system',
    contrast: 'auto',
    initChrome: function () {
      this.theme = document.documentElement.dataset.theme || 'system';
      this.contrast = localStorage.getItem('ck-contrast') || 'auto';
      this.applyContrast(this.contrast);
    },
    setTheme: function (t) {
      this.theme = t;
      localStorage.setItem('ck-theme', t);
      var dark = t === 'dark' || (t === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
      document.documentElement.classList.toggle('dark', dark);
      document.documentElement.dataset.theme = t;
    },
    setContrast: function (c) {
      this.contrast = c;
      localStorage.setItem('ck-contrast', c);
      this.applyContrast(c);
    },
    applyContrast: function (c) {
      // 'auto' = honor prefers-contrast media query; 'more' = force
      // contrast-more class on <html>; 'normal' = remove the class
      // + fall back to the regular palette regardless of OS pref.
      var html = document.documentElement;
      html.classList.remove('contrast-more', 'contrast-normal');
      if (c === 'more') html.classList.add('contrast-more');
      if (c === 'normal') html.classList.add('contrast-normal');
    },
  };
}

// commentComposer is the v1.8 phase 4 @mention autocomplete. Wired
// to the comments_panel <textarea> via x-data; tracks the caret +
// query, fetches /api/v1/users/search, and replaces the in-flight
// "@partial" with the picked label on click.
function commentComposer() {
  return {
    suggestions: [],
    query: '',
    triggerStart: -1,
    onInput: function (ev) {
      var ta = ev.target;
      var pos = ta.selectionStart;
      var before = ta.value.slice(0, pos);
      var at = before.lastIndexOf('@');
      if (at < 0) { this.suggestions = []; this.triggerStart = -1; return; }
      var prev = at === 0 ? '' : before[at - 1];
      if (prev && !/[\s\(\[\{,;:!?]/.test(prev)) {
        this.suggestions = []; this.triggerStart = -1;
        return;
      }
      var token = before.slice(at + 1);
      if (/\s/.test(token)) { this.suggestions = []; this.triggerStart = -1; return; }
      this.query = token;
      this.triggerStart = at;
      this.refresh();
    },
    onAt: function () { /* placeholder for explicit '@' keyup binding */ },
    refresh: async function () {
      try {
        var r = await fetch('/api/v1/users/search?q=' + encodeURIComponent(this.query),
          { headers: { 'Accept': 'application/json' } });
        if (!r.ok) { this.suggestions = []; return; }
        var data = await r.json();
        this.suggestions = (data.items || []).slice(0, 8);
      } catch (e) { this.suggestions = []; }
    },
    pick: function (s) {
      var ta = this.$refs.ta;
      var pos = ta.selectionStart;
      var before = ta.value.slice(0, this.triggerStart);
      var after = ta.value.slice(pos);
      var localPart = (s.email || '').split('@')[0] || s.label;
      var replacement = '@' + localPart + ' ';
      ta.value = before + replacement + after;
      var newPos = before.length + replacement.length;
      ta.setSelectionRange(newPos, newPos);
      this.suggestions = [];
      this.triggerStart = -1;
      ta.focus();
    },
  };
}

// v1.16 phase 1 — Service worker registration. Registers /sw.js with
// the root scope so it can intercept every navigation + fetch on the
// daemon. Idempotent — re-registering an unchanged sw.js is a no-op.
// Failure is non-fatal: the daemon still works without offline / push
// support, the user just loses PWA install affordances.
if ('serviceWorker' in navigator && window.location.protocol !== 'data:') {
  window.addEventListener('load', function () {
    navigator.serviceWorker.register('/sw.js', { scope: '/' }).then(
      function (reg) {
        // Log under the global ck namespace for browser console
        // discoverability; never alerts the user.
        window.ck = window.ck || {};
        window.ck.sw = reg;
      },
      function (err) {
        if (window.console && console.warn) {
          console.warn('compliancekit: service worker registration failed:', err);
        }
      }
    );
  });
}

// v1.16 phase 2 — PWA install banner factory. Bound to <div
// x-data="installBanner()"> in base.html. Two-flow:
//
//   Android / Chromium desktop: capture beforeinstallprompt + show
//     a banner with an Install button; clicking it calls the saved
//     prompt() handle to surface the browser's native install UI.
//   iOS Safari: no event fires. Detect iOS + display-mode standalone
//     state; show a banner explaining Share → Add to Home Screen.
//
// Dismissal persists in localStorage; we never re-prompt the same
// browser. The display-mode media query suppresses the banner once
// the app is launched in standalone mode.
function installBanner() {
  return {
    visible: false,
    canPromptNative: false,
    hint: '',
    _deferred: null,
    init: function () {
      // Honor a prior dismissal.
      try {
        if (localStorage.getItem('ck-install-dismissed') === '1') return;
      } catch (e) {}
      // Skip entirely when launched in standalone mode (already installed).
      var standalone =
        (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) ||
        window.navigator.standalone === true;
      if (standalone) return;

      var self = this;
      // Chromium path: cache the event so we can fire it on user gesture.
      window.addEventListener('beforeinstallprompt', function (e) {
        e.preventDefault();
        self._deferred = e;
        self.canPromptNative = true;
        self.hint = 'Add compliancekit to your home screen for one-tap access and offline support.';
        self.visible = true;
      });

      // iOS Safari path: no event, but the standalone state is queryable.
      var ua = window.navigator.userAgent || '';
      var isIOS = /iPad|iPhone|iPod/.test(ua) && !window.MSStream;
      if (isIOS) {
        self.canPromptNative = false;
        self.hint =
          'On iOS: tap the Share icon in Safari, then choose "Add to Home Screen" to install.';
        // Delay slightly so the banner doesn't fight first paint;
        // gives the SW registration time to settle.
        setTimeout(function () {
          self.visible = true;
        }, 2000);
      }
    },
    install: async function () {
      if (!this._deferred) return;
      this._deferred.prompt();
      try {
        var choice = await this._deferred.userChoice;
        if (choice && choice.outcome === 'accepted') {
          this.visible = false;
          this._deferred = null;
        }
      } catch (e) {}
    },
    dismiss: function () {
      this.visible = false;
      try {
        localStorage.setItem('ck-install-dismissed', '1');
      } catch (e) {}
    },
  };
}

// v1.16 phase 4 — /settings/notifications Alpine factory. Manages
// the per-browser Web Push subscription lifecycle (the server-side
// catalog of every device lives at GET /api/v1/push/subscriptions,
// rendered into the template ahead of this script booting). Two
// flows:
//
//   Enable:  Notification.requestPermission → SW pushManager.subscribe
//            with the daemon's VAPID public key → POST /api/v1/push
//            /subscribe with endpoint + keys
//   Disable: SW pushSubscription.unsubscribe → POST /api/v1/push
//            /unsubscribe with the endpoint
//
// Browsers refuse pushManager.subscribe() outside HTTPS / localhost
// + outside a user gesture, so the button click is the entry point.
function pushSubs() {
  return {
    supported: false,
    subscribed: false,
    loading: false,
    message: '',
    messageOK: false,
    statusHint: 'Checking browser support...',
    _vapidKey: null,
    init: async function () {
      this.supported = 'serviceWorker' in navigator &&
        'PushManager' in window &&
        'Notification' in window;
      if (!this.supported) {
        this.statusHint = 'This browser does not support Web Push.';
        return;
      }
      try {
        var reg = await navigator.serviceWorker.ready;
        var sub = await reg.pushManager.getSubscription();
        this.subscribed = !!sub;
        this.statusHint = this.subscribed
          ? 'Subscribed. Critical findings push to this browser within seconds.'
          : 'Not subscribed. Enable to receive critical-finding alerts.';
      } catch (e) {
        this.statusHint = 'Service worker not ready.';
      }
    },
    subscribe: async function () {
      this.loading = true; this.message = '';
      try {
        var perm = await Notification.requestPermission();
        if (perm !== 'granted') {
          throw new Error('notifications permission ' + perm);
        }
        if (!this._vapidKey) {
          var r = await fetch('/api/v1/push/vapid-public-key');
          if (!r.ok) throw new Error('vapid key fetch ' + r.status);
          var j = await r.json();
          this._vapidKey = urlBase64ToUint8Array(j.key);
        }
        var reg = await navigator.serviceWorker.ready;
        var sub = await reg.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: this._vapidKey,
        });
        var subJSON = sub.toJSON();
        var resp = await fetch('/api/v1/push/subscribe', {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken(),
          },
          body: JSON.stringify({
            endpoint: subJSON.endpoint,
            keys: subJSON.keys,
          }),
        });
        if (!resp.ok) throw new Error('subscribe POST ' + resp.status);
        this.subscribed = true;
        this.statusHint = 'Subscribed. Critical findings push to this browser within seconds.';
        this.message = 'Push enabled on this browser.'; this.messageOK = true;
      } catch (e) {
        this.message = 'Subscribe failed: ' + e.message; this.messageOK = false;
      } finally {
        this.loading = false;
      }
    },
    unsubscribe: async function () {
      this.loading = true; this.message = '';
      try {
        var reg = await navigator.serviceWorker.ready;
        var sub = await reg.pushManager.getSubscription();
        if (sub) {
          await sub.unsubscribe();
          await fetch('/api/v1/push/unsubscribe', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
              'Content-Type': 'application/json',
              'X-CSRF-Token': csrfToken(),
            },
            body: JSON.stringify({ endpoint: sub.endpoint }),
          });
        }
        this.subscribed = false;
        this.statusHint = 'Not subscribed. Enable to receive critical-finding alerts.';
        this.message = 'Push disabled on this browser.'; this.messageOK = true;
      } catch (e) {
        this.message = 'Unsubscribe failed: ' + e.message; this.messageOK = false;
      } finally {
        this.loading = false;
      }
    },
  };
}

// Helpers for the push factory. csrfToken pulls the value out of the
// ck_csrf cookie (set by auth.SetCookies); urlBase64ToUint8Array
// converts the daemon's URL-safe-base64 VAPID public key into the
// raw Uint8Array PushManager.subscribe expects.
function csrfToken() {
  var m = document.cookie.match(/(?:^|;\s*)ck_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : '';
}
function urlBase64ToUint8Array(base64String) {
  var padding = '='.repeat((4 - base64String.length % 4) % 4);
  var base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  var raw = window.atob(base64);
  var out = new Uint8Array(raw.length);
  for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

// v1.16 phase 5 — Quick-scan progress factory. Bound to <div
// x-data="quickScanProgress(scanID, streamURL)"> inserted into the
// /quick-scan page by the POST /quick-scan/run htmx swap.
// Subscribes to the daemon's SSE stream for the scan, drives a
// percent + status text update, then htmx-loads the top-5 findings
// into a sibling slot once status flips to completed/failed.
function quickScanProgress(scanID, streamURL) {
  return {
    percent: 0,
    status: 'queued',
    _es: null,
    init: function () {
      var self = this;
      try {
        this._es = new EventSource(streamURL);
        this._es.addEventListener('progress', function (e) {
          try {
            var d = JSON.parse(e.data);
            if (typeof d.percent === 'number') self.percent = d.percent;
            if (d.status) self.status = d.status;
          } catch (err) {}
        });
        this._es.addEventListener('scan.completed', function () { self.finish('completed'); });
        this._es.addEventListener('scan.failed', function () { self.finish('failed'); });
        this._es.addEventListener('done', function () { self.finish('completed'); });
      } catch (e) {
        // EventSource isn't supported — fall back to a single results load.
        setTimeout(function () { self.finish('completed'); }, 2000);
      }
    },
    finish: function (final) {
      this.percent = 100;
      this.status = final === 'completed' ? 'Scan complete' : 'Scan failed';
      if (this._es) { try { this._es.close(); } catch (e) {} this._es = null; }
      // htmx loads the results partial into the inline slot.
      var slot = document.getElementById('quickscan-results-slot');
      if (slot && window.htmx) {
        window.htmx.ajax('GET', '/quick-scan/' + scanID + '/results', { target: slot, swap: 'innerHTML' });
      }
    },
  };
}

// v1.16 phase 6 — Swipe gesture wiring. Hooks touch events on any
// element matching `[data-ck-swipe]` and emits a `ck:swipe` custom
// event on the element with detail = { direction: 'left' | 'right',
// distance }. Templates wire the event to a domain action via
// @ck:swipe.left="ack" / @ck:swipe.right="waive" on the element
// (Alpine catches them). Threshold = 80px so accidental scrolls
// don't trigger. Skipped entirely when the device doesn't expose
// touch events (desktop browsers stay unaffected).
(function () {
  if (typeof window === 'undefined') return;
  if (!('ontouchstart' in window) && !('ontouchstart' in document.documentElement)) return;

  var SWIPE_THRESHOLD = 80;   // px — minimum horizontal travel
  var VERTICAL_MAX = 40;      // px — vertical wiggle allowed before we cancel

  function installSwipe(root) {
    var nodes = root.querySelectorAll('[data-ck-swipe]');
    nodes.forEach(function (el) {
      if (el.__ckSwipeBound) return;
      el.__ckSwipeBound = true;

      var startX = 0, startY = 0, tracking = false;
      el.addEventListener('touchstart', function (e) {
        if (e.touches.length !== 1) { tracking = false; return; }
        startX = e.touches[0].clientX;
        startY = e.touches[0].clientY;
        tracking = true;
      }, { passive: true });

      el.addEventListener('touchmove', function (e) {
        if (!tracking) return;
        var dy = Math.abs(e.touches[0].clientY - startY);
        if (dy > VERTICAL_MAX) tracking = false;
      }, { passive: true });

      el.addEventListener('touchend', function (e) {
        if (!tracking) return;
        tracking = false;
        var dx = e.changedTouches[0].clientX - startX;
        if (Math.abs(dx) < SWIPE_THRESHOLD) return;
        var direction = dx < 0 ? 'left' : 'right';
        el.dispatchEvent(new CustomEvent('ck:swipe', {
          detail: { direction: direction, distance: Math.abs(dx) },
          bubbles: true,
        }));
        // Mirror as a direction-specific event so Alpine bindings can
        // write `@ck:swipe.left="ack()"` cleanly.
        el.dispatchEvent(new CustomEvent('ck:swipe-' + direction, {
          detail: { distance: Math.abs(dx) },
          bubbles: true,
        }));
      });
    });
  }

  // Initial pass + re-scan after every htmx swap so new rows pick up
  // swipe handlers without operators wiring anything per-template.
  if (document.readyState !== 'loading') installSwipe(document);
  else document.addEventListener('DOMContentLoaded', function () { installSwipe(document); });
  document.body.addEventListener('htmx:afterSwap', function (e) { installSwipe(e.target || document); });
})();

// v1.16 phase 7 — Offline banner. Listens for the ck:offline
// postMessage the service worker broadcasts when it serves a
// navigation from cache. Surfaces a fixed banner across the top
// of the viewport with a Retry button. Auto-dismisses when a
// navigation lands a fresh response (caught via
// navigator.onLine + a window load event clearing the banner).
(function () {
  if (typeof navigator === 'undefined' || !('serviceWorker' in navigator)) return;
  navigator.serviceWorker.addEventListener('message', function (event) {
    var msg = event && event.data;
    if (!msg || msg.type !== 'ck:offline') return;
    showOfflineBanner();
  });

  function showOfflineBanner() {
    if (document.getElementById('ck-offline-banner')) return;
    var bar = document.createElement('div');
    bar.id = 'ck-offline-banner';
    bar.setAttribute('role', 'status');
    bar.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:50;' +
      'background:hsl(var(--warning));color:hsl(var(--warning-foreground));' +
      'padding:6px 12px;font-size:12px;text-align:center;' +
      'font-family:ui-sans-serif,system-ui,sans-serif;' +
      'box-shadow:0 1px 2px rgba(0,0,0,0.15);';
    bar.innerHTML =
      '<span>Showing cached content &mdash; daemon unreachable.</span> ' +
      '<button type="button" id="ck-offline-retry" ' +
      'style="margin-left:8px;text-decoration:underline;background:none;border:0;color:inherit;cursor:pointer;font:inherit;">Retry</button>';
    document.body.appendChild(bar);
    var btn = document.getElementById('ck-offline-retry');
    if (btn) btn.addEventListener('click', function () { window.location.reload(); });
  }

  // Hide the banner whenever the browser regains connectivity. The
  // user has to retry / navigate before the cached page refreshes,
  // but at least the warning stops shouting.
  window.addEventListener('online', function () {
    var b = document.getElementById('ck-offline-banner');
    if (b && b.parentNode) b.parentNode.removeChild(b);
  });
})();

// v1.18 phase 8 — page-top nprogress bar driven by the htmx request
// lifecycle. No dependency on the nprogress npm package — a ~30-line
// controller that nudges a CSS var (--ck-np, 0..1) on #ck-nprogress.
//
// htmx fires htmx:beforeRequest when a swap starts + htmx:afterRequest
// when it settles. We trickle toward 0.9 while in flight (so long
// requests still feel alive) and snap to 1.0 + fade on completion.
// Concurrent requests are reference-counted so a burst of swaps shows
// one continuous bar, not a flicker per request.
(function () {
  var bar = null;
  var pending = 0;
  var progress = 0;
  var trickleTimer = null;

  function el() {
    if (!bar) bar = document.getElementById('ck-nprogress');
    return bar;
  }
  function set(p) {
    var node = el();
    if (!node) return;
    progress = p;
    node.style.setProperty('--ck-np', String(p));
  }
  function start() {
    var node = el();
    if (!node) return;
    node.setAttribute('data-state', 'loading');
    if (progress < 0.08) set(0.08);
    if (!trickleTimer) {
      trickleTimer = setInterval(function () {
        // Ease toward 0.9 but never reach it until the request finishes.
        if (progress < 0.9) set(progress + (0.9 - progress) * 0.12);
      }, 250);
    }
  }
  function done() {
    var node = el();
    if (!node) return;
    if (trickleTimer) { clearInterval(trickleTimer); trickleTimer = null; }
    set(1);
    node.setAttribute('data-state', 'done');
    // Reset the scale after the fade so the next request starts at 0.
    setTimeout(function () { set(0); }, 300);
  }

  document.addEventListener('htmx:beforeRequest', function () {
    pending++;
    start();
  });
  function settle() {
    pending = Math.max(0, pending - 1);
    if (pending === 0) done();
  }
  document.addEventListener('htmx:afterRequest', settle);
  // htmx:sendError / timeout still need to clear the bar.
  document.addEventListener('htmx:sendError', settle);
  document.addEventListener('htmx:timeout', settle);
})();

// v1.18 phase 9 — toast queue. window.ck.toast({variant,title,message,
// timeout}) appends a slide-in toast to #ck-toasts; it auto-dismisses
// after `timeout` ms (default 5000, 0 = sticky), and the operator can
// click the × or swipe it horizontally to dismiss early. Severity-coded
// via the ck-toast-{variant} classes (phase 3). No framework — plain
// DOM so it works before Alpine boots (e.g. from an htmx error handler).
window.ck = window.ck || {};
(function () {
  function container() {
    return document.getElementById('ck-toasts');
  }
  function dismiss(node) {
    if (!node || node.dataset.leaving) return;
    node.dataset.leaving = '1';
    node.classList.add('ck-toast-leave');
    setTimeout(function () {
      if (node.parentNode) node.parentNode.removeChild(node);
    }, 250);
  }
  function esc(s) {
    var d = document.createElement('div');
    d.textContent = s == null ? '' : String(s);
    return d.innerHTML;
  }
  window.ck.toast = function (opts) {
    opts = opts || {};
    var host = container();
    if (!host) return;
    var variant = opts.variant || 'info';
    var node = document.createElement('div');
    node.className = 'ck-toast ck-toast-' + variant + ' ck-toast-enter';
    node.setAttribute('role', variant === 'error' ? 'alert' : 'status');
    node.innerHTML =
      '<div class="ck-toast-icon" aria-hidden="true"></div>' +
      '<div class="ck-toast-body">' +
      (opts.title ? '<p class="ck-toast-title">' + esc(opts.title) + '</p>' : '') +
      (opts.message ? '<p class="ck-toast-message">' + esc(opts.message) + '</p>' : '') +
      '</div>' +
      '<button type="button" class="ck-toast-close" aria-label="Dismiss">&times;</button>';
    host.appendChild(node);
    // Force a reflow then drop the enter class so the CSS transition runs.
    void node.offsetWidth;
    node.classList.remove('ck-toast-enter');
    node.querySelector('.ck-toast-close').addEventListener('click', function () { dismiss(node); });
    // Swipe-to-dismiss: track horizontal pointer drag.
    var startX = null;
    node.addEventListener('pointerdown', function (e) { startX = e.clientX; });
    node.addEventListener('pointerup', function (e) {
      if (startX !== null && Math.abs(e.clientX - startX) > 60) dismiss(node);
      startX = null;
    });
    var timeout = opts.timeout === undefined ? 5000 : opts.timeout;
    if (timeout > 0) setTimeout(function () { dismiss(node); }, timeout);
    return node;
  };

  // Bridge: a `ck-toast` CustomEvent (from Alpine, or an HX-Trigger
  // header the daemon sets on a mutation response) raises a toast.
  // htmx parses HX-Trigger into a window CustomEvent whose detail is
  // the JSON value, so `HX-Trigger: {"ck-toast":{"variant":"success",
  // "title":"Saved"}}` just works.
  window.addEventListener('ck-toast', function (e) {
    window.ck.toast(e.detail || {});
  });

  // Global failure feedback: any htmx response error (4xx/5xx) or
  // network/timeout error raises an error toast. This is the
  // reconcile-on-error half of optimistic UI applied across every
  // htmx mutation at once — the ckOptimistic helper handles the
  // visual rollback per element.
  document.addEventListener('htmx:responseError', function (e) {
    var status = e.detail && e.detail.xhr ? e.detail.xhr.status : 0;
    window.ck.toast({
      variant: 'error',
      title: 'Request failed',
      message: status ? 'The server returned ' + status + '.' : 'Please try again.',
    });
  });
  document.addEventListener('htmx:sendError', function () {
    window.ck.toast({ variant: 'error', title: 'Network error', message: 'Could not reach the daemon.' });
  });
})();

// v1.18 phase 12 — confetti. window.ck.confetti() spawns a short burst
// of DOM particles from the top of the viewport. No canvas, no library:
// ~60 absolutely-positioned divs that fall + spin + fade, then clean up
// after themselves. Skipped entirely under prefers-reduced-motion (the
// celebration still toasts; it just doesn't animate).
window.ck = window.ck || {};
window.ck.confetti = function (opts) {
  opts = opts || {};
  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  var count = opts.count || 60;
  var colors = ['#6366f1', '#22c55e', '#f59e0b', '#06b6d4', '#ec4899', '#a855f7'];
  var layer = document.createElement('div');
  layer.style.cssText = 'position:fixed;inset:0;pointer-events:none;z-index:80;overflow:hidden;';
  document.body.appendChild(layer);
  for (var i = 0; i < count; i++) {
    var p = document.createElement('div');
    var size = 6 + Math.random() * 6;
    var left = Math.random() * 100;
    var delay = Math.random() * 0.2;
    var dur = 1.6 + Math.random() * 1.4;
    var rot = (Math.random() * 720 - 360) | 0;
    var drift = (Math.random() * 120 - 60) | 0;
    p.style.cssText =
      'position:absolute;top:-16px;left:' + left + '%;width:' + size + 'px;height:' + (size * 0.5) + 'px;' +
      'background:' + colors[i % colors.length] + ';opacity:0.9;border-radius:1px;' +
      'will-change:transform,opacity;' +
      'animation:ck-confetti-fall ' + dur + 's cubic-bezier(.2,.6,.4,1) ' + delay + 's forwards;' +
      '--ck-drift:' + drift + 'px;--ck-rot:' + rot + 'deg;';
    layer.appendChild(p);
  }
  setTimeout(function () { if (layer.parentNode) layer.parentNode.removeChild(layer); }, 3400);
};

// v1.18 phase 9 — optimistic-UI Alpine helper. Wrap a mutating control
// in x-data="ckOptimistic()" and call apply(fn) on submit: it runs fn
// immediately (the optimistic update) + records a rollback. If the
// triggering htmx request errors, the helper reverts the DOM change
// and the global error toast above explains why. On success the
// optimistic state stands (the server swap reconciles it).
document.addEventListener('alpine:init', function () {
  if (!window.Alpine) return;
  window.Alpine.data('ckOptimistic', function () {
    return {
      pending: false,
      _rollback: null,
      // optimistic(applyFn, rollbackFn): apply now, remember how to undo.
      optimistic: function (applyFn, rollbackFn) {
        this.pending = true;
        this._rollback = rollbackFn || null;
        if (typeof applyFn === 'function') applyFn();
      },
      // call from @htmx:after-request to settle / roll back.
      settle: function (ok) {
        this.pending = false;
        if (!ok && typeof this._rollback === 'function') this._rollback();
        this._rollback = null;
      },
    };
  });
});

// v1.18 phase 3 — Alpine factories for the design-system components.
// ck-dropdown + ck-modal partials reference these via x-data; Alpine
// auto-registers them on alpine:init. Adding a new interactive
// component? Register its factory here, never in an inline <script>
// (CSP would block it per ADR-018).
document.addEventListener('alpine:init', function () {
  if (!window.Alpine) return;
  // ckDropdown — open/close + click-outside dismiss. Matches the
  // ck-dropdown.html partial's x-data binding.
  window.Alpine.data('ckDropdown', function () {
    return {
      open: false,
      toggle: function () { this.open = !this.open; },
      close: function () { this.open = false; },
    };
  });
  // ckChartTip — rich hover tooltip for the v1.18 phase 12 score
  // chart. show($event) reads the hovered point's data-* attributes +
  // positions the tooltip near the cursor within the chart card.
  window.Alpine.data('ckChartTip', function () {
    return {
      open: false,
      tip: { date: '', score: '', total: '', actionable: '' },
      style: '',
      show: function (e) {
        var t = e.target;
        if (!t || !t.dataset) return;
        this.tip = {
          date: t.dataset.date || '',
          score: t.dataset.score || '',
          total: t.dataset.total || '',
          actionable: t.dataset.actionable || '',
        };
        // Position relative to the chart card (the x-data root).
        var host = this.$el;
        var hr = host.getBoundingClientRect();
        var pr = t.getBoundingClientRect();
        var x = pr.left - hr.left + pr.width / 2;
        var y = pr.top - hr.top;
        this.style = 'left:' + x + 'px; top:' + y + 'px;';
        this.open = true;
      },
      hide: function () { this.open = false; },
    };
  });
  // ckModal — open/close keyed by ID, with focus-trap on open. The
  // partial passes its own ID into the factory so cross-page modals
  // don't collide. window.dispatchEvent(new CustomEvent('ck-modal-open',
  // {detail:'<id>'})) opens; Esc / click-outside closes.
  window.Alpine.data('ckModal', function (id) {
    return {
      open: false,
      id: id,
      _onOpen: null,
      init: function () {
        var self = this;
        self._onOpen = function (e) {
          if (e && e.detail === self.id) {
            self.open = true;
            // Move focus into the panel on the next tick so the close
            // button receives focus and screen readers announce it.
            setTimeout(function () {
              var el = document.getElementById(self.id);
              var btn = el && el.querySelector('button');
              if (btn) btn.focus();
            }, 30);
          }
        };
        window.addEventListener('ck-modal-open', self._onOpen);
      },
      destroy: function () {
        if (this._onOpen) window.removeEventListener('ck-modal-open', this._onOpen);
      },
      close: function () { this.open = false; },
    };
  });
});
