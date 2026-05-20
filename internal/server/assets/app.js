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
            var html = '';
            if (t === 'scan.completed') {
              html = '<span data-status-pill class="inline-flex items-center gap-1.5 text-xs text-success"><span class="h-2 w-2 rounded-full bg-success"></span>completed</span>';
            } else if (t === 'scan.started') {
              html = '<span data-status-pill class="inline-flex items-center gap-1.5 text-xs"><span class="h-2 w-2 rounded-full bg-warning animate-pulse"></span>running</span>';
            } else if (t === 'scan.failed') {
              html = '<span data-status-pill class="inline-flex items-center gap-1.5 text-xs text-destructive"><span class="h-2 w-2 rounded-full bg-destructive"></span>failed</span>';
            } else { // queued
              html = '<span data-status-pill class="inline-flex items-center gap-1.5 text-xs text-muted-foreground"><span class="h-2 w-2 rounded-full bg-muted-foreground"></span>queued</span>';
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
      });
      window.ck.events.on('scan.completed', function (ev) {
        var dur = ev.data && ev.data.duration_ms ? ' in ' + ev.data.duration_ms + 'ms' : '';
        self.push({
          variant: 'success',
          title: 'Scan completed' + dur,
          body: ev.entity_id ? 'Scan ' + ev.entity_id.slice(0, 8) : '',
          href: ev.entity_id ? '/scans/' + ev.entity_id : '/scans',
        });
      });
      window.ck.events.on('scan.failed', function (ev) {
        self.push({
          variant: 'destructive',
          title: 'Scan failed',
          body: (ev.data && ev.data.error) || 'See /scans for detail',
          href: ev.entity_id ? '/scans/' + ev.entity_id : '/scans',
        });
      });
      window.ck.events.on('webhook.received', function (ev) {
        self.push({
          variant: 'primary',
          title: 'Webhook received',
          body: (ev.data && ev.data.source) || ev.entity_id || '',
          href: '/audit',
        });
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

// Cmd+K global search palette factory. Referenced from base.html as
// `x-data="cmdk()"`. Vanilla Alpine — no extra JS library. Modal is
// mounted at body level so every authenticated page can open it via
// the keyboard shortcut.
function cmdk() {
  return {
    visible: false,
    query: '',
    results: [],
    open: function () {
      this.visible = true;
      this.$nextTick(function () {
        if (this.$refs.input) this.$refs.input.focus();
      }.bind(this));
    },
    run: async function () {
      if (this.query.length === 0) { this.results = []; return; }
      try {
        var r = await fetch('/search?q=' + encodeURIComponent(this.query));
        if (!r.ok) { this.results = []; return; }
        this.results = await r.json();
      } catch (e) {
        this.results = [];
      }
    },
  };
}
