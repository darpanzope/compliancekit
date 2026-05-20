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
  var lastID = 0;
  var es = null;
  var connected = false;
  var stopped = false;

  function emit(type, ev) {
    var bucket = listeners[type] || [];
    for (var i = 0; i < bucket.length; i++) {
      try { bucket[i](ev); } catch (e) { console.error('ck.events handler', type, e); }
    }
    for (var j = 0; j < allListeners.length; j++) {
      try { allListeners[j](ev); } catch (e) { console.error('ck.events * handler', e); }
    }
  }

  function connect() {
    if (stopped) return;
    var url = '/api/v1/events?since=' + lastID;
    try { es = new EventSource(url); } catch (e) { schedule(); return; }
    es.onopen = function () { connected = true; api.connected = true; };
    es.onerror = function () {
      connected = false; api.connected = false;
      try { es.close(); } catch (_) {}
      schedule();
    };
    // SSE uses named events; we have one listener per type so add each.
    var types = ['scan.queued','scan.started','scan.progress',
                 'scan.completed','scan.failed','finding.created',
                 'finding.resolved','webhook.received','auth.session.created'];
    types.forEach(function (t) {
      es.addEventListener(t, function (e) {
        try {
          var payload = JSON.parse(e.data);
          lastID = payload.id || lastID;
          emit(t, payload);
        } catch (err) { console.error('ck.events parse', t, err); }
      });
    });
  }

  function schedule() {
    if (stopped) return;
    setTimeout(connect, 2000); // simple 2s backoff; phase 7 layers jitter
  }

  var api = {
    connected: false,
    on: function (type, callback) {
      if (type === '*') { allListeners.push(callback); return; }
      (listeners[type] = listeners[type] || []).push(callback);
    },
    stop: function () { stopped = true; if (es) es.close(); },
  };

  // Boot on DOMContentLoaded so the EventSource doesn't race the
  // initial page render. /login pages skip — no auth cookie yet.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      if (!document.body || document.body.dataset.loginPage === '1') return;
      connect();
    });
  } else {
    if (document.body && document.body.dataset.loginPage !== '1') connect();
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
