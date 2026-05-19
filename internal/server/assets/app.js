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
