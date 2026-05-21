// v1.10 phase 1 — Keyboard navigation + focus management helpers.
//
// Loaded from base.html alongside /assets/app.js. Owns:
//   - Global Escape key handler that closes any element marked
//     [data-ck-dismiss="true"] (modals, side-panels, dropdowns).
//   - Focus trap installation for modals — Tab cycles within the
//     modal; Shift-Tab cycles backward. Operators can't tab out of
//     an open dialog by accident.
//   - Skip-link Enter-focus behavior: clicking the skip link or
//     pressing Enter on it moves focus into <main> so screen
//     readers + keyboard users land at the same spot.
//
// All wiring uses standard DOM events — no Alpine, no htmx, no
// framework lock-in. Stays in plain JS so the CSP doesn't need
// 'unsafe-eval' for this surface.

(function () {
  'use strict';

  // ─── Skip-link → main focus ─────────────────────────────────────
  function focusMain() {
    var main = document.getElementById('ck-main');
    if (main) {
      main.focus({ preventScroll: false });
    }
  }
  document.addEventListener('DOMContentLoaded', function () {
    var skip = document.querySelector('.ck-skip-link');
    if (!skip) return;
    skip.addEventListener('click', function (e) {
      e.preventDefault();
      focusMain();
    });
  });

  // ─── Global Escape dismiss ──────────────────────────────────────
  // Any element with [data-ck-dismiss="true"] receives a synthetic
  // close-detail event when Escape fires anywhere in the doc.
  // Alpine components listen via @close-detail.window.
  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    // If a native <dialog> is open, let the browser handle it.
    if (document.querySelector('dialog[open]')) return;
    window.dispatchEvent(new CustomEvent('close-detail'));
  });

  // ─── Focus trap helper ──────────────────────────────────────────
  // Operators tag a modal root with data-ck-focus-trap="true" + the
  // helper queries every focusable descendant and cycles Tab within
  // the set. The helper is intentionally idempotent: calling
  // installFocusTrap on an already-trapped element is a no-op.
  var FOCUSABLE = [
    'a[href]', 'button:not([disabled])', 'input:not([disabled])',
    'select:not([disabled])', 'textarea:not([disabled])',
    'summary', '[tabindex]:not([tabindex="-1"])',
  ].join(',');

  function focusables(root) {
    var nodes = root.querySelectorAll(FOCUSABLE);
    var out = [];
    for (var i = 0; i < nodes.length; i++) {
      var n = nodes[i];
      // Skip hidden elements; computed style covers display:none + visibility:hidden.
      var style = window.getComputedStyle(n);
      if (style.display === 'none' || style.visibility === 'hidden') continue;
      out.push(n);
    }
    return out;
  }

  function installFocusTrap(root) {
    if (!root || root.dataset.ckTrapInstalled === '1') return;
    root.dataset.ckTrapInstalled = '1';
    root.addEventListener('keydown', function (e) {
      if (e.key !== 'Tab') return;
      var nodes = focusables(root);
      if (!nodes.length) return;
      var first = nodes[0], last = nodes[nodes.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    });
    // Auto-focus the first focusable on install so the modal opens
    // with focus inside the trap — operators don't have to tab in.
    var nodes = focusables(root);
    if (nodes.length) nodes[0].focus();
  }

  // Walk on load + on every htmx swap so dynamically-injected
  // modals get trapped without a per-template wiring change.
  function scanForTraps() {
    var roots = document.querySelectorAll('[data-ck-focus-trap="true"]');
    for (var i = 0; i < roots.length; i++) {
      installFocusTrap(roots[i]);
    }
  }
  document.addEventListener('DOMContentLoaded', scanForTraps);
  document.body && document.body.addEventListener('htmx:afterSwap', scanForTraps);

  // Expose for ad-hoc use (Alpine x-init="window.ck.installFocusTrap($el)").
  window.ck = window.ck || {};
  window.ck.installFocusTrap = installFocusTrap;
  window.ck.focusMain = focusMain;
})();
