// v1.19 phase 0 — feature-tour overlay engine. ~200 lines, no
// Shepherd.js / Intro.js. Spotlights a sequence of elements tagged with
// data-ck-tour="<tourId>" and walks the operator through them with a
// popover (Prev / Next / Done). Honors prefers-reduced-motion (skips the
// spotlight transition). CSP-safe — loaded as an external script, no
// inline blocks.
//
// Markup contract (per touched element):
//   data-ck-tour="welcome"           tour id this step belongs to
//   data-ck-tour-order="1"           1-based step order within the tour
//   data-ck-tour-title="Scans"       popover heading
//   data-ck-tour-body="..."          popover body
//
// Auto-start: a tour auto-prompts (a small "Press . to start the X tour"
// pill, lower-left) when the page hosts its steps AND the user hasn't
// dismissed it (body[data-ck-tours-dismissed] is a JSON array of ids).
// ?tour=<id> in the URL force-starts that tour immediately (the
// /onboarding replay links use this).
//
// Dismiss/complete persists via POST /onboarding/tours/<id>/dismiss
// (CSRF mirrored from the ck_csrf cookie, matching the htmx convention).
(function () {
  function reduceMotion() {
    return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }
  function csrf() {
    var m = document.cookie.match(/(?:^|;\s*)ck_csrf=([^;]+)/);
    return m ? decodeURIComponent(m[1]) : '';
  }
  function dismissedSet() {
    try {
      return new Set(JSON.parse(document.body.getAttribute('data-ck-tours-dismissed') || '[]'));
    } catch (e) {
      return new Set();
    }
  }
  // Collect + sort the steps for a tour id from the current page.
  function stepsFor(tourId) {
    var els = Array.prototype.slice.call(document.querySelectorAll('[data-ck-tour="' + tourId + '"]'));
    els.sort(function (a, b) {
      return (parseInt(a.dataset.ckTourOrder || '0', 10)) - (parseInt(b.dataset.ckTourOrder || '0', 10));
    });
    return els;
  }
  // Tour ids present on this page, in first-seen order.
  function toursOnPage() {
    var ids = [];
    document.querySelectorAll('[data-ck-tour]').forEach(function (el) {
      var id = el.dataset.ckTour;
      if (id && ids.indexOf(id) === -1) ids.push(id);
    });
    return ids;
  }

  var overlay, spotlight, popover, current = { id: null, steps: [], i: 0 };

  function ensureChrome() {
    if (overlay) return;
    overlay = document.createElement('div');
    overlay.className = 'ck-tour-overlay';
    overlay.setAttribute('aria-hidden', 'true');
    spotlight = document.createElement('div');
    spotlight.className = 'ck-tour-spotlight';
    overlay.appendChild(spotlight);
    popover = document.createElement('div');
    popover.className = 'ck-tour-popover';
    popover.setAttribute('role', 'dialog');
    popover.setAttribute('aria-live', 'polite');
    document.body.appendChild(overlay);
    document.body.appendChild(popover);
  }

  function positionFor(el) {
    var r = el.getBoundingClientRect();
    var pad = 6;
    spotlight.style.left = (r.left - pad) + 'px';
    spotlight.style.top = (r.top - pad) + 'px';
    spotlight.style.width = (r.width + pad * 2) + 'px';
    spotlight.style.height = (r.height + pad * 2) + 'px';
    // Popover: prefer to the right of the target, else below.
    var px = r.right + 16, py = r.top;
    if (px + 300 > window.innerWidth) { px = Math.max(12, r.left); py = r.bottom + 12; }
    popover.style.left = Math.min(px, window.innerWidth - 320) + 'px';
    popover.style.top = py + 'px';
  }

  function render() {
    var el = current.steps[current.i];
    if (!el) { finish(true); return; }
    el.scrollIntoView({ block: 'center', behavior: reduceMotion() ? 'auto' : 'smooth' });
    positionFor(el);
    var n = current.steps.length;
    popover.innerHTML =
      '<div class="ck-tour-step">Step ' + (current.i + 1) + ' of ' + n + '</div>' +
      '<h3 class="ck-tour-title"></h3>' +
      '<p class="ck-tour-body"></p>' +
      '<div class="ck-tour-actions">' +
      '<button type="button" class="ck-btn ck-btn-ghost ck-btn-sm" data-ck-tour-skip>Skip</button>' +
      '<div class="ck-tour-nav">' +
      (current.i > 0 ? '<button type="button" class="ck-btn ck-btn-secondary ck-btn-sm" data-ck-tour-prev>Back</button>' : '') +
      '<button type="button" class="ck-btn ck-btn-primary ck-btn-sm" data-ck-tour-next>' +
      (current.i === n - 1 ? 'Done' : 'Next') + '</button>' +
      '</div></div>';
    // textContent assignment avoids injecting operator-supplied strings as HTML.
    popover.querySelector('.ck-tour-title').textContent = el.dataset.ckTourTitle || '';
    popover.querySelector('.ck-tour-body').textContent = el.dataset.ckTourBody || '';
    popover.querySelector('[data-ck-tour-next]').onclick = next;
    popover.querySelector('[data-ck-tour-skip]').onclick = function () { finish(true); };
    var prev = popover.querySelector('[data-ck-tour-prev]');
    if (prev) prev.onclick = function () { current.i = Math.max(0, current.i - 1); render(); };
  }

  function next() {
    if (current.i >= current.steps.length - 1) { finish(true); return; }
    current.i++;
    render();
  }

  function start(tourId) {
    var steps = stepsFor(tourId);
    if (!steps.length) return;
    ensureChrome();
    current = { id: tourId, steps: steps, i: 0 };
    overlay.classList.add('ck-tour-active');
    popover.classList.add('ck-tour-active');
    render();
  }

  function finish(persist) {
    if (overlay) overlay.classList.remove('ck-tour-active');
    if (popover) popover.classList.remove('ck-tour-active');
    var id = current.id;
    current = { id: null, steps: [], i: 0 };
    if (persist && id) {
      fetch('/onboarding/tours/' + encodeURIComponent(id) + '/dismiss', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf() },
      }).catch(function () {});
    }
  }

  // Reposition on resize/scroll while a tour is live.
  window.addEventListener('resize', function () { if (current.id) positionFor(current.steps[current.i]); });
  window.addEventListener('scroll', function () { if (current.id) positionFor(current.steps[current.i]); }, true);
  document.addEventListener('keydown', function (e) {
    if (!current.id) {
      // "." starts the first undismissed tour on the page.
      if (e.key === '.' && !/^(INPUT|TEXTAREA|SELECT)$/.test((e.target && e.target.tagName) || '')) {
        var dismissed = dismissedSet();
        var avail = toursOnPage().filter(function (id) { return !dismissed.has(id); });
        if (avail.length) { e.preventDefault(); start(avail[0]); }
      }
      return;
    }
    if (e.key === 'Escape') { finish(true); }
    else if (e.key === 'ArrowRight' || e.key === 'Enter') { e.preventDefault(); next(); }
    else if (e.key === 'ArrowLeft') { current.i = Math.max(0, current.i - 1); render(); }
  });

  // Boot: ?tour=<id> force-starts; otherwise show the auto-prompt pill
  // for the first undismissed tour present on the page.
  document.addEventListener('DOMContentLoaded', function () {
    var forced = new URLSearchParams(window.location.search).get('tour');
    if (forced) { start(forced); return; }
    var dismissed = dismissedSet();
    var avail = toursOnPage().filter(function (id) { return !dismissed.has(id); });
    if (!avail.length) return;
    var pill = document.createElement('button');
    pill.type = 'button';
    pill.className = 'ck-tour-prompt';
    pill.textContent = 'Press . for a quick tour';
    pill.onclick = function () { pill.remove(); start(avail[0]); };
    document.body.appendChild(pill);
    setTimeout(function () { if (pill.parentNode) pill.classList.add('ck-tour-prompt-fade'); }, 12000);
  });

  window.ck = window.ck || {};
  window.ck.startTour = start;
})();
