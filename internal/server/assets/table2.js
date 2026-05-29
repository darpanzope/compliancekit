// v1.19 phase 7 — Table 2.0. Progressive enhancement for any table
// tagged data-ck-table2="<id>": drag-to-resize columns, drag-to-reorder
// columns, pin-left, a column-visibility menu, and a per-(user,table)
// saved layout that round-trips through GET/POST /tables/<id>/layout.
//
// Columns are keyed by a slug of the header text (or an explicit
// data-col on the <th>); body cells match via their data-col or
// data-label (the same data-label the mobile-card mode already sets),
// so no per-row markup change is needed. The layout is re-applied on
// htmx:afterSwap so infinite-scroll-appended rows pick it up.
//
// Disabled below the sm breakpoint (640px) where the .ck-table-cards
// mobile layout takes over.
(function () {
  function slug(s) {
    return (s || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  }
  function csrf() {
    var m = document.cookie.match(/(?:^|;\s*)ck_csrf=([^;]+)/);
    return m ? decodeURIComponent(m[1]) : '';
  }
  function isMobile() { return window.matchMedia('(max-width: 639px)').matches; }

  function thKey(th) { return th.dataset.col || slug(th.textContent); }
  function cellKey(c) {
    if (c.tagName === 'TH') return thKey(c);
    return c.dataset.col || slug(c.dataset.label || '');
  }

  function Table2(table) {
    this.table = table;
    this.id = table.dataset.ckTable2;
    this.head = table.tHead && table.tHead.rows[0];
    if (!this.head) return;
    this.ths = Array.prototype.slice.call(this.head.cells);
    this.cols = this.ths.map(thKey);
    this.labels = {};
    this.ths.forEach(function (th, i) { this.labels[this.cols[i]] = th.textContent.trim(); }, this);
    this.layout = { order: this.cols.slice(), hidden: [], widths: {}, pinLeft: [] };
    this.saveTimer = null;
    this.init();
  }

  Table2.prototype.allRows = function () {
    var rs = [this.head];
    var tbs = this.table.tBodies;
    for (var i = 0; i < tbs.length; i++) {
      for (var j = 0; j < tbs[i].rows.length; j++) rs.push(tbs[i].rows[j]);
    }
    return rs;
  };

  Table2.prototype.init = function () {
    var self = this;
    this.injectMenu();
    this.injectResizers();
    this.enableReorder();
    // Load persisted layout, then apply.
    fetch('/tables/' + encodeURIComponent(this.id) + '/layout', { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.ok ? r.json() : {}; })
      .then(function (saved) { self.merge(saved); self.apply(); })
      .catch(function () { self.apply(); });
    // Re-apply to htmx-appended rows (findings infinite scroll).
    document.body.addEventListener('htmx:afterSwap', function (e) {
      if (self.table.contains(e.target) || e.target.contains(self.table)) self.apply();
    });
  };

  // merge folds a persisted layout into the defaults, dropping keys that
  // no longer exist (schema drift) + appending new columns at the end.
  Table2.prototype.merge = function (saved) {
    if (!saved || typeof saved !== 'object') return;
    var known = this.cols;
    if (Array.isArray(saved.order)) {
      var order = saved.order.filter(function (k) { return known.indexOf(k) >= 0; });
      known.forEach(function (k) { if (order.indexOf(k) < 0) order.push(k); });
      this.layout.order = order;
    }
    if (Array.isArray(saved.hidden)) {
      this.layout.hidden = saved.hidden.filter(function (k) { return known.indexOf(k) >= 0; });
    }
    if (Array.isArray(saved.pinLeft)) {
      this.layout.pinLeft = saved.pinLeft.filter(function (k) { return known.indexOf(k) >= 0; });
    }
    if (saved.widths && typeof saved.widths === 'object') {
      var w = {};
      known.forEach(function (k) { if (typeof saved.widths[k] === 'number') w[k] = saved.widths[k]; });
      this.layout.widths = w;
    }
  };

  Table2.prototype.apply = function () {
    if (isMobile()) return; // mobile-card layout owns small screens
    var self = this;
    // 1. Reorder cells in every row to match layout.order.
    this.allRows().forEach(function (row) {
      var byKey = {};
      Array.prototype.forEach.call(row.cells, function (c) { byKey[cellKey(c)] = c; });
      self.layout.order.forEach(function (k) { if (byKey[k]) row.appendChild(byKey[k]); });
    });
    // 2. Visibility + 3. widths.
    this.allRows().forEach(function (row) {
      Array.prototype.forEach.call(row.cells, function (c) {
        var k = cellKey(c);
        c.style.display = self.layout.hidden.indexOf(k) >= 0 ? 'none' : '';
        var w = self.layout.widths[k];
        c.style.width = c.style.minWidth = c.style.maxWidth = w ? (w + 'px') : '';
      });
    });
    // 4. Pin-left (cumulative sticky offsets, in display order).
    var left = 0;
    this.layout.order.forEach(function (k) {
      var pinned = self.layout.pinLeft.indexOf(k) >= 0 && self.layout.hidden.indexOf(k) < 0;
      var width = 0;
      self.allRows().forEach(function (row) {
        Array.prototype.forEach.call(row.cells, function (c) {
          if (cellKey(c) !== k) return;
          if (pinned) { c.classList.add('ck-col-pin'); c.style.left = left + 'px'; }
          else { c.classList.remove('ck-col-pin'); c.style.left = ''; }
          if (c.tagName === 'TH') width = c.getBoundingClientRect().width;
        });
      });
      if (pinned) left += width || 120;
    });
    this.renderMenu();
  };

  Table2.prototype.persist = function () {
    var self = this;
    clearTimeout(this.saveTimer);
    this.saveTimer = setTimeout(function () {
      fetch('/tables/' + encodeURIComponent(self.id) + '/layout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() },
        body: JSON.stringify(self.layout),
      }).catch(function () {});
    }, 400);
  };

  // ── column-visibility + pin menu ──────────────────────────────────
  Table2.prototype.injectMenu = function () {
    var self = this;
    var wrap = document.createElement('div');
    wrap.className = 'ck-table2-cols';
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'ck-btn ck-btn-secondary ck-btn-sm';
    btn.textContent = 'Columns';
    var menu = document.createElement('div');
    menu.className = 'ck-table2-menu';
    menu.hidden = true;
    btn.addEventListener('click', function (e) { e.stopPropagation(); menu.hidden = !menu.hidden; });
    document.addEventListener('click', function () { menu.hidden = true; });
    menu.addEventListener('click', function (e) { e.stopPropagation(); });
    wrap.appendChild(btn);
    wrap.appendChild(menu);
    this.menu = menu;
    // Anchor the control: prefer an explicit [data-ck-table2-controls]
    // slot, else float it above the table.
    var slot = document.querySelector('[data-ck-table2-controls="' + this.id + '"]');
    (slot || this.table.parentNode).insertBefore(wrap, slot ? null : this.table);
    self.renderMenu();
  };

  Table2.prototype.renderMenu = function () {
    if (!this.menu) return;
    var self = this;
    this.menu.innerHTML = '';
    this.layout.order.forEach(function (k, idx) {
      var row = document.createElement('div');
      row.className = 'ck-table2-menu-row';
      var cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = self.layout.hidden.indexOf(k) < 0;
      cb.addEventListener('change', function () { self.toggleHidden(k); });
      var label = document.createElement('span');
      label.className = 'ck-table2-menu-label';
      label.textContent = self.labels[k] || k;
      var pin = document.createElement('button');
      pin.type = 'button';
      pin.className = 'ck-table2-pin' + (self.layout.pinLeft.indexOf(k) >= 0 ? ' ck-table2-pin-on' : '');
      pin.title = 'Pin left';
      pin.textContent = '📌';
      pin.addEventListener('click', function () { self.togglePin(k); });
      var up = document.createElement('button');
      up.type = 'button'; up.className = 'ck-table2-move'; up.textContent = '↑'; up.title = 'Move left';
      up.disabled = idx === 0;
      up.addEventListener('click', function () { self.moveCol(k, -1); });
      var down = document.createElement('button');
      down.type = 'button'; down.className = 'ck-table2-move'; down.textContent = '↓'; down.title = 'Move right';
      down.disabled = idx === self.layout.order.length - 1;
      down.addEventListener('click', function () { self.moveCol(k, 1); });
      row.appendChild(cb); row.appendChild(label); row.appendChild(pin); row.appendChild(up); row.appendChild(down);
      self.menu.appendChild(row);
    });
  };

  Table2.prototype.toggleHidden = function (k) {
    var i = this.layout.hidden.indexOf(k);
    if (i >= 0) this.layout.hidden.splice(i, 1);
    else if (this.layout.hidden.length < this.cols.length - 1) this.layout.hidden.push(k); // keep ≥1 visible
    this.apply(); this.persist();
  };
  Table2.prototype.togglePin = function (k) {
    var i = this.layout.pinLeft.indexOf(k);
    if (i >= 0) this.layout.pinLeft.splice(i, 1); else this.layout.pinLeft.push(k);
    this.apply(); this.persist();
  };
  Table2.prototype.moveCol = function (k, delta) {
    var i = this.layout.order.indexOf(k);
    var j = i + delta;
    if (i < 0 || j < 0 || j >= this.layout.order.length) return;
    this.layout.order.splice(i, 1);
    this.layout.order.splice(j, 0, k);
    this.apply(); this.persist();
  };

  // ── drag-to-resize ────────────────────────────────────────────────
  Table2.prototype.injectResizers = function () {
    var self = this;
    this.ths.forEach(function (th) {
      th.classList.add('ck-th2');
      var handle = document.createElement('span');
      handle.className = 'ck-col-resizer';
      handle.addEventListener('mousedown', function (e) { self.startResize(e, th); });
      th.appendChild(handle);
    });
  };
  Table2.prototype.startResize = function (e, th) {
    e.preventDefault(); e.stopPropagation();
    var self = this, k = thKey(th);
    var startX = e.clientX, startW = th.getBoundingClientRect().width;
    document.body.classList.add('ck-col-resizing');
    function move(ev) {
      var w = Math.max(60, Math.round(startW + (ev.clientX - startX)));
      self.layout.widths[k] = w;
      self.allRows().forEach(function (row) {
        Array.prototype.forEach.call(row.cells, function (c) {
          if (cellKey(c) === k) { c.style.width = c.style.minWidth = c.style.maxWidth = w + 'px'; }
        });
      });
    }
    function up() {
      document.removeEventListener('mousemove', move);
      document.removeEventListener('mouseup', up);
      document.body.classList.remove('ck-col-resizing');
      self.persist();
    }
    document.addEventListener('mousemove', move);
    document.addEventListener('mouseup', up);
  };

  // ── drag-to-reorder (HTML5 draggable headers) ─────────────────────
  Table2.prototype.enableReorder = function () {
    var self = this, dragKey = null;
    this.ths.forEach(function (th) {
      th.setAttribute('draggable', 'true');
      th.addEventListener('dragstart', function (e) {
        dragKey = thKey(th); th.classList.add('ck-th2-dragging');
        if (e.dataTransfer) e.dataTransfer.effectAllowed = 'move';
      });
      th.addEventListener('dragend', function () { th.classList.remove('ck-th2-dragging'); dragKey = null; });
      th.addEventListener('dragover', function (e) { e.preventDefault(); th.classList.add('ck-th2-over'); });
      th.addEventListener('dragleave', function () { th.classList.remove('ck-th2-over'); });
      th.addEventListener('drop', function (e) {
        e.preventDefault(); th.classList.remove('ck-th2-over');
        var target = thKey(th);
        if (!dragKey || dragKey === target) return;
        var from = self.layout.order.indexOf(dragKey);
        var to = self.layout.order.indexOf(target);
        if (from < 0 || to < 0) return;
        self.layout.order.splice(from, 1);
        self.layout.order.splice(to, 0, dragKey);
        self.apply(); self.persist();
      });
    });
  };

  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('[data-ck-table2]').forEach(function (t) { new Table2(t); });
  });
})();
