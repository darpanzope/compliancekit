/* compliancekit HTML report — vanilla-JS SVG chart primitives.
 *
 * Three drawers: gauge (radial 180°), donut (severity breakdown),
 * hbar (horizontal-bar framework coverage). Each reads its data from
 * data-* attributes on the host <svg> element, reads palette colors
 * live from CSS variables on :root (so a theme flip re-paints
 * correctly), and re-renders on every theme-toggle click + OS
 * prefers-color-scheme change.
 *
 * No external CDN, no module bundler. Single inline <script>.
 * Sparkline drawer for phase 6 will land in this same file.
 */
(function () {
  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function polar(cx, cy, r, deg) {
    var a = (deg - 90) * Math.PI / 180;
    return { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) };
  }

  // Donut-segment / ring-arc path. startDeg < endDeg, both in [0..360].
  // inner is the inner radius; outer is r. Path is a closed wedge.
  function ringArc(cx, cy, r, inner, startDeg, endDeg) {
    if (endDeg - startDeg >= 359.999) {
      // Full ring — split into two halves so the arc never collapses.
      return ringArc(cx, cy, r, inner, 0, 180) + ' ' + ringArc(cx, cy, r, inner, 180, 360);
    }
    var s = polar(cx, cy, r, startDeg);
    var e = polar(cx, cy, r, endDeg);
    var si = polar(cx, cy, inner, startDeg);
    var ei = polar(cx, cy, inner, endDeg);
    var large = (endDeg - startDeg) > 180 ? 1 : 0;
    return [
      'M', s.x, s.y,
      'A', r, r, 0, large, 1, e.x, e.y,
      'L', ei.x, ei.y,
      'A', inner, inner, 0, large, 0, si.x, si.y,
      'Z'
    ].join(' ');
  }

  function drawGauge(el) {
    var value = parseFloat(el.getAttribute('data-value')) || 0;
    var max = parseFloat(el.getAttribute('data-max')) || 100;
    var pct = Math.max(0, Math.min(1, value / max));
    var W = 200, H = 130, cx = W / 2, cy = 110, r = 88, thick = 16;
    var startDeg = -90, endDeg = 90;
    var fillEnd = startDeg + (endDeg - startDeg) * pct;
    // Translate from -90..90 (gauge) to 270..90 (full-circle) so
    // ringArc's [0..360] domain works. Equivalent angles.
    var bgPath = ringArc(cx, cy, r, r - thick, 270, 360 + 90);
    var fillPath = ringArc(cx, cy, r, r - thick, 270, 270 + (endDeg - startDeg) * pct);
    var color = pct >= 0.85 ? cssVar('--status-pass')
              : pct >= 0.50 ? cssVar('--sev-medium')
              :               cssVar('--sev-high');
    el.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    el.innerHTML =
      '<path d="' + bgPath + '" fill="' + cssVar('--panel-2') + '"/>' +
      '<path d="' + fillPath + '" fill="' + color + '"/>' +
      '<text x="' + cx + '" y="' + (cy - 14) + '" text-anchor="middle" font-size="38" font-weight="600" fill="' + cssVar('--text') + '" font-variant-numeric="tabular-nums">' + Math.round(value) + '</text>' +
      '<text x="' + cx + '" y="' + (cy + 8) + '" text-anchor="middle" font-size="11" fill="' + cssVar('--muted') + '" letter-spacing="0.06em">/ ' + max + '</text>';
    // Suppress fillEnd-unused warning from older linters.
    void fillEnd;
  }

  function drawDonut(el) {
    var segments;
    try { segments = JSON.parse(el.getAttribute('data-segments') || '[]'); } catch (e) { segments = []; }
    var W = 200, H = 180, cx = W / 2, cy = H / 2, r = 78, thick = 22;
    var total = segments.reduce(function (a, s) { return a + (s.value || 0); }, 0);
    var html = '';
    if (total === 0) {
      html += '<circle cx="' + cx + '" cy="' + cy + '" r="' + (r - thick / 2) + '" fill="none" stroke="' + cssVar('--panel-2') + '" stroke-width="' + thick + '"/>';
      html += '<text x="' + cx + '" y="' + (cy + 6) + '" text-anchor="middle" font-size="20" fill="' + cssVar('--muted') + '">0</text>';
    } else {
      var pos = 0;
      for (var i = 0; i < segments.length; i++) {
        var s = segments[i];
        if (!s.value) continue;
        var pct = s.value / total;
        var startDeg = pos * 360;
        var endDeg = (pos + pct) * 360;
        var color = cssVar('--sev-' + s.key) || cssVar('--muted');
        html += '<path d="' + ringArc(cx, cy, r, r - thick, startDeg, endDeg) + '" fill="' + color + '"/>';
        pos += pct;
      }
      html += '<text x="' + cx + '" y="' + (cy - 4) + '" text-anchor="middle" font-size="32" font-weight="600" fill="' + cssVar('--text') + '" font-variant-numeric="tabular-nums">' + total + '</text>';
      html += '<text x="' + cx + '" y="' + (cy + 18) + '" text-anchor="middle" font-size="11" fill="' + cssVar('--muted') + '" letter-spacing="0.06em">actionable</text>';
    }
    el.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    el.innerHTML = html;
  }

  function drawHBar(el) {
    var items;
    try { items = JSON.parse(el.getAttribute('data-items') || '[]'); } catch (e) { items = []; }
    var W = 280, rowH = 28, top = 8;
    var H = items.length * rowH + top * 2 || 60;
    var labelW = 92, valueW = 40, barX = labelW + 8, barW = W - labelW - valueW - 16;
    var html = '';
    if (items.length === 0) {
      html = '<text x="' + (W / 2) + '" y="32" text-anchor="middle" font-size="12" fill="' + cssVar('--muted') + '">No framework mappings</text>';
    } else {
      items.forEach(function (it, i) {
        var y = top + i * rowH;
        var total = (it.pass || 0) + (it.fail || 0);
        var pct = total > 0 ? (it.pass / total) : 0;
        html += '<text x="0" y="' + (y + rowH / 2 + 4) + '" font-size="12" fill="' + cssVar('--text') + '">' + it.label + '</text>';
        html += '<rect x="' + barX + '" y="' + (y + rowH / 2 - 6) + '" width="' + barW + '" height="10" rx="5" fill="' + cssVar('--panel-2') + '"/>';
        html += '<rect x="' + barX + '" y="' + (y + rowH / 2 - 6) + '" width="' + (pct * barW) + '" height="10" rx="5" fill="' + cssVar('--status-pass') + '"/>';
        html += '<text x="' + (W - 4) + '" y="' + (y + rowH / 2 + 4) + '" font-size="12" text-anchor="end" font-variant-numeric="tabular-nums" fill="' + cssVar('--muted') + '">' + Math.round(pct * 100) + '%</text>';
      });
    }
    el.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    el.setAttribute('height', H);
    el.innerHTML = html;
  }

  var drawers = { gauge: drawGauge, donut: drawDonut, hbar: drawHBar };

  function renderAll() {
    document.querySelectorAll('[data-chart]').forEach(function (el) {
      var fn = drawers[el.getAttribute('data-chart')];
      if (fn) { try { fn(el); } catch (e) { /* swallow per-chart errors */ } }
    });
  }

  // Initial paint after the DOM is ready (we're at the bottom of
  // <body>, so DOM is already parsed; just call directly).
  renderAll();

  // Theme-flip re-paint. The theme script in this same <script> block
  // wires the toggle buttons; we just need to re-run after a flip so
  // the cssVar() reads pick up the new palette. requestAnimationFrame
  // lets the data-theme attribute update before we read computed style.
  document.querySelectorAll('.theme-toggle button[data-theme-set]').forEach(function (b) {
    b.addEventListener('click', function () { requestAnimationFrame(renderAll); });
  });
  if (window.matchMedia) {
    var mq = window.matchMedia('(prefers-color-scheme: dark)');
    var onChange = function () { requestAnimationFrame(renderAll); };
    if (mq.addEventListener) { mq.addEventListener('change', onChange); }
    else if (mq.addListener) { mq.addListener(onChange); }
  }
})();
