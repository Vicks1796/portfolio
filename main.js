/* CASE FILE VP-26-001 · main.js
   Progressive enhancement only. Everything on the page works without this file.
   Rules this file keeps:
     - never builds HTML from strings (Trusted Types are enforced by CSP)
     - never touches a third-party origin
     - stores exactly one key in localStorage: "theme"
*/
(function () {
  'use strict';

  var doc = document;
  var root = doc.documentElement;

  /* ---------- helpers ---------- */
  function $(id) { return doc.getElementById(id); }
  function setText(el, text) { if (el) el.textContent = String(text); }
  function el(tag, text, cls) {
    var n = doc.createElement(tag);
    if (text != null) n.textContent = String(text);
    if (cls) n.className = cls;
    return n;
  }
  function toHex(buf) {
    var bytes = new Uint8Array(buf), out = '';
    for (var i = 0; i < bytes.length; i++) out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    return out;
  }
  function sha256(text) {
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)).then(toHex);
  }

  /* ---------- theme toggle (persisted) ---------- */
  (function theme() {
    var btn = $('theme-toggle');
    if (!btn) return;
    var mq = matchMedia('(prefers-color-scheme: light)');
    function current() {
      var t = root.getAttribute('data-theme');
      if (t === 'light' || t === 'dark') return t;
      return mq.matches ? 'light' : 'dark';
    }
    function reflect() {
      var isLight = current() === 'light';
      btn.setAttribute('aria-pressed', isLight ? 'true' : 'false');
      btn.setAttribute('aria-label', isLight ? 'Switch to dark theme' : 'Switch to light theme');
    }
    btn.addEventListener('click', function () {
      var next = current() === 'light' ? 'dark' : 'light';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem('theme', next); } catch (e) { /* storage blocked: theme still applies for this page */ }
      reflect();
    });
    mq.addEventListener('change', reflect);
    reflect();
  })();

  /* ---------- redactions: tap to toggle on touch devices ---------- */
  (function redactions() {
    var marks = doc.querySelectorAll('.redact');
    for (var i = 0; i < marks.length; i++) {
      marks[i].addEventListener('click', function () { this.classList.toggle('is-open'); });
      marks[i].addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); this.classList.toggle('is-open'); }
      });
    }
  })();

  /* ---------- index: highlight the section in view ---------- */
  (function indexSpy() {
    if (!('IntersectionObserver' in window)) return;
    var links = doc.querySelectorAll('.index-list a[href^="#"]');
    var map = {};
    for (var i = 0; i < links.length; i++) map[links[i].getAttribute('href').slice(1)] = links[i];
    var ids = Object.keys(map);
    if (!ids.length) return;
    var visible = {};
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { visible[en.target.id] = en.isIntersecting ? en.intersectionRatio : 0; });
      var best = null, bestRatio = 0;
      ids.forEach(function (id) { if (visible[id] > bestRatio) { bestRatio = visible[id]; best = id; } });
      ids.forEach(function (id) { map[id].classList.toggle('is-active', id === best); });
    }, { rootMargin: '-20% 0px -60% 0px', threshold: [0, 0.1, 0.25, 0.5, 1] });
    ids.forEach(function (id) { var s = $(id); if (s) io.observe(s); });
  })();

  /* ---------- copy email (fixed string, never page content) ---------- */
  (function copyEmail() {
    var btn = $('copy-email'), status = $('copy-status');
    if (!btn) return;
    var value = btn.getAttribute('data-email') || '';
    // Only a plain address is ever placed on the clipboard.
    if (!/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(value)) return;
    btn.addEventListener('click', function () {
      if (!navigator.clipboard) { setText(status, 'Select and copy the address manually.'); return; }
      navigator.clipboard.writeText(value).then(function () {
        setText(status, 'Copied to clipboard');
        setTimeout(function () { setText(status, ''); }, 2200);
      }, function () {
        setText(status, 'Clipboard blocked. Select the address instead.');
      });
    });
  })();

  /* ---------- response header audit ---------- */
  var CHECKS = {
    'content-security-policy': function (v) {
      if (!v) return ['bad', 'missing'];
      var low = v.toLowerCase();
      var problems = [];
      if (!/default-src\s+'none'/.test(low) && !/default-src\s+'self'/.test(low)) problems.push('no default-src');
      var script = (low.match(/script-src([^;]*)/) || [])[1] || '';
      if (/'unsafe-inline'/.test(script) || /'unsafe-eval'/.test(script)) problems.push('unsafe script-src');
      if (!/frame-ancestors/.test(low)) problems.push('no frame-ancestors');
      if (!/object-src\s+'none'/.test(low)) problems.push('object-src');
      if (!/base-uri/.test(low)) problems.push('no base-uri');
      var tt = /require-trusted-types-for\s+'script'/.test(low);
      if (problems.length) return ['warn', problems.join(', ')];
      return ['ok', tt ? 'strict · trusted types' : 'strict'];
    },
    'strict-transport-security': function (v) {
      if (!v) return ['bad', 'missing'];
      var age = parseInt((v.match(/max-age=(\d+)/i) || [])[1] || '0', 10);
      if (age < 31536000) return ['warn', 'max-age ' + age + 's'];
      var sub = /includesubdomains/i.test(v), pre = /preload/i.test(v);
      if (!sub) return ['warn', 'no includeSubDomains'];
      return ['ok', pre ? '1y · subdomains · preload' : '1y · subdomains'];
    },
    'x-frame-options': function (v) {
      if (!v) return ['bad', 'missing'];
      return /^(deny|sameorigin)$/i.test(v.trim()) ? ['ok', v.trim().toUpperCase()] : ['warn', v];
    },
    'x-content-type-options': function (v) {
      if (!v) return ['bad', 'missing'];
      return /nosniff/i.test(v) ? ['ok', 'nosniff'] : ['warn', v];
    },
    'referrer-policy': function (v) {
      if (!v) return ['bad', 'missing'];
      var low = v.toLowerCase();
      if (/no-referrer(?!-when)/.test(low) || /strict-origin-when-cross-origin|same-origin|strict-origin/.test(low)) return ['ok', low];
      return ['warn', low];
    },
    'permissions-policy': function (v) {
      if (!v) return ['bad', 'missing'];
      var low = v.toLowerCase(), need = ['camera', 'microphone', 'geolocation'], missing = [];
      need.forEach(function (f) { if (!(new RegExp(f + '=\\(\\)')).test(low)) missing.push(f); });
      return missing.length ? ['warn', 'allows ' + missing.join(', ')] : ['ok', 'sensors denied'];
    },
    'cross-origin-opener-policy': function (v) {
      if (!v) return ['bad', 'missing'];
      return /same-origin/i.test(v) ? ['ok', v.toLowerCase()] : ['warn', v];
    },
    'cross-origin-resource-policy': function (v) {
      if (!v) return ['bad', 'missing'];
      return /same-(origin|site)/i.test(v) ? ['ok', v.toLowerCase()] : ['warn', v];
    },
    'cross-origin-embedder-policy': function (v) {
      if (!v) return ['warn', 'missing (optional)'];
      return /require-corp|credentialless/i.test(v) ? ['ok', v.toLowerCase()] : ['warn', v];
    },
    'x-permitted-cross-domain-policies': function (v) {
      if (!v) return ['warn', 'missing (optional)'];
      return /none/i.test(v) ? ['ok', 'none'] : ['warn', v];
    }
  };

  function thirdPartyRequests() {
    if (!('performance' in window) || !performance.getEntriesByType) return null;
    var list = performance.getEntriesByType('resource'), out = [];
    for (var i = 0; i < list.length; i++) {
      try {
        var u = new URL(list[i].name);
        if (u.origin !== location.origin) out.push(u.hostname);
      } catch (e) { /* ignore unparsable entries */ }
    }
    return out;
  }

  function gradeFor(okCount, warnCount, badCount) {
    if (badCount === 0 && warnCount === 0) return 'A';
    if (badCount === 0 && warnCount <= 2) return 'B';
    if (badCount <= 2) return 'C';
    return 'F';
  }

  function runHeaderAudit() {
    var table = $('hdr-table'), grade = $('hdr-grade'), status = $('hdr-status');
    if (!table) return;
    setText(status, 'Fetching this page…');
    grade.removeAttribute('data-grade'); setText(grade, '…');

    function apply(headers, transport) {
      var ok = 0, warn = 0, bad = 0;
      var rows = table.querySelectorAll('tbody tr[data-h]');
      for (var i = 0; i < rows.length; i++) {
        var name = rows[i].getAttribute('data-h'), cell = rows[i].querySelector('.hdr-res'), res;
        if (name === '_transport') res = transport;
        else res = CHECKS[name](headers.get(name));
        cell.setAttribute('data-state', res[0]);
        setText(cell, res[1]);
        if (res[0] === 'ok') ok++; else if (res[0] === 'warn') warn++; else bad++;
      }
      var g = gradeFor(ok, warn, bad);
      grade.setAttribute('data-grade', g); setText(grade, g);
      setText(status, ok + ' pass · ' + warn + ' warn · ' + bad + ' fail' +
        (location.protocol === 'http:' ? ' · local preview: HTTPS not possible' : ''));
    }

    function transportResult() {
      var third = thirdPartyRequests();
      var https = location.protocol === 'https:';
      var isLocal = /^(localhost|127\.0\.0\.1|\[::1\])$/.test(location.hostname);
      if (third && third.length) return ['bad', 'third-party: ' + third.filter(function (h, i, a) { return a.indexOf(h) === i; }).join(', ')];
      if (https) return ['ok', 'https · first-party only'];
      if (isLocal) return ['warn', 'http (local) · first-party only'];
      return ['bad', 'not https'];
    }

    var url = location.pathname || '/';
    fetch(url, { method: 'HEAD', cache: 'no-store', credentials: 'omit' })
      .then(function (r) { if (!r.ok) throw new Error('HEAD ' + r.status); return r; })
      .catch(function () { return fetch(url, { method: 'GET', cache: 'no-store', credentials: 'omit' }); })
      .then(function (r) {
        if (r.status === 401 || r.status === 403) {
          var rows = table.querySelectorAll('tbody tr[data-h] .hdr-res');
          for (var i = 0; i < rows.length; i++) { rows[i].setAttribute('data-state', 'warn'); setText(rows[i], 'not visible'); }
          grade.setAttribute('data-grade', 'B'); setText(grade, '?');
          setText(status, 'The server answered ' + r.status + '. Visitor protection is on, so this audit only sees the login page. Make the site public and run it again.');
          return;
        }
        apply(r.headers, transportResult());
      })
      .catch(function (err) {
        setText(status, 'Could not fetch this page: ' + (err && err.message ? err.message : 'network error'));
        grade.setAttribute('data-grade', 'F'); setText(grade, '?');
      });
  }

  (function headerAudit() {
    var btn = $('hdr-run');
    if (!btn) return;
    btn.addEventListener('click', runHeaderAudit);
    if ('requestIdleCallback' in window) requestIdleCallback(runHeaderAudit, { timeout: 2000 });
    else setTimeout(runHeaderAudit, 600);
  })();

  /* ---------- page integrity: SHA-256 of the served HTML ---------- */
  function runIntegrity() {
    var served = $('hash-served'), published = $('hash-published'), grade = $('int-grade'), status = $('int-status');
    if (!served || !window.crypto || !crypto.subtle) {
      setText(status, 'Web Crypto is not available in this context.');
      return;
    }
    setText(status, 'Hashing…');
    served.removeAttribute('data-state'); published.removeAttribute('data-state');
    grade.removeAttribute('data-grade'); setText(grade, '…');

    var htmlP = fetch('/index.html', { cache: 'no-store', credentials: 'omit' }).then(function (r) {
      if (r.status === 401 || r.status === 403) throw new Error('index.html ' + r.status + ': visitor protection is on, make the site public first');
      if (!r.ok) throw new Error('index.html ' + r.status);
      return r.text();
    }).then(sha256);

    var pubP = fetch('/integrity.json', { cache: 'no-store', credentials: 'omit' }).then(function (r) {
      if (!r.ok) throw new Error('no integrity.json');
      return r.json();
    }).then(function (j) { return j && j.files && j.files['index.html'] ? String(j.files['index.html']) : null; }, function () { return null; });

    // Hosting platforms sometimes add their own markup at the edge (Netlify's free-tier badge
    // script is one). Strip the known patterns and hash again, so the panel can say exactly
    // what changed instead of a bare mismatch.
    function stripHostInjection(html) {
      var removed = [];
      var out = html.replace(/<!--\s*This site is hosted on Netlify[\s\S]*?-->\n?/g, function () { removed.push('Netlify hosting comment'); return ''; });
      out = out.replace(/<script[^>]*src="\/\.netlify\/scripts\/hud[^"]*"[^>]*><\/script>\n?/g, function () { removed.push('Netlify badge script'); return ''; });
      return { html: out, removed: removed };
    }
    var htmlTextP = fetch('/index.html', { cache: 'no-store', credentials: 'omit' }).then(function (r) { return r.ok ? r.text() : ''; });

    Promise.all([htmlP, pubP, htmlTextP]).then(function (res) {
      var s = res[0], p = res[1], raw = res[2];
      setText(served, s);
      if (!p) {
        setText(published, 'not published (integrity.json is written at build time)');
        grade.setAttribute('data-grade', 'B'); setText(grade, '?');
        setText(status, 'Served digest computed. No published digest to compare against.');
        return;
      }
      setText(published, p);
      var match = s === p.toLowerCase();
      if (match) {
        served.setAttribute('data-state', 'ok'); published.setAttribute('data-state', 'ok');
        grade.setAttribute('data-grade', 'A'); setText(grade, 'MATCH');
        setText(status, 'The HTML you received is byte-identical to the build.');
        return;
      }
      var stripped = stripHostInjection(raw);
      if (stripped.removed.length) {
        return sha256(stripped.html).then(function (s2) {
          var ok = s2 === p.toLowerCase();
          served.setAttribute('data-state', ok ? 'warn' : 'bad'); published.setAttribute('data-state', ok ? 'warn' : 'bad');
          grade.setAttribute('data-grade', ok ? 'B' : 'F'); setText(grade, ok ? 'HOST-MODIFIED' : 'DIFF');
          setText(status, ok
            ? 'The host added content at the edge (' + stripped.removed.join(', ') + '). With those lines removed, the page is byte-identical to the build. Nothing in the authored HTML changed.'
            : 'Digests differ even after removing host-added content. The page may have been modified in transit or cached from an older build.');
        });
      }
      served.setAttribute('data-state', 'bad'); published.setAttribute('data-state', 'bad');
      grade.setAttribute('data-grade', 'F'); setText(grade, 'DIFF');
      setText(status, 'Digests differ. The page may have been modified in transit or cached from an older build.');
    }).catch(function (err) {
      setText(status, 'Could not compute: ' + (err && err.message ? err.message : 'error'));
      grade.setAttribute('data-grade', 'F'); setText(grade, '?');
    });
  }

  (function integrity() {
    var btn = $('int-run');
    if (!btn) return;
    btn.addEventListener('click', runIntegrity);
    if ('requestIdleCallback' in window) requestIdleCallback(runIntegrity, { timeout: 2500 });
    else setTimeout(runIntegrity, 900);
  })();

  /* ---------- PGP fingerprint grid (filled from data attribute when supplied) ---------- */
  (function hexgrid() {
    var grid = $('hexgrid');
    if (!grid) return;
    var fp = (grid.getAttribute('data-fingerprint') || '').replace(/[^0-9a-fA-F]/g, '').toUpperCase();
    if (fp.length !== 40) return;
    grid.replaceChildren();
    for (var i = 0; i < 40; i += 2) grid.appendChild(el('span', fp.slice(i, i + 2)));
    grid.setAttribute('aria-label', 'PGP fingerprint ' + fp.replace(/(.{4})/g, '$1 ').trim());
  })();

  /* ---------- trace field: the dot grid becomes a live substrate ----------
     Thin PCB-style traces route themselves across the grid at right angles, a single packet
     runs along each, then they fade. Runs only without prefers-reduced-motion, pauses when the
     tab is hidden, and the CSS dot grid remains as the fallback. Canvas only, no DOM strings. */
  (function traceField() {
    if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    if (!doc.body || !window.requestAnimationFrame) return;
    var cv = doc.createElement('canvas');
    cv.className = 'trace-field';
    cv.setAttribute('aria-hidden', 'true');
    doc.body.insertBefore(cv, doc.body.firstChild);
    root.classList.add('has-field');
    var ctx = cv.getContext('2d', { alpha: true });
    if (!ctx) { cv.remove(); root.classList.remove('has-field'); return; }

    var CELL = 28, W = 0, H = 0, cols = 0, rows = 0, dpr = 1;
    var col = { ink: '#e9e6df', accent: '#ff5c4a' };
    var traces = [], lastSpawn = 0, lastFrame = 0, lastStep = 0;
    var pointer = { x: -1e4, y: -1e4, active: false };
    var running = false, raf = 0;

    function readColors() {
      var cs = getComputedStyle(root);
      col.ink = cs.getPropertyValue('--ink').trim() || col.ink;
      col.accent = cs.getPropertyValue('--accent').trim() || col.accent;
    }
    function size() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      W = window.innerWidth; H = window.innerHeight;
      cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr);
      cv.style.width = W + 'px'; cv.style.height = H + 'px';
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      cols = Math.ceil(W / CELL) + 1; rows = Math.ceil(H / CELL) + 1;
      traces.length = 0;
    }
    function rnd(n) { return Math.floor(Math.random() * n); }
    var DIRS = [[1, 0], [0, 1], [-1, 0], [0, -1]];

    function spawn() {
      var d = rnd(4);
      traces.push({
        pts: [[rnd(cols), rnd(rows)]], dir: d, maxLen: 8 + rnd(22),
        phase: 'grow', alpha: 0, hold: 1800 + rnd(2200), t: 0, packet: 0
      });
    }
    function step(now) {
      // grow every ~55ms, independent of frame rate
      if (now - lastStep < 55) return;
      lastStep = now;
      for (var i = traces.length - 1; i >= 0; i--) {
        var tr = traces[i];
        if (tr.phase === 'grow') {
          tr.alpha = Math.min(1, tr.alpha + 0.12);
          if (Math.random() < 0.16) tr.dir = (tr.dir + (Math.random() < 0.5 ? 1 : 3)) % 4;
          var last = tr.pts[tr.pts.length - 1];
          var nx = last[0] + DIRS[tr.dir][0], ny = last[1] + DIRS[tr.dir][1];
          if (nx < 0 || ny < 0 || nx >= cols || ny >= rows || tr.pts.length >= tr.maxLen) { tr.phase = 'hold'; tr.t = now; }
          else tr.pts.push([nx, ny]);
        } else if (tr.phase === 'hold') {
          tr.packet = Math.min(1, (now - tr.t) / tr.hold);
          if (now - tr.t > tr.hold) { tr.phase = 'fade'; tr.t = now; }
        } else {
          tr.alpha -= 0.05;
          if (tr.alpha <= 0) traces.splice(i, 1);
        }
      }
      var cap = Math.max(4, Math.min(10, Math.round((W * H) / 160000)));
      if (traces.length < cap && now - lastSpawn > 650) { spawn(); lastSpawn = now; }
    }
    function draw() {
      ctx.clearRect(0, 0, W, H);
      // dots
      ctx.fillStyle = col.ink;
      var px = pointer.x, py = pointer.y, R = 150, R2 = R * R;
      for (var c = 0; c < cols; c++) {
        for (var r = 0; r < rows; r++) {
          var x = c * CELL + 1, y = r * CELL + 1, a = 0.13, sz = 1.2;
          if (pointer.active) {
            var dx = x - px, dy = y - py, d2 = dx * dx + dy * dy;
            if (d2 < R2) { var k = 1 - Math.sqrt(d2) / R; a += 0.45 * k; sz += 0.9 * k; }
          }
          ctx.globalAlpha = a;
          ctx.fillRect(x - sz / 2, y - sz / 2, sz, sz);
        }
      }
      // traces
      ctx.lineWidth = 1; ctx.lineJoin = 'miter'; ctx.lineCap = 'butt';
      for (var i = 0; i < traces.length; i++) {
        var tr = traces[i], pts = tr.pts;
        if (pts.length < 2) continue;
        ctx.globalAlpha = 0.28 * tr.alpha; ctx.strokeStyle = col.ink;
        ctx.beginPath(); ctx.moveTo(pts[0][0] * CELL + 1, pts[0][1] * CELL + 1);
        for (var j = 1; j < pts.length; j++) ctx.lineTo(pts[j][0] * CELL + 1, pts[j][1] * CELL + 1);
        ctx.stroke();
        // vias at the two ends
        ctx.globalAlpha = 0.5 * tr.alpha; ctx.fillStyle = col.ink;
        var e0 = pts[0], e1 = pts[pts.length - 1];
        ctx.fillRect(e0[0] * CELL - 1, e0[1] * CELL - 1, 4, 4);
        ctx.fillRect(e1[0] * CELL - 1, e1[1] * CELL - 1, 4, 4);
        // packet: a short bright run that travels the trace while it holds
        if (tr.phase === 'hold' || tr.phase === 'fade') {
          var segs = pts.length - 1, pos = tr.packet * segs, len = 2.5;
          var s0 = Math.max(0, pos - len), s1 = pos;
          ctx.globalAlpha = 0.9 * tr.alpha; ctx.strokeStyle = col.accent; ctx.lineWidth = 1.5;
          ctx.beginPath();
          var started = false;
          for (var k2 = Math.floor(s0); k2 <= Math.min(segs - 1, Math.floor(s1)); k2++) {
            var a0 = Math.max(s0, k2) - k2, a1 = Math.min(s1, k2 + 1) - k2;
            var p0 = pts[k2], p1 = pts[k2 + 1];
            var x0 = (p0[0] + (p1[0] - p0[0]) * a0) * CELL + 1, y0 = (p0[1] + (p1[1] - p0[1]) * a0) * CELL + 1;
            var x1 = (p0[0] + (p1[0] - p0[0]) * a1) * CELL + 1, y1 = (p0[1] + (p1[1] - p0[1]) * a1) * CELL + 1;
            if (!started) { ctx.moveTo(x0, y0); started = true; }
            ctx.lineTo(x1, y1);
          }
          ctx.stroke(); ctx.lineWidth = 1;
        }
      }
      ctx.globalAlpha = 1;
    }
    function frame(now) {
      raf = 0;
      if (!running) return;
      if (now - lastFrame >= 33) { // ~30 fps is plenty for this
        lastFrame = now; step(now); draw();
      }
      raf = requestAnimationFrame(frame);
    }
    function start() { if (running) return; running = true; if (!raf) raf = requestAnimationFrame(frame); }
    function stop() { running = false; if (raf) { cancelAnimationFrame(raf); raf = 0; } }

    readColors(); size();
    var resizeT = 0;
    window.addEventListener('resize', function () { clearTimeout(resizeT); resizeT = setTimeout(size, 120); }, { passive: true });
    window.addEventListener('pointermove', function (e) {
      if (e.pointerType === 'touch') return;
      pointer.x = e.clientX; pointer.y = e.clientY; pointer.active = true;
    }, { passive: true });
    window.addEventListener('pointerleave', function () { pointer.active = false; });
    doc.addEventListener('visibilitychange', function () { doc.hidden ? stop() : start(); });
    new MutationObserver(readColors).observe(root, { attributes: true, attributeFilter: ['data-theme'] });
    matchMedia('(prefers-color-scheme: light)').addEventListener('change', readColors);
    // start after first paint has had its turn
    if ('requestIdleCallback' in window) requestIdleCallback(start, { timeout: 1500 }); else setTimeout(start, 400);
  })();

  /* ---------- exhibit 0 ---------- */
  (function exhibitZero() {
    var style = 'font-family: ui-monospace, Menlo, monospace; font-size: 12px;';
    var accent = style + ' color: #ff5c4a; font-weight: 600;';
    try {
      console.log('%cCASE FILE VP-26-001', accent);
      console.log('%cYou opened the console. That is Exhibit 0 behaviour.', style);
      console.log('%cflag{r3ad_th3_s0urc3_n0t_th3_h3adl1n3}', accent);
      console.log('%cBring it to /exhibit-0/', style);
    } catch (e) { /* no console */ }
  })();
})();
