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
      .then(function (r) { apply(r.headers, transportResult()); })
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
      if (!r.ok) throw new Error('index.html ' + r.status);
      return r.text();
    }).then(sha256);

    var pubP = fetch('/integrity.json', { cache: 'no-store', credentials: 'omit' }).then(function (r) {
      if (!r.ok) throw new Error('no integrity.json');
      return r.json();
    }).then(function (j) { return j && j.files && j.files['index.html'] ? String(j.files['index.html']) : null; }, function () { return null; });

    Promise.all([htmlP, pubP]).then(function (res) {
      var s = res[0], p = res[1];
      setText(served, s);
      if (!p) {
        setText(published, 'not published (integrity.json is written at build time)');
        grade.setAttribute('data-grade', 'B'); setText(grade, '?');
        setText(status, 'Served digest computed. No published digest to compare against.');
        return;
      }
      setText(published, p);
      var match = s === p.toLowerCase();
      served.setAttribute('data-state', match ? 'ok' : 'bad');
      published.setAttribute('data-state', match ? 'ok' : 'bad');
      grade.setAttribute('data-grade', match ? 'A' : 'F');
      setText(grade, match ? 'MATCH' : 'DIFF');
      setText(status, match ? 'The HTML you received is byte-identical to the build.' : 'Digests differ. The page may have been modified in transit or cached from an older build.');
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
