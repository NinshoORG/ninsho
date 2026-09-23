/**
 * Walkthrough player for walkthroughs.html.
 *
 * Renders the recordings in assets/walkthroughs.js, which are produced by
 * `npm run walkthroughs` from the real library and re-checked by CI. This file
 * only displays them. Every number on the page — step counts, operations
 * checked, the grace-window default — is read from the recording rather than
 * written into the page, so the copy cannot drift from what was recorded.
 *
 * No dependencies, no build step, same as the rest of the site. Loaded with a
 * plain <script> rather than fetch() so the page also works opened from disk.
 */
(function () {
  'use strict';

  var data = window.NINSHO_WALKTHROUGHS;
  var player = document.getElementById('wt-player');
  var list = document.getElementById('wt-list');
  if (!data || !player || !list) return;

  var REPO = 'https://github.com/NinshoORG/ninsho/blob/main/';
  var reducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // ── Small helpers ──────────────────────────────────────────────────────────

  function esc(text) {
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /** Notes use `backticks` for code, and nothing else. */
  function prose(text) {
    return String(text)
      .split('`')
      .map(function (part, i) {
        return i % 2 ? '<code>' + esc(part) + '</code>' : esc(part);
      })
      .join('');
  }

  function el(tag, cls, html) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (html !== undefined) node.innerHTML = html;
    return node;
  }

  function fmt(n) {
    return Number(n).toLocaleString('en-US');
  }

  /** JSON with token colouring. Safe: every piece is escaped before wrapping. */
  function json(value) {
    var text = JSON.stringify(value, null, 2);
    var out = '';
    var last = 0;
    var re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
    var m;
    while ((m = re.exec(text))) {
      out += esc(text.slice(last, m.index));
      if (m[1]) {
        out += m[2]
          ? '<span class="j-key">' + esc(m[1]) + '</span>' + esc(m[2])
          : '<span class="j-str">' + esc(m[1]) + '</span>';
      } else {
        out += '<span class="j-lit">' + esc(m[0]) + '</span>';
      }
      last = re.lastIndex;
    }
    return out + esc(text.slice(last));
  }

  function statusClass(code) {
    if (code >= 200 && code < 300) return 's-ok';
    if (code >= 500) return 's-down';
    return 's-no';
  }

  /** One line per citation: `.cite` is a flex row, so a <br> inside it would not break. */
  function citeLine(cites) {
    if (!cites || !cites.length) return null;
    var box = el('div', 'wt-cites');
    cites.forEach(function (c) {
      var file = c.path
        ? '<a href="' + esc(REPO + c.path) + '" rel="noopener">' + esc(c.file) + '</a>'
        : esc(c.file);
      box.appendChild(el('p', 'cite', 'Evidence <span>· ' + file + ' › ' + esc(c.test) + '</span>'));
    });
    return box;
  }

  // ── Headline figures, all from the recording ──────────────────────────────

  var steps = 0;
  var requests = 0;
  var cites = 0;
  data.scenarios.forEach(function (sc) {
    cites += (sc.cite || []).length;
    sc.steps.forEach(function (st) {
      steps += 1;
      requests += st.exchanges.length;
      cites += (st.cite || []).length;
    });
  });

  var facts = document.getElementById('wt-facts');
  if (facts) {
    [
      [data.scenarios.length, 'walkthroughs'],
      [steps, 'steps, each asserted'],
      [requests, 'real HTTP requests'],
      [data.storeOpsChecked, 'store operations logged'],
      [cites, 'test citations, all verified'],
    ].forEach(function (f) {
      var box = el('div', 'wt-fact');
      box.appendChild(el('dt', null, fmt(f[0])));
      box.appendChild(el('dd', null, esc(f[1])));
      facts.appendChild(box);
    });
  }

  var caveat = document.getElementById('wt-caveat');
  if (caveat) {
    var grace = data.defaults && data.defaults.refreshGraceSeconds;
    var reuse = data.scenarios.filter(function (s) { return s.id === 'refresh-reuse'; })[0];
    var graceCite = reuse && reuse.cite && reuse.cite[0];
    caveat.innerHTML =
      '<strong>No raw token reached the store in these recordings</strong> — ' +
      fmt(data.storeOpsChecked) + ' operations checked against all ' + fmt(data.rawTokensChecked) +
      ' tokens issued, before anything was shortened for display. One exception is by design and ' +
      'deliberately not recorded here: with the default ' + esc(grace) + '-second grace window, a ' +
      'rotated refresh token\u2019s replacements are held for ' + esc(grace) + ' seconds so a second tab ' +
      'refreshing at the same moment receives the same pair.' +
      (graceCite && graceCite.path
        ? ' <a href="' + esc(REPO + graceCite.path) + '" rel="noopener">' + esc(graceCite.file) + '</a>' +
          ' › <em>' + esc(graceCite.test) + '</em>.'
        : '') +
      ' Recorded against <span class="mono">@ninshorg/server ' + esc(data.library) + '</span>.';
  }

  // ── The index ──────────────────────────────────────────────────────────────

  data.scenarios.forEach(function (sc, i) {
    var li = el('li');
    var a = el('a', 'wt-index-link');
    a.href = '#' + sc.id;
    a.setAttribute('data-id', sc.id);
    a.innerHTML =
      '<span class="wt-index-n">' + String(i + 1).padStart(2, '0') + '</span>' +
      '<span class="wt-index-t">' + esc(sc.title) + '</span>' +
      '<span class="wt-index-c">' + sc.steps.length + ' steps</span>';
    li.appendChild(a);
    list.appendChild(li);
  });

  // ── Rendering one step ─────────────────────────────────────────────────────

  function renderExchange(x, compact) {
    var box = el('div', 'wt-x' + (compact ? ' wt-x-compact' : ''));
    var req = el('div', 'wt-req');
    var line = '<span class="wt-method">' + esc(x.method) + '</span> <span class="wt-path">' + esc(x.path) + '</span>';
    req.appendChild(el('div', 'wt-line', line));

    if (!compact) {
      var headers = Object.keys(x.headers || {});
      if (headers.length) {
        req.appendChild(
          el(
            'div',
            'wt-headers',
            headers
              .map(function (h) {
                return '<span class="wt-h">' + esc(h) + ':</span> ' + esc(x.headers[h]);
              })
              .join('<br />')
          )
        );
      }
      if (x.body !== undefined) req.appendChild(el('pre', 'wt-json', json(x.body)));
    }
    box.appendChild(req);

    var res = el('div', 'wt-res');
    res.appendChild(el('div', 'wt-line', '<span class="wt-status ' + statusClass(x.status) + '">' + x.status + '</span>'));
    if (!compact) {
      var rh = Object.keys(x.responseHeaders || {});
      if (rh.length) {
        res.appendChild(
          el(
            'div',
            'wt-headers',
            rh
              .map(function (h) {
                return '<span class="wt-h">' + esc(h) + ':</span> ' + esc(x.responseHeaders[h]);
              })
              .join('<br />')
          )
        );
      }
      if (x.response !== undefined) res.appendChild(el('pre', 'wt-json', json(x.response)));
    }
    box.appendChild(res);
    return box;
  }

  function renderStep(st, index, total) {
    var li = el('li', 'wt-step');
    li.setAttribute('data-role', st.role);
    li.id = 'wt-step-' + (index + 1);

    var head = el('div', 'wt-step-head');
    head.appendChild(el('span', 'wt-step-n', String(index + 1) + '<span>/' + total + '</span>'));
    head.appendChild(el('span', 'wt-actor', esc(st.actor)));
    head.appendChild(el('h3', 'wt-step-title', esc(st.title)));
    if (st.expected) {
      var got = st.exchanges.map(function (x) { return x.status; });
      var unique = got.filter(function (v, i) { return got.indexOf(v) === i; });
      head.appendChild(
        el(
          'span',
          'wt-verdict',
          '<span class="wt-verdict-mark" aria-hidden="true">\u2713</span> expected ' + esc(st.expected) +
            '<span class="wt-verdict-got"> · got ' + esc(unique.join(', ')) + '</span>'
        )
      );
    }
    li.appendChild(head);

    if (st.exchanges.length === 1) {
      li.appendChild(renderExchange(st.exchanges[0], false));
    } else if (st.exchanges.length > 1) {
      var many = el('div', 'wt-many');
      many.appendChild(el('p', 'wt-many-label', st.exchanges.length + ' requests'));
      var grid = el('div', 'wt-many-grid');
      st.exchanges.forEach(function (x) {
        grid.appendChild(renderExchange(x, true));
      });
      many.appendChild(grid);
      var sample = el('details', 'wt-more');
      sample.appendChild(el('summary', null, 'First request in full'));
      sample.appendChild(renderExchange(st.exchanges[0], false));
      many.appendChild(sample);
      li.appendChild(many);
    } else {
      li.appendChild(el('div', 'wt-system', '<span aria-hidden="true">\u26A1</span> No request — a change to the world.'));
    }

    li.appendChild(el('p', 'wt-note', prose(st.note)));

    if (st.storeOps.length) {
      var ops = el('details', 'wt-more');
      ops.appendChild(el('summary', null, 'Store operations <span class="wt-count">' + st.storeOps.length + '</span>'));
      var table = el('table', 'wt-ops');
      table.innerHTML =
        '<thead><tr><th>op</th><th>key</th><th>outcome</th><th>ttl</th></tr></thead>' +
        '<tbody>' +
        st.storeOps
          .map(function (o) {
            return (
              '<tr><td class="wt-op">' + esc(o.op) + '</td>' +
              '<td class="wt-key">' + esc(o.key) + '</td>' +
              '<td>' + esc(o.outcome || '') + '</td>' +
              '<td>' + (o.ttlSeconds !== undefined ? esc(o.ttlSeconds) + 's' : '') + '</td></tr>'
            );
          })
          .join('') +
        '</tbody>';
      var scroll = el('div', 'wt-scroll');
      scroll.appendChild(table);
      ops.appendChild(scroll);
      li.appendChild(ops);
    }

    if (st.events.length) {
      var ev = el('div', 'wt-events');
      st.events.forEach(function (e) {
        var parts = [];
        if (e.reason) parts.push(esc(e.reason));
        if (e.signalMatch) parts.push('signalMatch: <b>' + esc(e.signalMatch) + '</b>');
        ev.appendChild(
          el('span', 'wt-event', '<span class="wt-event-t">' + esc(e.type) + '</span>' + (parts.length ? ' ' + parts.join(' · ') : ''))
        );
      });
      li.appendChild(ev);
    }

    var c = citeLine(st.cite);
    if (c) li.appendChild(c);
    return li;
  }

  // ── The player ─────────────────────────────────────────────────────────────

  var current = null; // scenario
  var shown = 1; // steps revealed
  var timer = null;

  var head = el('header', 'wt-head');
  var controls = el('div', 'wt-controls');
  var btnPrev = el('button', 'btn btn-ghost wt-btn', '\u2190 Back');
  var btnNext = el('button', 'btn btn-primary wt-btn', 'Next step \u2192');
  var btnPlay = el('button', 'btn btn-ghost wt-btn', 'Play');
  var btnAll = el('button', 'btn btn-ghost wt-btn', 'Show all');
  var counter = el('span', 'wt-counter');
  counter.setAttribute('aria-live', 'polite');
  [btnPrev, btnNext, btnPlay, btnAll].forEach(function (b) {
    b.type = 'button';
  });
  controls.appendChild(btnPrev);
  controls.appendChild(btnNext);
  controls.appendChild(counter);
  controls.appendChild(btnPlay);
  controls.appendChild(btnAll);

  var stepList = el('ol', 'wt-steps');
  player.appendChild(head);
  player.appendChild(controls);
  player.appendChild(stepList);

  function stopPlay() {
    if (timer) clearTimeout(timer);
    timer = null;
    btnPlay.textContent = 'Play';
    btnPlay.setAttribute('aria-pressed', 'false');
  }

  function sync(scrollTo) {
    var items = stepList.children;
    for (var i = 0; i < items.length; i += 1) {
      items[i].hidden = i >= shown;
      items[i].classList.toggle('is-current', i === shown - 1);
    }
    var total = current.steps.length;
    counter.textContent = 'Step ' + shown + ' of ' + total;
    btnPrev.disabled = shown <= 1;
    btnNext.disabled = shown >= total;
    btnAll.disabled = shown >= total;
    var hash = '#' + current.id + (shown > 1 ? '/' + shown : '');
    if (location.hash !== hash) history.replaceState(null, '', hash);
    if (scrollTo && items[shown - 1]) {
      items[shown - 1].scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'nearest' });
    }
  }

  function select(id, step, scrollTo) {
    var sc = data.scenarios.filter(function (s) { return s.id === id; })[0] || data.scenarios[0];
    stopPlay();
    current = sc;
    var n = data.scenarios.indexOf(sc);

    head.innerHTML = '';
    head.appendChild(el('p', 'eyebrow', 'Walkthrough ' + (n + 1) + ' of ' + data.scenarios.length));
    head.appendChild(el('h2', null, esc(sc.title)));
    head.appendChild(el('p', 'lede', prose(sc.lede)));
    head.appendChild(el('pre', 'wt-config', '<code>' + esc(sc.config) + '</code>'));
    var sc_cite = citeLine(sc.cite);
    if (sc_cite) head.appendChild(sc_cite);

    stepList.innerHTML = '';
    sc.steps.forEach(function (st, i) {
      stepList.appendChild(renderStep(st, i, sc.steps.length));
    });

    Array.prototype.forEach.call(list.querySelectorAll('.wt-index-link'), function (a) {
      if (a.getAttribute('data-id') === sc.id) a.setAttribute('aria-current', 'true');
      else a.removeAttribute('aria-current');
    });

    shown = Math.min(Math.max(step || 1, 1), sc.steps.length);
    sync(false);
    if (scrollTo) player.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'start' });
  }

  /** Long enough to read the note: ~0.28s a word, between 4 and 14 seconds. */
  function readingTime(st) {
    var words = (st.note + ' ' + st.title).split(/\s+/).length;
    return Math.min(14000, Math.max(4000, words * 280));
  }

  function next() {
    if (shown < current.steps.length) {
      shown += 1;
      sync(true);
    }
  }

  btnNext.addEventListener('click', function () {
    stopPlay();
    next();
  });
  btnPrev.addEventListener('click', function () {
    stopPlay();
    if (shown > 1) {
      shown -= 1;
      sync(true);
    }
  });
  btnAll.addEventListener('click', function () {
    stopPlay();
    shown = current.steps.length;
    sync(false);
  });
  btnPlay.addEventListener('click', function () {
    if (timer) return stopPlay();
    btnPlay.textContent = 'Pause';
    btnPlay.setAttribute('aria-pressed', 'true');
    (function tick() {
      timer = setTimeout(function () {
        if (shown >= current.steps.length) return stopPlay();
        next();
        tick();
      }, readingTime(current.steps[shown - 1]));
    })();
  });

  list.addEventListener('click', function (event) {
    var a = event.target.closest && event.target.closest('.wt-index-link');
    if (!a) return;
    event.preventDefault();
    select(a.getAttribute('data-id'), 1, true);
  });

  document.addEventListener('keydown', function (event) {
    var t = event.target;
    if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
    if (event.altKey || event.ctrlKey || event.metaKey) return;
    if (event.key === 'ArrowRight') {
      stopPlay();
      next();
    } else if (event.key === 'ArrowLeft' && shown > 1) {
      stopPlay();
      shown -= 1;
      sync(true);
    }
  });

  function fromHash() {
    var m = /^#([a-z0-9-]+)(?:\/(\d+))?$/.exec(location.hash);
    select(m ? m[1] : data.scenarios[0].id, m && m[2] ? Number(m[2]) : 1, false);
  }
  window.addEventListener('hashchange', fromHash);
  fromHash();

  // ── The app source, with line numbers ──────────────────────────────────────

  var source = document.getElementById('wt-source');
  var meta = document.getElementById('wt-source-meta');
  if (source && data.appSource) {
    var KEYWORDS = /^(import|export|from|const|let|var|function|return|if|else|for|of|in|new|async|await|try|catch|throw|type|interface|readonly|typeof|as|extends|true|false|null|undefined)$/;
    var src = data.appSource;
    var html = '';
    var i = 0;
    /** A token that may span lines is closed and reopened at each newline, so every line stays balanced. */
    function wrap(cls, text) {
      return '<span class="' + cls + '">' + esc(text).replace(/\n/g, '</span>\n<span class="' + cls + '">') + '</span>';
    }
    while (i < src.length) {
      var ch = src[i];
      var rest = src.slice(i);
      var m;
      if (rest.slice(0, 2) === '//') {
        var end = src.indexOf('\n', i);
        end = end === -1 ? src.length : end;
        html += wrap('t-c', src.slice(i, end));
        i = end;
      } else if (rest.slice(0, 2) === '/*') {
        var close = src.indexOf('*/', i + 2);
        close = close === -1 ? src.length : close + 2;
        html += wrap('t-c', src.slice(i, close));
        i = close;
      } else if (ch === "'" || ch === '"' || ch === '`') {
        var j = i + 1;
        while (j < src.length && src[j] !== ch) j += src[j] === '\\' ? 2 : 1;
        html += wrap('t-s', src.slice(i, j + 1));
        i = j + 1;
      } else if ((m = /^[A-Za-z_$][\w$]*/.exec(rest))) {
        html += KEYWORDS.test(m[0]) ? wrap('t-k', m[0]) : /^[A-Z]/.test(m[0]) ? wrap('t-t', m[0]) : esc(m[0]);
        i += m[0].length;
      } else {
        html += esc(ch);
        i += 1;
      }
    }
    source.innerHTML = html
      .split('\n')
      .map(function (line) {
        return '<span class="ln">' + (line || ' ') + '</span>';
      })
      .join('\n');
    if (meta) meta.textContent = src.split('\n').length + ' lines — the whole of it';
  }
})();
