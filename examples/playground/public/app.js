/**
 * Playground UI.
 *
 * Deliberately plain: no framework, no build step, no dependencies — matching
 * the packages it demonstrates. Everything on screen comes from the server,
 * which ran the real library to produce it.
 */

const $ = (id) => document.getElementById(id);
const escape = (value) =>
  String(value).replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
  );

/** Tokens the page has shown, so the store search can be checked against them. */
const seenTokens = new Set();

function setStatus(text) {
  $('status').textContent = text;
}

async function call(method, url, body) {
  const response = await fetch(url, {
    method,
    headers: { 'content-type': 'application/json' },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  return response.json();
}

// ─── Rendering ─────────────────────────────────────────────────────────────

function renderNote(note) {
  return note ? `<p class="note">${escape(note)}</p>` : '';
}

/**
 * A verdict line.
 *
 * For an attack, "refused" is the success case — so the wording says what
 * happened rather than borrowing pass/fail from the request's point of view.
 */
function renderVerdict(text, good) {
  return `<div class="verdict ${good ? 'ok' : 'bad'}">${good ? '✓' : '✕'} ${escape(text)}</div>`;
}

function renderTokens(tokens) {
  if (!tokens) return '';
  for (const value of Object.values(tokens)) {
    if (typeof value === 'string' && value.length > 20) seenTokens.add(value);
  }
  return `<dl class="kv">${Object.entries(tokens)
    .map(([k, v]) => `<dt>${escape(k)}</dt><dd class="token">${escape(v)}</dd>`)
    .join('')}</dl>`;
}

function renderStoreOps(ops) {
  if (!ops || ops.length === 0) return '';
  const rows = ops
    .map((op) => {
      const atomic = op.op.includes('atomic') ? ' atomic' : '';
      const value = op.value === null || op.value === undefined ? '—' : op.value;
      return `<tr>
        <td class="op${atomic}">${escape(op.op)}</td>
        <td>${escape(op.key)}</td>
        <td>${escape(value.length > 220 ? `${value.slice(0, 220)}…` : value)}</td>
        <td>${escape(op.outcome ?? (op.ttlSeconds !== undefined ? `ttl ${op.ttlSeconds}s` : ''))}</td>
      </tr>`;
    })
    .join('');

  return `<h4 class="sub">Store operations (${ops.length})</h4>
    <div class="scroll"><table>
      <thead><tr><th>op</th><th>key</th><th>value</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;
}

function renderEvents(events) {
  if (!events || events.length === 0) return '';
  const rows = events
    .map(
      (e) => `<tr>
        <td class="op">${escape(e.type)}</td>
        <td>${escape(e.userId ?? '')}</td>
        <td>${escape(e.reason ?? '')}</td>
        <td>${escape(e.signalMatch ?? '')}</td>
      </tr>`,
    )
    .join('');

  return `<h4 class="sub">Audit events (${events.length})</h4>
    <div class="scroll"><table>
      <thead><tr><th>type</th><th>user</th><th>reason</th><th>signals</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;
}

/**
 * A byte map.
 *
 * Offsets and widths are shown because they are the thing a spec diagram gives
 * you and a JSON dump does not — lining the two up is most of what reading a
 * binary format consists of.
 */
function renderDecode(decode) {
  const rows = decode.fields
    .map((f) => {
      const indent = f.depth ? ' style="padding-left:2rem"' : '';
      const span = f.length > 0 ? `${f.offset} … ${f.offset + f.length - 1}` : '';
      return `<tr>
        <td class="dim">${escape(span)}</td>
        <td class="dim">${f.length > 0 ? escape(f.length) : ''}</td>
        <td class="op"${indent}>${escape(f.name)}</td>
        <td class="hash">${escape(f.hex)}</td>
        <td>${escape(f.value)}</td>
      </tr>
      <tr><td colspan="5" class="fieldnote">${escape(f.note)}</td></tr>`;
    })
    .join('');

  return `<h4 class="sub">${escape(decode.title)} — ${decode.totalBytes} bytes</h4>
    <p class="explain">${escape(decode.summary)}</p>
    <div class="scroll"><table>
      <thead><tr><th>bytes</th><th>len</th><th>field</th><th>hex</th><th>value</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;
}

/** Everything a response might carry, rendered in a consistent order. */
function render(data) {
  let html = '';

  if (data.rejected === true) html += renderVerdict('The attack was refused', true);
  if (data.rejected === false) html += renderVerdict('The attack SUCCEEDED — that is a bug', false);
  if (data.ok === false && data.rejected === undefined && data.message) {
    html += renderVerdict(data.message, false);
  }
  if (data.liveTokenStillWorks === true) {
    html += renderVerdict('…but the legitimate token still works — that is a bug', false);
  }
  if (data.liveTokenStillWorks === false) {
    html += renderVerdict('The whole family died with it, including the legitimate token', true);
  }
  if (typeof data.survivors === 'number') {
    html += renderVerdict(
      `${data.survivors} of 2 racing links remained usable (1 is correct)`,
      data.survivors === 1,
    );
  }

  html += renderNote(data.note);
  html += renderTokens(data.tokens);

  const scalars = {};
  for (const [k, v] of Object.entries(data)) {
    if (['note', 'trace', 'tokens', 'ok', 'rejected', 'keys', 'events', 'decodes', 'summary', 'clientDataJSON'].includes(k)) continue;
    if (v === null || typeof v === 'object') continue;
    scalars[k] = v;
  }
  if (Object.keys(scalars).length > 0) {
    html += `<dl class="kv">${Object.entries(scalars)
      .map(([k, v]) => `<dt>${escape(k)}</dt><dd>${escape(v)}</dd>`)
      .join('')}</dl>`;
  }

  if (data.context) {
    html += `<h4 class="sub">Verified identity</h4><dl class="kv">${Object.entries(data.context)
      .map(([k, v]) => `<dt>${escape(k)}</dt><dd>${escape(JSON.stringify(v))}</dd>`)
      .join('')}</dl>`;
  }

  if (data.outcomes) {
    html += `<dl class="kv">${data.outcomes
      .map((o) => `<dt>result</dt><dd>${escape(o)}</dd>`)
      .join('')}</dl>`;
  }

  if (data.keys) {
    html += `<h4 class="sub">Live keys (${data.keys.length})</h4>
      <div class="scroll"><table>
        <thead><tr><th>key</th><th>value</th></tr></thead>
        <tbody>${data.keys
          .map(
            (k) =>
              `<tr><td class="hash">${escape(k.key)}</td><td>${escape(
                k.value.length > 260 ? `${k.value.slice(0, 260)}…` : k.value,
              )}</td></tr>`,
          )
          .join('')}</tbody>
      </table></div>`;
  }

  if (data.clientDataJSON) {
    html += `<h4 class="sub">clientDataJSON</h4><div class="scroll"><table><tbody><tr><td class="token">${escape(
      data.clientDataJSON,
    )}</td></tr></tbody></table></div>`;
  }

  if (data.decodes) {
    for (const decode of data.decodes) html += renderDecode(decode);
  }

  if (data.events) html += renderEvents(data.events);
  if (data.trace) {
    html += renderStoreOps(data.trace.storeOps);
    html += renderEvents(data.trace.events);
  }

  return html;
}

// ─── Wiring ────────────────────────────────────────────────────────────────

for (const button of document.querySelectorAll('[data-post], [data-get]')) {
  button.addEventListener('click', async () => {
    const url = button.dataset.post ?? button.dataset.get;
    const target = $(button.dataset.target);

    button.disabled = true;
    setStatus('running…');
    try {
      const data = await call(button.dataset.post ? 'POST' : 'GET', url);
      target.innerHTML = render(data);
      setStatus('');
    } catch (error) {
      target.innerHTML = renderVerdict(`Request failed: ${error.message}`, false);
      setStatus('');
    } finally {
      button.disabled = false;
    }
  });
}

$('search').addEventListener('click', async () => {
  const needle = $('needle').value.trim();
  const result = $('search-result');

  if (needle.length === 0) {
    result.innerHTML = renderVerdict('Paste a token first', false);
    return;
  }

  const { keys } = await call('GET', '/api/store');
  const hit = keys.some((k) => k.key.includes(needle) || k.value.includes(needle));

  result.innerHTML = hit
    ? renderVerdict('Found it in the store — that would be a bug', false)
    : renderVerdict(
        `Not present anywhere in ${keys.length} live keys. Only its SHA-256 is stored.`,
        true,
      );
});

$('reset').addEventListener('click', async () => {
  await call('POST', '/api/reset');
  for (const out of document.querySelectorAll('.out')) out.innerHTML = '';
  $('search-result').innerHTML = '';
  $('needle').value = '';
  seenTokens.clear();
  setStatus('cleared');
  setTimeout(() => setStatus(''), 1500);
});
