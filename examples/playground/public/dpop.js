/**
 * Live DPoP, running in the visitor's browser.
 *
 * ─── Why this section is different from the rest ──────────────────────────
 * Everything else on the page happens on the server, and a visitor has to take
 * the server's word for it. This does not: the private key is generated here,
 * marked non-extractable, and never leaves. The server sees a signature and a
 * public key, and could not produce that signature itself.
 *
 * It imports the real `@ninshorg/client` bundle — served from the package it was
 * built from rather than copied — so the code running is the code an
 * application would install.
 */

import { generateDpopKey, createProof, jwkThumbprint } from '/vendor/index.js';

const $ = (id) => document.getElementById(id);
const out = () => $('out-dpop');
const escape = (value) =>
  String(value).replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
  );

/** Held only in this page's memory. Nothing persists it, nothing sends it. */
let key = null;
let thumbprint = null;
let lastProof = null;
/** The token the proof must be bound to, via the `ath` claim. */
let accessToken = null;

function verdict(text, good) {
  return `<div class="verdict ${good ? 'ok' : 'bad'}">${good ? '✓' : '✕'} ${escape(text)}</div>`;
}

function note(text) {
  return `<p class="note">${escape(text)}</p>`;
}

function kv(pairs) {
  return `<dl class="kv">${Object.entries(pairs)
    .map(([k, v]) => `<dt>${escape(k)}</dt><dd class="token">${escape(v)}</dd>`)
    .join('')}</dl>`;
}

function renderStoreOps(ops) {
  if (!ops || ops.length === 0) return '';
  return `<h4 class="sub">Store operations (${ops.length})</h4>
    <div class="scroll"><table>
      <thead><tr><th>op</th><th>key</th><th></th></tr></thead>
      <tbody>${ops
        .map(
          (op) =>
            `<tr><td class="op${op.op.includes('atomic') ? ' atomic' : ''}">${escape(
              op.op,
            )}</td><td>${escape(op.key)}</td><td>${escape(op.outcome ?? '')}</td></tr>`,
        )
        .join('')}</tbody>
    </table></div>`;
}

async function post(url, body) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
  return response.json();
}

function requireKey() {
  if (key === null) {
    out().innerHTML = verdict('Generate a key first', false);
    return false;
  }
  return true;
}

// ─── 1 · Generate ──────────────────────────────────────────────────────────

$('dpop-generate').addEventListener('click', async () => {
  // `extractable: false` is not a parameter you pass — it is the second
  // argument to generateKey, and getting it wrong is the whole ballgame.
  key = await generateDpopKey();
  thumbprint = await jwkThumbprint(key.publicJwk);
  lastProof = null;
  accessToken = null;

  out().innerHTML =
    verdict('A P-256 key pair now exists in this page', true) +
    note(
      'The private half is a non-extractable CryptoKey. The browser will not hand its bytes to ' +
        'any script — including a script an attacker injects. That is what makes a DPoP key ' +
        'different from a token: a token is a string an XSS copies and uses indefinitely.',
    ) +
    kv({
      'public key (x)': key.publicJwk.x,
      'public key (y)': key.publicJwk.y,
      'RFC 7638 thumbprint': thumbprint,
      'private key': 'never leaves this page — try the next button',
    });
});

// ─── 2 · Try to steal it ───────────────────────────────────────────────────

$('dpop-export').addEventListener('click', async () => {
  if (!requireKey()) return;

  // The attack an injected script would attempt.
  try {
    await crypto.subtle.exportKey('jwk', key.privateKey);
    out().innerHTML = verdict(
      'The private key was exported — that would be a serious bug',
      false,
    );
  } catch (error) {
    out().innerHTML =
      verdict('The browser refused to export the private key', true) +
      note(
        'This is the browser enforcing it, not the library asking politely. An attacker with ' +
          'script execution can sign proofs while they are running, but cannot take the key with ' +
          'them — so the compromise ends when the page does, instead of lasting as long as a ' +
          'stolen token would.',
      ) +
      kv({ 'exportKey threw': String(error && error.name ? error.name : error) });
  }
});

// ─── 3 · Bind a session ────────────────────────────────────────────────────

$('dpop-bind').addEventListener('click', async () => {
  if (!requireKey()) return;

  const data = await post('/api/dpop/bind', { thumbprint });
  accessToken = data.accessToken;
  out().innerHTML =
    verdict('The server issued a token bound to your key', true) +
    note(data.note) +
    kv({ 'access token': data.accessToken, 'bound to (cnf.jkt)': data.thumbprint }) +
    renderStoreOps(data.trace?.storeOps);
});

// ─── 4 · Call with a proof ─────────────────────────────────────────────────

$('dpop-call').addEventListener('click', async () => {
  if (!requireKey()) return;

  if (accessToken === null) {
    out().innerHTML = verdict('Bind a session first', false);
    return;
  }

  // A fresh proof per request, bound to this method, this URI, and — through
  // the `ath` claim — this specific access token. Omitting the token here
  // makes the server refuse the proof, which is the binding being thorough
  // rather than a bug.
  lastProof = await createProof(key, {
    method: 'POST',
    url: `${location.origin}/api/dpop/call`,
    accessToken,
  });

  const data = await post('/api/dpop/call', { thumbprint, proof: lastProof });
  out().innerHTML =
    verdict(
      data.accepted ? 'Accepted — the signature checked out' : `Refused: ${data.detail ?? data.code}`,
      Boolean(data.accepted),
    ) +
    note(data.note) +
    kv({ proof: `${lastProof.slice(0, 96)}…` }) +
    renderStoreOps(data.trace?.storeOps);
});

// ─── 5 · Replay it ─────────────────────────────────────────────────────────

$('dpop-replay').addEventListener('click', async () => {
  if (!requireKey()) return;
  if (lastProof === null) {
    out().innerHTML = verdict('Make a call first, so there is a proof to replay', false);
    return;
  }

  const data = await post('/api/dpop/call', { thumbprint, proof: lastProof });
  out().innerHTML =
    verdict(
      data.accepted
        ? 'The replay was accepted — that would be a bug'
        : `Replay refused: ${data.detail ?? data.code}`,
      !data.accepted,
    ) +
    note(
      'A proof carries a single-use jti, remembered for as long as the proof would still be ' +
        'accepted. Capturing one off the wire buys an attacker nothing, because it has already ' +
        'been spent.',
    ) +
    renderStoreOps(data.trace?.storeOps);
});

// ─── 6 · The stolen token ──────────────────────────────────────────────────

$('dpop-steal').addEventListener('click', async () => {
  if (!requireKey()) return;

  // Exactly what a thief who exfiltrated the token has: the token, no key.
  const data = await post('/api/dpop/call', { thumbprint, omitProof: true });
  out().innerHTML =
    verdict(
      data.accepted
        ? 'The token alone was accepted — that would defeat the whole binding'
        : `Refused: ${data.detail ?? data.code}`,
      !data.accepted,
    ) +
    note(data.note) +
    renderStoreOps(data.trace?.storeOps);
});
