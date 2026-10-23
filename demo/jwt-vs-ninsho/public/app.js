import {
  NinshoClient,
  IndexedDbKeyStore,
  createProof,
  generateDpopKey,
} from '/vendor/ninsho-client/index.js';

// ─── Setup ──────────────────────────────────────────────────────────────────

const JWT_STORAGE_KEY = 'jwt_token';
const origin = window.location.origin;
const ME = `${origin}/api/ninsho/me`;

// The real Ninsho browser client: keeps the access token in memory and signs
// every request with a non-exportable key stored in IndexedDB.
const ninsho = new NinshoClient({
  baseUrl: origin,
  keyStore: new IndexedDbKeyStore('jvn-ninsho-keys'),
  refreshPath: '/api/ninsho/refresh',
});

let running = false; // a scenario is in progress

const state = {
  jwt: { user: null, expiresAt: null },
  ninsho: { user: null, sessions: null },
};

const $ = (selector, root = document) => root.querySelector(selector);
const sides = { jwt: $('#jwtSide'), ninsho: $('#ninshoSide') };
const field = (side, name) => $(`[data-field="${name}"]`, sides[side]);

async function readJson(res) {
  try {
    return await res.json();
  } catch {
    return {};
  }
}

function setMsg(side, text, tone = '') {
  const el = field(side, 'msg');
  el.textContent = text;
  el.className = `msg ${tone}`;
}

function code(text) {
  const el = document.createElement('code');
  el.textContent = text;
  return el;
}

/** Disables a button while its action runs, so nothing is sent twice. */
async function busy(button, fn) {
  button.disabled = true;
  try {
    await fn();
  } finally {
    button.disabled = false;
    render();
  }
}

// ─── JWT side ───────────────────────────────────────────────────────────────

function jwtToken() {
  try {
    return localStorage.getItem(JWT_STORAGE_KEY);
  } catch {
    return null;
  }
}

function forgetJwt() {
  try {
    localStorage.removeItem(JWT_STORAGE_KEY);
  } catch {
    // Storage unavailable: nothing was saved.
  }
  state.jwt = { user: null, expiresAt: null };
}

async function jwtSignIn(email, password) {
  const res = await fetch('/api/jwt/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const body = await readJson(res);
  if (!res.ok) return setMsg('jwt', body.error?.message ?? 'Sign-in failed.', 'bad');
  try {
    localStorage.setItem(JWT_STORAGE_KEY, body.token);
  } catch {
    // Without storage the token only lives until reload; the demo still works.
  }
  state.jwt = { user: body.user, expiresAt: body.expiresAt };
  setMsg('jwt', 'Signed in. The token is now saved in localStorage.', 'good');
}

async function jwtCheck() {
  const token = jwtToken();
  const res = await fetch('/api/jwt/me', { headers: { authorization: `Bearer ${token}` } });
  const body = await readJson(res);
  if (res.ok) setMsg('jwt', `${res.status} OK — checked against ${body.checkedAgainst}.`, 'good');
  else setMsg('jwt', `${res.status} — ${body.error?.message ?? 'refused'}`, 'bad');
}

async function jwtSignOut() {
  const res = await fetch('/api/jwt/logout', { method: 'POST' });
  forgetJwt();
  setMsg('jwt', 'Signed out in this browser. The server had nothing to cancel.');
  return res;
}

// ─── Ninsho side ────────────────────────────────────────────────────────────

async function ninshoSignIn(email, password) {
  const res = await ninsho.signIn('/api/ninsho/login', { email, password });
  const body = await readJson(res.clone());
  if (!res.ok) return setMsg('ninsho', body.error?.message ?? 'Sign-in failed.', 'bad');
  state.ninsho.user = body.user;
  setMsg('ninsho', 'Signed in. The session is bound to this browser’s key.', 'good');
  await loadSessions();
}

async function ninshoCheck() {
  const res = await ninsho.fetch('/api/ninsho/me');
  const body = await readJson(res);
  if (res.ok) setMsg('ninsho', `${res.status} OK — checked against ${body.checkedAgainst}.`, 'good');
  else setMsg('ninsho', `${res.status} — ${body.error?.message ?? 'refused'}`, 'bad');
}

async function ninshoSignOut() {
  const res = await ninsho.signOut('/api/ninsho/logout');
  state.ninsho = { user: null, sessions: null };
  setMsg('ninsho', res?.ok ? 'Signed out. The server ended the session.' : 'Signed out in this browser.');
  return res;
}

async function loadSessions() {
  try {
    const res = await ninsho.fetch('/api/ninsho/sessions');
    state.ninsho.sessions = res.ok ? (await res.json()).sessions : null;
  } catch {
    state.ninsho.sessions = null;
  }
  render();
}

// ─── The attacker ───────────────────────────────────────────────────────────
// The server replays the stolen strings from a separate connection: no cookies,
// no device key, nothing this browser has except what is passed here.

async function attacker(side, token, proof) {
  const res = await fetch('/api/attacker/replay', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ side, token, proof, origin }),
  });
  return readJson(res);
}

// ─── Rendering ──────────────────────────────────────────────────────────────

function render() {
  for (const side of ['jwt', 'ninsho']) {
    const user = state[side].user;
    $('.signin', sides[side]).hidden = Boolean(user);
    $('.signed-in', sides[side]).hidden = !user;
    if (user) {
      field(side, 'name').textContent = user.name;
      field(side, 'email').textContent = user.email;
    }
  }

  const token = jwtToken();
  const stored = field('jwt', 'stored');
  const readable = field('jwt', 'readable');
  if (token) {
    stored.replaceChildren(code(`${token.slice(0, 22)}…`), ` (${token.length} characters)`);
    readable.textContent = 'Yes. Any script can run localStorage.getItem("jwt_token").';
    readable.className = 'bad';
  } else {
    stored.textContent = 'nothing';
    readable.textContent = '—';
    readable.className = '';
  }
  renderExpiry();

  const n = state.ninsho;
  field('ninsho', 'stored').textContent = 'nothing, by design';
  setHold('access', n.user ? 'In page memory only. Gone when the tab closes.' : '—', n.user);
  setHold('refresh', n.user ? 'In an HttpOnly cookie. Scripts cannot read it.' : '—', n.user);
  setHold('key', n.user ? 'In IndexedDB, marked non-exportable. It can sign; it cannot be copied.' : '—', n.user);
  const sessions = n.sessions;
  field('ninsho', 'sessions').textContent = !sessions
    ? '—'
    : `${sessions.length} (${sessions.length === 1 ? 'this browser' : `this browser + ${sessions.length - 1} other`})`;

  const ready = Boolean(state.jwt.user && state.ninsho.user);
  document.querySelectorAll('[data-run]').forEach((b) => (b.disabled = !ready || running));
  $('#scenarioHint').textContent = ready
    ? 'Each scenario runs on both sides at once. Read down each column.'
    : 'Sign in on both sides to run these.';
}

function setHold(name, text, good) {
  const el = field('ninsho', name);
  el.textContent = text;
  el.className = good ? 'good' : '';
}

function renderExpiry() {
  const el = field('jwt', 'expires');
  if (!state.jwt.expiresAt) return void (el.textContent = '—');
  const left = Math.max(0, Math.round((Date.parse(state.jwt.expiresAt) - Date.now()) / 1000));
  el.textContent = `${Math.floor(left / 60)}m ${String(left % 60).padStart(2, '0')}s — and nothing can end it sooner`;
}
setInterval(renderExpiry, 1000);

// ─── Scenarios ──────────────────────────────────────────────────────────────

/** A step-by-step log for each side of one scenario card. */
function scenarioLog(name) {
  const card = $(`[data-scenario="${name}"]`);
  $('.results', card).hidden = false;
  const logs = {};
  for (const side of ['jwt', 'ninsho']) {
    const box = $(`[data-result="${side}"]`, card);
    const list = $('ol', box);
    const verdict = $('.verdict', box);
    list.replaceChildren();
    verdict.textContent = 'Running…';
    verdict.className = 'verdict';
    logs[side] = {
      step(text, status) {
        const li = document.createElement('li');
        li.textContent = text;
        if (status !== undefined) {
          const s = document.createElement('span');
          s.className = 'status';
          s.textContent = ` → HTTP ${status}`;
          li.append(s);
        }
        list.append(li);
      },
      verdict(text, good) {
        verdict.textContent = text;
        verdict.className = `verdict ${good ? 'good' : 'bad'}`;
      },
    };
  }
  return logs;
}

const scenarios = {
  // 1. Signed out, but a copy was taken first.
  async copied() {
    const log = scenarioLog('copied');
    await Promise.all([
      (async () => {
        const token = jwtToken();
        log.jwt.step(`Someone copies your token: ${token.slice(0, 14)}…`);
        let r = await attacker('jwt', token);
        log.jwt.step('They try it from their computer', r.status);
        await jwtSignOut();
        log.jwt.step('You sign out. The server has nothing to cancel; only your browser forgets its copy.');
        r = await attacker('jwt', token);
        log.jwt.step('They use their copy again', r.status);
        if (r.status === 200) log.jwt.verdict('Still works after you signed out — for up to 15 minutes.', false);
        else log.jwt.verdict(`Refused (${r.status}).`, true);
      })(),
      (async () => {
        const token = ninsho.accessToken;
        const key = await ninsho.getKey();
        // Worst case: not just the token, but complete requests signed by your
        // own device key, made before you signed out.
        const first = await createProof(key, { method: 'GET', url: ME, accessToken: token });
        const second = await createProof(key, { method: 'GET', url: ME, accessToken: token });
        log.ninsho.step('Worst case: they copy your token AND two requests signed by your device key');
        let r = await attacker('ninsho', token, first);
        log.ninsho.step('They try one from their computer', r.status);
        const out = await ninshoSignOut();
        log.ninsho.step('You sign out. The server ends the session.', out?.status);
        r = await attacker('ninsho', token, second);
        log.ninsho.step('They use the other signed copy', r.status);
        if (r.status === 401) log.ninsho.verdict('Refused. The session is gone, so no copy works any more.', true);
        else log.ninsho.verdict(`Unexpected: ${r.status}.`, false);
      })(),
    ]);
    setMsg('jwt', 'Scenario 1 signed you out on this side.');
    setMsg('ninsho', 'Scenario 1 signed you out on this side.');
  },

  // 2. The token leaks while you are signed in.
  async stolen() {
    const log = scenarioLog('stolen');
    await Promise.all([
      (async () => {
        const token = jwtToken();
        log.jwt.step('The token leaks. Any script on the page can read it from localStorage.');
        const r = await attacker('jwt', token);
        log.jwt.step('The attacker uses it from their own computer', r.status);
        if (r.status === 200) log.jwt.verdict('Works. They are signed in as you until it expires.', false);
        else log.jwt.verdict(`Refused (${r.status}).`, true);
      })(),
      (async () => {
        const token = ninsho.accessToken;
        log.ninsho.step('The access token leaks (from a log, or a script watching requests).');
        const alone = await attacker('ninsho', token);
        log.ninsho.step('The attacker sends the token alone', alone.status);
        const thiefKey = await generateDpopKey();
        const forged = await createProof(thiefKey, { method: 'GET', url: ME, accessToken: token });
        const signed = await attacker('ninsho', token, forged);
        log.ninsho.step('They sign the request with their own key', signed.status);
        try {
          await crypto.subtle.exportKey('jwk', (await ninsho.getKey()).privateKey);
          log.ninsho.step('They try to copy your device key: it was exported (this should not happen).');
        } catch {
          log.ninsho.step('They try to copy your device key: the browser refuses. It is not exportable.');
        }
        const mine = await ninsho.fetch('/api/ninsho/me');
        log.ninsho.step('Meanwhile your own browser keeps working', mine.status);
        const blocked = alone.status === 401 && signed.status === 401;
        if (blocked) log.ninsho.verdict('Blocked. The token is useless without this browser’s key.', true);
        else log.ninsho.verdict('Unexpected: the stolen token was accepted.', false);
      })(),
    ]);
  },

  // 3. Sign out of every device.
  async everywhere() {
    const log = scenarioLog('everywhere');
    await Promise.all([
      (async () => {
        log.jwt.step('How many devices are signed in? The server cannot say — it keeps no list.');
        const res = await fetch('/api/jwt/logout-all', { method: 'POST' });
        const body = await readJson(res);
        log.jwt.step(`“Sign out everywhere”: ${body.possible ? 'done' : 'not possible'}`, res.status);
        const r = await attacker('jwt', jwtToken());
        log.jwt.step('A token like the one on your lost phone is tried', r.status);
        if (r.status === 200) log.jwt.verdict('Your phone stays signed in until its token expires.', false);
        else log.jwt.verdict(`Refused (${r.status}).`, true);
      })(),
      (async () => {
        const list = await ninsho.fetch('/api/ninsho/sessions');
        const count = list.ok ? (await list.json()).sessions.length : '?';
        log.ninsho.step(`The server lists ${count} active session${count === 1 ? '' : 's'} for your account`, list.status);
        const token = ninsho.accessToken;
        const copy = await createProof(await ninsho.getKey(), { method: 'GET', url: ME, accessToken: token });
        const res = await ninsho.fetch('/api/ninsho/logout-all', { method: 'POST' });
        const body = await readJson(res);
        log.ninsho.step(`“Sign out everywhere”: ${body.sessionsEnded ?? 0} session(s) ended`, res.status);
        const r = await attacker('ninsho', token, copy);
        log.ninsho.step('A signed request made before that is tried', r.status);
        await ninsho.signOut('/api/ninsho/logout').catch(() => null);
        state.ninsho = { user: null, sessions: null };
        if (res.ok && r.status === 401) log.ninsho.verdict('Every device is signed out, right now.', true);
        else log.ninsho.verdict('Unexpected result.', false);
      })(),
    ]);
    setMsg('ninsho', 'Scenario 3 signed out every Ninsho session for this account.');
  },
};

document.querySelectorAll('[data-run]').forEach((button) => {
  button.addEventListener('click', async () => {
    if (running) return;
    running = true;
    render();
    try {
      await scenarios[button.dataset.run]();
    } catch (err) {
      console.error(err);
      alert(`The scenario stopped: ${err.message}`);
    } finally {
      running = false;
      render();
    }
  });
});

// ─── Forms and buttons ──────────────────────────────────────────────────────

$('#signupForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  const msg = $('#signupMsg');
  await busy($('button', form), async () => {
    const res = await fetch('/api/signup', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(data),
    });
    const body = await readJson(res);
    if (!res.ok) {
      msg.textContent = body.error?.message ?? 'Could not create the account.';
      msg.className = 'msg bad';
      return;
    }
    msg.textContent = `Account created for ${body.user.email}. Now sign in on both sides.`;
    msg.className = 'msg good';
    document.querySelectorAll('.signin input[name="email"]').forEach((i) => (i.value = body.user.email));
    form.reset();
  });
});

document.querySelectorAll('form.signin').forEach((form) => {
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const { email, password } = Object.fromEntries(new FormData(form));
    await busy($('button', form), async () => {
      try {
        if (form.dataset.form === 'jwt') await jwtSignIn(email, password);
        else await ninshoSignIn(email, password);
        if (state[form.dataset.form].user) form.reset();
      } catch (err) {
        setMsg(form.dataset.form, `Sign-in failed: ${err.message}`, 'bad');
      }
    });
  });
});

for (const side of ['jwt', 'ninsho']) {
  sides[side].addEventListener('click', async (event) => {
    const button = event.target.closest('[data-action]');
    if (!button) return;
    await busy(button, async () => {
      try {
        if (button.dataset.action === 'check') await (side === 'jwt' ? jwtCheck() : ninshoCheck());
        if (button.dataset.action === 'signout') await (side === 'jwt' ? jwtSignOut() : ninshoSignOut());
      } catch (err) {
        setMsg(side, err.message, 'bad');
      }
    });
  });
}

// ─── Start ──────────────────────────────────────────────────────────────────

async function checkHealth() {
  const el = $('#health');
  try {
    const res = await fetch('/api/health');
    const body = await res.json();
    const part = (label, ok) => {
      const span = document.createElement('span');
      span.className = ok ? 'ok' : 'down';
      span.textContent = `● ${label}`;
      return span;
    };
    el.replaceChildren(part('Postgres', body.database), '  ', part('Redis', body.redis));
  } catch {
    el.textContent = 'Server unreachable';
  }
}

async function restore() {
  // JWT: whatever is in localStorage is the login, as long as it still verifies.
  const token = jwtToken();
  if (token) {
    const res = await fetch('/api/jwt/me', { headers: { authorization: `Bearer ${token}` } });
    if (res.ok) {
      const body = await res.json();
      state.jwt = { user: body.user, expiresAt: body.expiresAt };
    } else {
      forgetJwt();
    }
  }
  // Ninsho: nothing is stored where scripts can read it, so a reload asks the
  // server for a fresh access token using the HttpOnly cookie and this key.
  try {
    if (await ninsho.refresh()) {
      const res = await ninsho.fetch('/api/ninsho/me');
      if (res.ok) {
        state.ninsho.user = (await res.json()).user;
        await loadSessions();
      }
    }
  } catch {
    // Not signed in.
  }
}

render();
checkHealth();
restore().finally(render);
