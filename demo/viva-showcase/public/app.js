import {
  NinshoClient,
  IndexedDbKeyStore,
  generateDpopKey,
  createProof,
} from '/vendor/@ninshorg/client/index.js';

// ── State Management ────────────────────────────────────────────────────────

let currentStrategy = 'dpop'; // 'dpop' | 'opaque' | 'jwt'
let currentUser = null; // { id, email, name, role, avatar }
let capturedJwtToken = null;
let capturedOpaqueToken = null;
let capturedOpaqueSessionId = null;
let capturedDpopToken = null;
const timelineEvents = [];

// Initialize real @ninshorg/client with IndexedDB key store and sessionSync opt-in
const dpopClient = new NinshoClient({
  baseUrl: window.location.origin,
  keyStore: new IndexedDbKeyStore('secureshop-dpop-keys'),
  refreshPath: '/api/dpop/refresh',
  sessionSync: { context: 'secureshop-auth' },
});

let signingOut = false; // this tab is signing itself out

// Two-tab demonstration. This channel also hears this tab's OWN notices, and
// a notice carries no sender. The Ninsho client's channel was created first,
// so it has already handled the message (ignoring its own) by the time this
// runs: if this tab's token is now gone, another tab ended or replaced it.
const syncChannel = new BroadcastChannel('ninsho:session:v1:secureshop-auth');
syncChannel.onmessage = (event) => {
  const data = event.data;
  if (!data || data.context !== 'secureshop-auth') return;
  if (currentStrategy !== 'dpop' || !currentUser || signingOut || dpopClient.accessToken !== null) return;
  appendTimeline('EVENT', 'BroadcastChannel (sessionSync)', data.type, {
    notice: data.type === 'logout' ? 'Another tab signed out' : 'Another tab signed in',
    id: data.id,
  });
  currentUser = null;
  updateUI();
  showNotice(
    data.type === 'logout'
      ? 'Another tab signed out, so this tab was signed out too. No token was sent between tabs.'
      : 'Another tab signed in, which replaced this tab’s login. Sign in again here, or use the other tab.',
  );
};

/** Plain-text banner at the top of the page, in place of alert(). */
function showNotice(text, tone = 'info') {
  const el = document.getElementById('notice');
  document.getElementById('noticeText').textContent = text;
  el.className = `notice notice-${tone}`;
  el.hidden = false;
}
document.getElementById('noticeClose').onclick = () => {
  document.getElementById('notice').hidden = true;
};

const esc = (value) =>
  String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

const initials = (name) =>
  name.split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join('');

// ── Timeline Helper ─────────────────────────────────────────────────────────

function appendTimeline(method, url, status, body, headers = {}) {
  const event = {
    id: Date.now() + Math.random().toString(36).slice(2, 6),
    time: new Date().toLocaleTimeString(),
    method,
    url,
    status,
    body,
    headers,
  };
  timelineEvents.unshift(event);
  renderTimeline();
}

function renderTimeline() {
  const list = document.getElementById('timelineList');
  const countBadge = document.getElementById('timelineCount');
  countBadge.textContent = timelineEvents.length;

  if (timelineEvents.length === 0) {
    list.innerHTML = `
      <div class="empty-state">
        <p>No requests yet. Sign in or run an experiment, and each request appears here.</p>
      </div>`;
    return;
  }

  list.innerHTML = timelineEvents
    .map((e) => {
      let statusClass = 'status-200';
      if (typeof e.status === 'number') {
        if (e.status >= 500) statusClass = 'status-500';
        else if (e.status === 401 || e.status === 403) statusClass = 'status-401';
        else if (e.status >= 400) statusClass = 'status-403';
      } else {
        statusClass = 'status-204';
      }

      return `
        <div class="timeline-entry">
          <div class="timeline-header">
            <div>
              <span class="timeline-method">${esc(e.method)}</span>
              <span class="timeline-path">${esc(e.url)}</span>
            </div>
            <div>
              <span class="timeline-status ${statusClass}">${typeof e.status === 'number' ? `HTTP ${e.status}` : esc(e.status)}</span>
              <span class="timeline-time">${esc(e.time)}</span>
            </div>
          </div>
          <div class="timeline-body">${esc(JSON.stringify({ headers: e.headers, response: e.body }, null, 2))}</div>
        </div>`;
    })
    .join('');
}

// ── UI Updates ──────────────────────────────────────────────────────────────

function updateUI() {
  // Strategy pills
  document.querySelectorAll('#strategyPills .pill').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.strategy === currentStrategy);
  });

  const modeBadge = document.getElementById('currentAuthModeBadge');
  const profMode = document.getElementById('profMode');
  const modeNames = {
    dpop: 'Ninsho + device key',
    opaque: 'Ninsho sessions',
    jwt: 'Plain JWT',
  };
  modeBadge.textContent = modeNames[currentStrategy];
  if (profMode) profMode.textContent = modeNames[currentStrategy];

  // User state
  const navAvatar = document.getElementById('navAvatar');
  const navUserName = document.getElementById('navUserName');
  const navLogoutBtn = document.getElementById('navLogoutBtn');
  const loginFormContainer = document.getElementById('loginFormContainer');
  const profileContainer = document.getElementById('profileContainer');

  if (currentUser) {
    navAvatar.textContent = initials(currentUser.name);
    navUserName.textContent = `${currentUser.name} (${currentUser.role})`;
    navLogoutBtn.style.display = 'inline-flex';
    loginFormContainer.style.display = 'none';
    profileContainer.style.display = 'block';

    document.getElementById('profAvatar').textContent = initials(currentUser.name);
    document.getElementById('profName').textContent = currentUser.name;
    document.getElementById('profEmail').textContent = currentUser.email;
    document.getElementById('profRole').textContent = currentUser.role;

    // Storage inspector
    const inspectLocal = document.getElementById('inspectLocalStorage');
    const inspectMem = document.getElementById('inspectMemoryToken');
    const inspectIdb = document.getElementById('inspectIndexedDb');
    const inspectCookie = document.getElementById('inspectCookie');

    if (currentStrategy === 'jwt') {
      const stored = localStorage.getItem('secureshop_jwt_token');
      inspectLocal.textContent = stored ? `${stored.slice(0, 16)}… (any script can read it)` : 'Nothing';
      inspectLocal.className = 'inspect-val is-bad';
      inspectMem.textContent = 'Read from localStorage';
      inspectIdb.textContent = 'None';
      inspectCookie.textContent = 'None';
    } else if (currentStrategy === 'opaque') {
      inspectLocal.textContent = 'Nothing';
      inspectLocal.className = 'inspect-val is-good';
      inspectMem.textContent = capturedOpaqueToken ? `${capturedOpaqueToken.slice(0, 12)}… (in page memory)` : 'In page memory';
      inspectIdb.textContent = 'None (this mode uses no device key)';
      inspectCookie.textContent = 'None';
    } else {
      // DPoP
      inspectLocal.textContent = 'Nothing';
      inspectLocal.className = 'inspect-val is-good';
      inspectMem.textContent = 'In page memory only';
      inspectIdb.textContent = 'secureshop-dpop-keys (cannot be exported)';
      inspectCookie.textContent = 'ninsho_dpop_rt (HttpOnly: scripts cannot read it)';
    }
  } else {
    navAvatar.textContent = '';
    navUserName.textContent = 'Not signed in';
    navLogoutBtn.style.display = 'none';
    loginFormContainer.style.display = 'block';
    profileContainer.style.display = 'none';
    document.getElementById('ordersEmptyState').style.display = 'block';
    document.getElementById('ordersList').style.display = 'none';
    document.getElementById('ordersSourceBadge').textContent = 'Not loaded';
  }
}

// ── Products Catalog ────────────────────────────────────────────────────────

async function loadProducts() {
  try {
    const res = await fetch('/api/products');
    const data = await res.json();
    const grid = document.getElementById('productGrid');
    grid.innerHTML = data.products
      .map(
        (p) => `
      <div class="product-card">
        <div class="product-name">${esc(p.name)}</div>
        <p class="product-desc">${esc(p.description)}</p>
        <div class="product-price">$${esc(p.price)}</div>
      </div>`,
      )
      .join('');
  } catch (err) {
    console.error('Failed to load products', err);
  }
}

// ── Check Health ────────────────────────────────────────────────────────────

async function checkHealth() {
  const statusEl = document.getElementById('redisStatus');
  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    if (data.status === 'healthy') {
      statusEl.textContent = 'Redis connected';
      statusEl.className = 'is-good';
    } else {
      statusEl.textContent = 'Redis unavailable';
      statusEl.className = 'is-bad';
    }
  } catch {
    statusEl.textContent = 'Server unreachable';
    statusEl.className = 'is-bad';
  }
}

// ── Orders Loader ───────────────────────────────────────────────────────────

async function loadOrders() {
  if (!currentUser) return;
  const listEl = document.getElementById('ordersList');
  const emptyEl = document.getElementById('ordersEmptyState');
  const badgeEl = document.getElementById('ordersSourceBadge');

  let res;
  let data;
  let endpoint = '';
  const headers = {};

  if (currentStrategy === 'jwt') {
    endpoint = '/api/jwt/dashboard';
    const token = localStorage.getItem('secureshop_jwt_token') || '';
    headers['Authorization'] = `Bearer ${token}`;
    res = await fetch(endpoint, { headers });
    data = await res.json();
    appendTimeline('GET', endpoint, res.status, data, headers);
  } else if (currentStrategy === 'opaque') {
    endpoint = '/api/opaque/instance-a/orders';
    headers['Authorization'] = `Bearer ${capturedOpaqueToken}`;
    res = await fetch(endpoint, { headers });
    data = await res.json();
    appendTimeline('GET', endpoint, res.status, data, headers);
  } else {
    // DPoP using NinshoClient.fetch
    endpoint = '/api/dpop/orders';
    try {
      res = await dpopClient.fetch(endpoint);
      data = await res.json();
      appendTimeline('GET (DPoP Client)', endpoint, res.status, data, {
        Authorization: 'DPoP <access_token>',
        DPoP: '<rfc9449_proof>',
      });
    } catch (err) {
      appendTimeline('GET (DPoP Client Error)', endpoint, 401, {
        error: err instanceof Error ? err.message : String(err),
      });
      showNotice(`The request could not be sent: ${err.message}`, 'bad');
      return;
    }
  }

  if (res && res.ok && data.orders) {
    emptyEl.style.display = 'none';
    listEl.style.display = 'block';
    badgeEl.textContent = 'Loaded from the server';

    listEl.innerHTML = data.orders
      .map(
        (o) => `
      <div class="order-item">
        <div class="order-top">
          <span class="order-id">${esc(o.id)}</span>
          <span class="badge">${esc(o.status)}</span>
          <span class="order-total">$${esc(o.total)}</span>
        </div>
        <div class="order-items">
          ${o.items.map((i) => `<div>${esc(i.productName)} &times; ${esc(i.quantity)} — $${esc(i.price)} each</div>`).join('')}
        </div>
        <div class="order-meta">
          Tracking ${esc(o.tracking)} · Placed ${esc(new Date(o.placedAt).toLocaleDateString())}
        </div>
      </div>`,
      )
      .join('');
  } else {
    emptyEl.style.display = 'block';
    listEl.style.display = 'none';
    badgeEl.textContent = `Refused (HTTP ${res ? res.status : 'error'})`;
  }
}

// ── Authentication Handlers ─────────────────────────────────────────────────

async function handleLogin(email, password) {
  if (currentStrategy === 'jwt') {
    const res = await fetch('/api/jwt/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    appendTimeline('POST', '/api/jwt/login', res.status, data);

    if (res.ok) {
      localStorage.setItem('secureshop_jwt_token', data.token);
      capturedJwtToken = data.token;
      currentUser = data.user;
      updateUI();
      await loadOrders();
    } else {
      showNotice(data.error?.message || 'Sign-in failed.', 'bad');
    }
  } else if (currentStrategy === 'opaque') {
    const res = await fetch('/api/opaque/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    appendTimeline('POST', '/api/opaque/login', res.status, data);

    if (res.ok) {
      capturedOpaqueToken = data.accessToken;
      capturedOpaqueSessionId = data.sessionId;
      currentUser = data.user;
      updateUI();
      await loadOrders();
    } else {
      showNotice(data.error?.message || 'Sign-in failed.', 'bad');
    }
  } else {
    // DPoP using NinshoClient.signIn
    try {
      const res = await dpopClient.signIn('/api/dpop/login', { email, password });
      appendTimeline('POST (DPoP Client)', '/api/dpop/login', res.status, {
        ok: res.ok,
        message: 'Bound session created; access token in memory',
      });

      if (res.ok) {
        // Find user details from seeded records
        currentUser = email.includes('alice')
          ? { id: 'usr_alice_secureshop', email, name: 'Alice Vance', role: 'admin', avatar: '👩‍💼' }
          : { id: 'usr_bob_secureshop', email, name: 'Bob Smith', role: 'customer', avatar: '👨‍💼' };
        capturedDpopToken = dpopClient.accessToken;
        updateUI();
        await loadOrders();
      } else {
        const err = await res.json().catch(() => ({}));
        showNotice(err.error?.message || 'Sign-in failed.', 'bad');
      }
    } catch (err) {
      showNotice(`Sign-in failed: ${err.message}`, 'bad');
    }
  }
}

async function handleLogout() {
  if (currentStrategy === 'jwt') {
    const res = await fetch('/api/jwt/logout', { method: 'POST' });
    const data = await res.json();
    appendTimeline('POST', '/api/jwt/logout', res.status, data);
    localStorage.removeItem('secureshop_jwt_token');
    currentUser = null;
    updateUI();
  } else if (currentStrategy === 'opaque') {
    const res = await fetch('/api/opaque/logout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionId: capturedOpaqueSessionId }),
    });
    const data = await res.json();
    appendTimeline('POST', '/api/opaque/logout', res.status, data);
    currentUser = null;
    updateUI();
  } else {
    // DPoP using NinshoClient.signOut
    signingOut = true;
    try {
      const res = await dpopClient.signOut('/api/dpop/logout');
      // signOut sends nothing when this tab no longer holds a token (another
      // tab replaced or ended its login), so only claim what happened.
      if (res) {
        appendTimeline('POST (DPoP Client)', '/api/dpop/logout', res.status, {
          message: res.ok ? 'Session ended on the server; other tabs notified' : 'The server refused the sign-out',
        });
      } else {
        appendTimeline('POST (DPoP Client)', '/api/dpop/logout', 'not sent', {
          message: 'This tab had no active token, so there was nothing to end from here.',
        });
      }
    } catch (err) {
      console.error('SignOut error', err);
    } finally {
      signingOut = false;
      currentUser = null;
      updateUI();
    }
  }
}

// ── Experiment Lab Event Handlers ────────────────────────────────────────────

// Experiment 1: Stateless JWT
document.getElementById('expJwtLoginBtn').onclick = async () => {
  const res = await fetch('/api/jwt/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'alice@example.com', password: 'password123' }),
  });
  const data = await res.json();
  appendTimeline('POST', '/api/jwt/login', res.status, data);
  if (res.ok) {
    capturedJwtToken = data.token;
    localStorage.setItem('secureshop_jwt_token', data.token);
    document.getElementById('expJwtCaptureBtn').disabled = false;
    document.getElementById('expJwtLogoutBtn').disabled = false;
    document.getElementById('jwtVerdictBox').textContent = 'Step 1 done: Alice is signed in and holds a token.';
    document.getElementById('jwtVerdictBox').className = 'verdict-box verdict-success';
  }
};

document.getElementById('expJwtCaptureBtn').onclick = () => {
  if (capturedJwtToken) {
    document.getElementById('jwtCapturedBox').textContent = capturedJwtToken;
    document.getElementById('expJwtReplayBtn').disabled = false;
    document.getElementById('jwtVerdictBox').textContent = 'Step 2 done: the token is copied (shown above).';
  }
};

document.getElementById('expJwtLogoutBtn').onclick = async () => {
  const res = await fetch('/api/jwt/logout', { method: 'POST' });
  const data = await res.json();
  appendTimeline('POST', '/api/jwt/logout', res.status, data);
  localStorage.removeItem('secureshop_jwt_token');
  document.getElementById('jwtVerdictBox').textContent = 'Step 3 done: signed out. The browser deleted its token; the server had nothing to do.';
  document.getElementById('jwtVerdictBox').className = 'verdict-box verdict-warning';
};

document.getElementById('expJwtReplayBtn').onclick = async () => {
  const res = await fetch('/api/jwt/dashboard', {
    headers: { Authorization: `Bearer ${capturedJwtToken}` },
  });
  const data = await res.json();
  appendTimeline('POST (Replay Attack)', '/api/jwt/dashboard', res.status, data, {
    Authorization: `Bearer ${capturedJwtToken.slice(0, 16)}...`,
  });

  const verdict = document.getElementById('jwtVerdictBox');
  if (res.status === 200) {
    verdict.textContent = 'Accepted (HTTP 200) after logout. The server keeps no record of the logout, so the copied token still works until it expires.';
    verdict.className = 'verdict-box verdict-warning';
  } else {
    verdict.textContent = `Unexpected rejection: HTTP ${res.status}`;
  }
};

// Experiment 2: Ninsho Opaque
document.getElementById('expOpaqueLoginBtn').onclick = async () => {
  const res = await fetch('/api/opaque/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'alice@example.com', password: 'password123' }),
  });
  const data = await res.json();
  appendTimeline('POST', '/api/opaque/login', res.status, data);
  if (res.ok) {
    capturedOpaqueToken = data.accessToken;
    capturedOpaqueSessionId = data.sessionId;
    document.getElementById('expOpaqueVerifyABtn').disabled = false;
    document.getElementById('expOpaqueVerifyBBtn').disabled = false;
    document.getElementById('expOpaqueLogoutBtn').disabled = false;
    document.getElementById('opaqueVerdictBox').textContent = 'Step 1 done: Alice is signed in through server A. Her session is in Redis.';
    document.getElementById('opaqueVerdictBox').className = 'verdict-box verdict-success';
  }
};

document.getElementById('expOpaqueVerifyABtn').onclick = async () => {
  const res = await fetch('/api/opaque/instance-a/orders', {
    headers: { Authorization: `Bearer ${capturedOpaqueToken}` },
  });
  const data = await res.json();
  appendTimeline('GET', '/api/opaque/instance-a/orders', res.status, data);
  document.getElementById('opaqueVerdictBox').textContent = `Server A answered HTTP ${res.status}.`;
};

document.getElementById('expOpaqueVerifyBBtn').onclick = async () => {
  const res = await fetch('/api/opaque/instance-b/orders', {
    headers: { Authorization: `Bearer ${capturedOpaqueToken}` },
  });
  const data = await res.json();
  appendTimeline('GET', '/api/opaque/instance-b/orders', res.status, data);
  document.getElementById('opaqueVerdictBox').textContent = `Server B answered HTTP ${res.status}, using the same session in Redis.`;
};

document.getElementById('expOpaqueLogoutBtn').onclick = async () => {
  const res = await fetch('/api/opaque/logout', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sessionId: capturedOpaqueSessionId }),
  });
  const data = await res.json();
  appendTimeline('POST', '/api/opaque/logout', res.status, data);
  document.getElementById('expOpaqueReplayABtn').disabled = false;
  document.getElementById('expOpaqueReplayBBtn').disabled = false;
  document.getElementById('opaqueVerdictBox').textContent = 'Step 3 done: the session was ended through server A. Now try the copied token.';
  document.getElementById('opaqueVerdictBox').className = 'verdict-box verdict-warning';
};

document.getElementById('expOpaqueReplayABtn').onclick = async () => {
  const res = await fetch('/api/opaque/instance-a/orders', {
    headers: { Authorization: `Bearer ${capturedOpaqueToken}` },
  });
  const data = await res.json();
  appendTimeline('GET (Replay Attack)', '/api/opaque/instance-a/orders', res.status, data);
  const verdict = document.getElementById('opaqueVerdictBox');
  if (res.status === 401) {
    verdict.textContent = 'Refused (HTTP 401) by server A. The session was ended, so the token no longer works.';
    verdict.className = 'verdict-box verdict-rejected';
  }
};

document.getElementById('expOpaqueReplayBBtn').onclick = async () => {
  const res = await fetch('/api/opaque/instance-b/orders', {
    headers: { Authorization: `Bearer ${capturedOpaqueToken}` },
  });
  const data = await res.json();
  appendTimeline('GET (Replay Attack)', '/api/opaque/instance-b/orders', res.status, data);
  const verdict = document.getElementById('opaqueVerdictBox');
  if (res.status === 401) {
    verdict.textContent = 'Refused (HTTP 401) by server B too. Both servers read the same Redis, so ending the session on one ends it on both.';
    verdict.className = 'verdict-box verdict-rejected';
  }
};

// Experiment 3: Ninsho DPoP
document.getElementById('expDpopLoginBtn').onclick = async () => {
  try {
    const res = await dpopClient.signIn('/api/dpop/login', {
      email: 'bob@example.com',
      password: 'password123',
    });
    const ok = res.ok;
    appendTimeline('POST (DPoP Client)', '/api/dpop/login', res.status, { ok });
    if (ok) {
      capturedDpopToken = dpopClient.accessToken;
      document.getElementById('expDpopTokenOnlyBtn').disabled = false;
      document.getElementById('expDpopWrongKeyBtn').disabled = false;
      document.getElementById('expDpopProofReplayBtn').disabled = false;
      document.getElementById('dpopVerdictBox').textContent = 'Step 1 done: Bob is signed in. His login is tied to this browser’s key.';
      document.getElementById('dpopVerdictBox').className = 'verdict-box verdict-success';
    }
  } catch (err) {
    showNotice(`Sign-in failed: ${err.message}`, 'bad');
  }
};

document.getElementById('expDpopTokenOnlyBtn').onclick = async () => {
  // Attacker has token but cannot produce proof from the non-extractable key
  const res = await fetch('/api/dpop/orders', {
    headers: { Authorization: `Bearer ${capturedDpopToken}` },
  });
  const data = await res.json();
  appendTimeline('GET (Token-Only Replay Attack)', '/api/dpop/orders', res.status, data, {
    Authorization: `Bearer ${capturedDpopToken ? capturedDpopToken.slice(0, 12) : ''}...`,
  });

  const verdict = document.getElementById('dpopVerdictBox');
  if (res.status === 401) {
    verdict.textContent = 'Refused (HTTP 401). The token is tied to a key, and no proof from that key was sent.';
    verdict.className = 'verdict-box verdict-rejected';
  }
};

document.getElementById('expDpopWrongKeyBtn').onclick = async () => {
  // Attacker generates their own key pair and creates a proof, but thumbprint won't match
  const attackerKey = await generateDpopKey();
  const proof = await createProof(attackerKey, {
    method: 'GET',
    url: `${window.location.origin}/api/dpop/orders`,
    accessToken: capturedDpopToken,
  });

  const res = await fetch('/api/dpop/orders', {
    headers: {
      Authorization: `DPoP ${capturedDpopToken}`,
      DPoP: proof,
    },
  });
  const data = await res.json();
  appendTimeline('GET (Wrong-Key Attack)', '/api/dpop/orders', res.status, data, {
    Authorization: 'DPoP <victim_token>',
    DPoP: '<attacker_signed_proof>',
  });

  const verdict = document.getElementById('dpopVerdictBox');
  if (res.status === 401) {
    verdict.textContent = 'Refused (HTTP 401). The proof was signed by a different key than the one this login is tied to.';
    verdict.className = 'verdict-box verdict-rejected';
  }
};

document.getElementById('expDpopProofReplayBtn').onclick = async () => {
  // A proof signed by the REAL device key, sent twice. The first use must
  // succeed; otherwise a refusal of the second would prove nothing.
  const token = dpopClient.accessToken ?? capturedDpopToken;
  const proof = await createProof(await dpopClient.getKey(), {
    method: 'GET',
    url: `${window.location.origin}/api/dpop/orders`,
    accessToken: token,
  });
  const send = () => fetch('/api/dpop/orders', { headers: { Authorization: `DPoP ${token}`, DPoP: proof } });

  const first = await send();
  appendTimeline('GET (proof, first use)', '/api/dpop/orders', first.status, await first.json(), {
    DPoP: '<proof signed by this device>',
  });
  const second = await send();
  appendTimeline('GET (same proof again)', '/api/dpop/orders', second.status, await second.json(), {
    DPoP: '<the identical proof>',
  });

  const verdict = document.getElementById('dpopVerdictBox');
  if (first.ok && second.status === 401) {
    verdict.textContent = 'First use accepted (HTTP 200). The identical proof sent again was refused (HTTP 401): each proof works once.';
    verdict.className = 'verdict-box verdict-rejected';
  } else {
    verdict.textContent = `The first use was refused (HTTP ${first.status}), so this run shows nothing about replay. Click "Login Bob (DPoP)" and try again.`;
    verdict.className = 'verdict-box verdict-warning';
  }
};

document.getElementById('openSecondTabBtn').onclick = () => {
  window.open(window.location.href, '_blank');
};

// ── Strategy Switcher & Seed Account Buttons ─────────────────────────────────

document.getElementById('btnStratDpop').onclick = () => {
  currentStrategy = 'dpop';
  currentUser = null;
  updateUI();
};

document.getElementById('btnStratOpaque').onclick = () => {
  currentStrategy = 'opaque';
  currentUser = null;
  updateUI();
};

document.getElementById('btnStratJwt').onclick = () => {
  currentStrategy = 'jwt';
  currentUser = null;
  updateUI();
};

document.getElementById('seedAliceBtn').onclick = () => {
  document.getElementById('loginEmail').value = 'alice@example.com';
  document.getElementById('loginPassword').value = 'password123';
};

document.getElementById('seedBobBtn').onclick = () => {
  document.getElementById('loginEmail').value = 'bob@example.com';
  document.getElementById('loginPassword').value = 'password123';
};

document.getElementById('loginForm').onsubmit = async (e) => {
  e.preventDefault();
  const email = document.getElementById('loginEmail').value;
  const password = document.getElementById('loginPassword').value;
  await handleLogin(email, password);
};

document.getElementById('logoutBtn').onclick = handleLogout;
document.getElementById('navLogoutBtn').onclick = handleLogout;
document.getElementById('refreshDashboardBtn').onclick = loadOrders;
document.getElementById('clearTimelineBtn').onclick = () => {
  timelineEvents.length = 0;
  renderTimeline();
};

// Main Tab Navigation
document.querySelectorAll('.tab-btn').forEach((btn) => {
  btn.onclick = () => {
    document.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach((c) => c.classList.remove('active'));
    btn.classList.add('active');
    const target = document.getElementById(`tab-${btn.dataset.tab}`);
    if (target) target.classList.add('active');
  };
});

// Initial boot
checkHealth();
loadProducts();
updateUI();
