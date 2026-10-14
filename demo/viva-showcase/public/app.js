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

// BroadcastChannel listener for 2-tab demonstration
const syncChannel = new BroadcastChannel('ninsho:session:v1:secureshop-auth');
syncChannel.onmessage = (event) => {
  const data = event.data;
  if (data && data.context === 'secureshop-auth' && data.type === 'logout') {
    appendTimeline('EVENT', 'BroadcastChannel (sessionSync)', 'peer-tab-logout', {
      notice: 'Received peer logout invalidation notice',
      type: data.type,
      id: data.id,
    });
    // Invalidate UI
    if (currentStrategy === 'dpop') {
      currentUser = null;
      updateUI();
      alert('👥 Two-Tab Sync: Session invalidated because another browser tab logged out!');
    }
  }
};

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
        <span class="empty-icon">📡</span>
        <p>No HTTP requests recorded yet. Make a request to view live wire logs.</p>
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
              <span class="timeline-method">${e.method}</span>
              <span class="timeline-path">${e.url}</span>
            </div>
            <div>
              <span class="timeline-status ${statusClass}">HTTP ${e.status}</span>
              <span class="text-muted" style="margin-left: 0.5rem; font-size: 0.75rem;">${e.time}</span>
            </div>
          </div>
          <div class="timeline-body">
${JSON.stringify({ headers: e.headers, response: e.body }, null, 2)}
          </div>
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
    dpop: 'Ninsho DPoP',
    opaque: 'Ninsho Opaque (Dual-Instance)',
    jwt: 'Stateless JWT Baseline',
  };
  modeBadge.textContent = `Mode: ${modeNames[currentStrategy]}`;
  if (profMode) profMode.textContent = modeNames[currentStrategy];

  // User state
  const navAvatar = document.getElementById('navAvatar');
  const navUserName = document.getElementById('navUserName');
  const navLogoutBtn = document.getElementById('navLogoutBtn');
  const loginFormContainer = document.getElementById('loginFormContainer');
  const profileContainer = document.getElementById('profileContainer');

  if (currentUser) {
    navAvatar.textContent = currentUser.avatar;
    navUserName.textContent = `${currentUser.name} (${currentUser.role})`;
    navLogoutBtn.style.display = 'inline-flex';
    loginFormContainer.style.display = 'none';
    profileContainer.style.display = 'block';

    document.getElementById('profAvatar').textContent = currentUser.avatar;
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
      inspectLocal.textContent = stored ? `Stored (${stored.slice(0, 16)}...)` : 'None';
      inspectLocal.style.color = '#f59e0b';
      inspectMem.textContent = 'None (reads localStorage)';
      inspectIdb.textContent = 'None';
      inspectCookie.textContent = 'None';
    } else if (currentStrategy === 'opaque') {
      inspectLocal.textContent = 'null (Tokens not stored in localStorage)';
      inspectLocal.style.color = '#10b981';
      inspectMem.textContent = capturedOpaqueToken ? `Present (${capturedOpaqueToken.slice(0, 12)}...)` : 'Stored in Client Memory';
      inspectIdb.textContent = 'None (Opaque requires no client key)';
      inspectCookie.textContent = 'None';
    } else {
      // DPoP
      inspectLocal.textContent = 'null (Protected - Absent from localStorage)';
      inspectLocal.style.color = '#10b981';
      inspectMem.textContent = 'In-Memory Only (Non-extractable)';
      inspectIdb.textContent = 'IndexedDB: secureshop-dpop-keys (Non-extractable)';
      inspectCookie.textContent = 'ninsho_dpop_rt (HttpOnly, SameSite=Lax)';
    }
  } else {
    navAvatar.textContent = '👤';
    navUserName.textContent = 'Not Authenticated';
    navLogoutBtn.style.display = 'none';
    loginFormContainer.style.display = 'block';
    profileContainer.style.display = 'none';
    document.getElementById('ordersEmptyState').style.display = 'block';
    document.getElementById('ordersList').style.display = 'none';
    document.getElementById('ordersSourceBadge').textContent = 'Awaiting API Call';
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
        <div class="product-name">${p.name}</div>
        <p class="text-muted" style="font-size: 0.75rem; margin-bottom: 0.5rem;">${p.description}</p>
        <div class="product-price">$${p.price}</div>
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
      statusEl.textContent = 'Redis: Connected (7.x Alpine)';
      statusEl.style.color = '#6ee7b7';
    } else {
      statusEl.textContent = 'Redis: Degraded';
      statusEl.style.color = '#fcd34d';
    }
  } catch {
    statusEl.textContent = 'Server: Unreachable';
    statusEl.style.color = '#fca5a5';
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
      alert(`DPoP request failed: ${err.message}`);
      return;
    }
  }

  if (res && res.ok && data.orders) {
    emptyEl.style.display = 'none';
    listEl.style.display = 'block';
    badgeEl.textContent = `Verified via ${data.verifiedBy || currentStrategy}`;

    listEl.innerHTML = data.orders
      .map(
        (o) => `
      <div class="order-item">
        <div class="order-top">
          <span class="order-id">${o.id}</span>
          <span class="badge badge-success">${o.status.toUpperCase()}</span>
          <span class="order-total">$${o.total}</span>
        </div>
        <div class="order-items">
          ${o.items.map((i) => `<div>• ${i.productName} (x${i.quantity}) — $${i.price} each</div>`).join('')}
        </div>
        <div class="text-muted font-mono" style="font-size: 0.75rem; margin-top: 0.35rem;">
          Tracking: ${o.tracking} | Placed: ${new Date(o.placedAt).toLocaleDateString()}
        </div>
      </div>`,
      )
      .join('');
  } else {
    emptyEl.style.display = 'block';
    listEl.style.display = 'none';
    badgeEl.textContent = `Rejected (HTTP ${res ? res.status : 'Error'})`;
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
      alert(data.error?.message || 'Login failed');
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
      alert(data.error?.message || 'Login failed');
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
        alert(err.error?.message || 'DPoP Login failed');
      }
    } catch (err) {
      alert(`DPoP signIn error: ${err.message}`);
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
    try {
      const res = await dpopClient.signOut('/api/dpop/logout');
      appendTimeline('POST (DPoP Client)', '/api/dpop/logout', res ? res.status : 200, {
        ok: true,
        message: 'Revoked via DPoP client and broadcasted to peer tabs',
      });
      currentUser = null;
      updateUI();
    } catch (err) {
      console.error('SignOut error', err);
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
    document.getElementById('jwtVerdictBox').textContent = 'Step 1 complete: Alice logged in. Token issued.';
    document.getElementById('jwtVerdictBox').className = 'verdict-box verdict-success';
  }
};

document.getElementById('expJwtCaptureBtn').onclick = () => {
  if (capturedJwtToken) {
    document.getElementById('jwtCapturedBox').textContent = capturedJwtToken;
    document.getElementById('expJwtReplayBtn').disabled = false;
    document.getElementById('jwtVerdictBox').textContent = 'Step 2 complete: Token captured into memory variable for replay.';
  }
};

document.getElementById('expJwtLogoutBtn').onclick = async () => {
  const res = await fetch('/api/jwt/logout', { method: 'POST' });
  const data = await res.json();
  appendTimeline('POST', '/api/jwt/logout', res.status, data);
  localStorage.removeItem('secureshop_jwt_token');
  document.getElementById('jwtVerdictBox').textContent = 'Step 3 complete: Client logged out and token deleted from localStorage.';
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
    verdict.textContent = `🚨 REPLAY ACCEPTED (HTTP 200)! The server accepted the captured token after logout. Because the baseline is stateless, the server has no record of the logout.`;
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
    document.getElementById('opaqueVerdictBox').textContent = 'Step 1 complete: Alice logged in via Instance A. Session stored in Redis.';
    document.getElementById('opaqueVerdictBox').className = 'verdict-box verdict-success';
  }
};

document.getElementById('expOpaqueVerifyABtn').onclick = async () => {
  const res = await fetch('/api/opaque/instance-a/orders', {
    headers: { Authorization: `Bearer ${capturedOpaqueToken}` },
  });
  const data = await res.json();
  appendTimeline('GET', '/api/opaque/instance-a/orders', res.status, data);
  document.getElementById('opaqueVerdictBox').textContent = `Instance A response: HTTP ${res.status} OK (Verified by Instance A).`;
};

document.getElementById('expOpaqueVerifyBBtn').onclick = async () => {
  const res = await fetch('/api/opaque/instance-b/orders', {
    headers: { Authorization: `Bearer ${capturedOpaqueToken}` },
  });
  const data = await res.json();
  appendTimeline('GET', '/api/opaque/instance-b/orders', res.status, data);
  document.getElementById('opaqueVerdictBox').textContent = `Instance B response: HTTP ${res.status} OK (Verified across shared Redis store by Instance B).`;
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
  document.getElementById('opaqueVerdictBox').textContent = 'Step 3 complete: Session revoked via Instance A. Ready to test replay.';
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
    verdict.textContent = `🛡️ REPLAY REJECTED (HTTP 401)! Instance A instantly rejected the revoked token.`;
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
    verdict.textContent = `🛡️ REPLAY REJECTED (HTTP 401)! Instance B ALSO instantly rejected the revoked token (zero latency cross-instance revocation).`;
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
      document.getElementById('dpopVerdictBox').textContent = 'Step 1 complete: Bob logged in via DPoP. Token bound to non-extractable client key.';
      document.getElementById('dpopVerdictBox').className = 'verdict-box verdict-success';
    }
  } catch (err) {
    alert(`DPoP error: ${err.message}`);
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
    verdict.textContent = `🛡️ ATTACK BLOCKED (HTTP 401)! Server refused bearer-only replay because the token is bound to a DPoP key proof.`;
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
    verdict.textContent = `🛡️ ATTACK BLOCKED (HTTP 401)! Server verified proof signature, but thumbprint does NOT match the bound confirmation key (jkt).`;
    verdict.className = 'verdict-box verdict-rejected';
  }
};

document.getElementById('expDpopProofReplayBtn').onclick = async () => {
  // Replay a previously used proof
  const attackerKey = await generateDpopKey();
  const proof = await createProof(attackerKey, {
    method: 'GET',
    url: `${window.location.origin}/api/dpop/orders`,
    accessToken: capturedDpopToken,
  });

  // First call (fails on wrong key, but registers jti in store)
  await fetch('/api/dpop/orders', {
    headers: { Authorization: `DPoP ${capturedDpopToken}`, DPoP: proof },
  });

  // Second call with same proof header (replay)
  const res2 = await fetch('/api/dpop/orders', {
    headers: { Authorization: `DPoP ${capturedDpopToken}`, DPoP: proof },
  });
  const data2 = await res2.json();
  appendTimeline('GET (Proof JTI Replay)', '/api/dpop/orders', res2.status, data2, {
    DPoP: '<replayed_proof_header>',
  });

  const verdict = document.getElementById('dpopVerdictBox');
  if (res2.status === 401) {
    verdict.textContent = `🛡️ ATTACK BLOCKED (HTTP 401)! Server detected reused DPoP proof JTI in single-use replay guard.`;
    verdict.className = 'verdict-box verdict-rejected';
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
