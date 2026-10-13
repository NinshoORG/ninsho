import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import express from 'express';
import { Redis } from 'ioredis';
import { Ninsho, RedisStore, MemoryAuditSink, getAuth, generateDpopKeyPair, createDpopProof } from '@ninshorg/server';

// Port 0 avoids collisions. Never read address() until listen has completed.
export async function listen(app) {
  const server = createServer(app);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  const address = server.address();
  assert(address && typeof address !== 'string');
  return { server, origin: `http://127.0.0.1:${address.port}` };
}

export async function runThreeDemos(redisUrl, log = console.log) {
  if (!redisUrl) throw new Error('Set REDIS_URL to a dedicated test Redis (6.2+). No memory fallback.');
  const prefix = `ninsho-viva:${randomUUID()}:`;
  const admin = new Redis(redisUrl, { lazyConnect: true, connectTimeout: 3000, retryStrategy: () => null });
  admin.on('error', () => {});
  const stores = [];
  const servers = [];
  const results = [];
  async function check(name, url, token, expected, { proof, method = 'GET' } = {}) {
    const response = await fetch(url, {
      method, signal: AbortSignal.timeout(5000),
      headers: { Authorization: `Bearer ${token}`, ...(proof && { DPoP: proof }) },
    });
    await response.arrayBuffer();
    results.push({ name, expected, actual: response.status });
    log(`${name}: expected ${expected}, actual ${response.status}`);
    assert.equal(response.status, expected, name);
  }
  try {
    await admin.connect();
    const replicas = [];
    for (const device of ['A', 'B']) {
      // Separate Redis connections and engine instances, same namespace.
      const store = new RedisStore(redisUrl, { redisOptions: { keyPrefix: prefix } });
      stores.push(store);
      assert.equal(await store.ping(), true);
      const audit = new MemoryAuditSink();
      const bearer = new Ninsho({ store, audit });
      const bound = new Ninsho({ store, audit, binding: 'dpop' });
      const app = express();
      app.get('/resource/:id', bearer.verify(), bearer.requireOwner(req => req.params?.['id']),
        (_req, res) => res.json({ device }));
      app.post('/logout', bearer.verify(), async (req, res) => {
        await bearer.revokeSession(getAuth(req).sessionId, 'logout');
        res.sendStatus(204);
      });
      // Identity is a fixed fixture, not a credential-verification example.
      app.post('/bound-login', async (req, res) => {
        const confirmationKey = await bound.confirmProofOfPossession(req);
        res.json(await bound.createSession({ userId: 'alice', roles: [], scopes: [] }, { confirmationKey }));
      });
      app.get('/bound', bound.verify(), (_req, res) => res.json({ device }));
      const endpoint = await listen(app);
      servers.push(endpoint.server);
      replicas.push({ ...endpoint, bearer });
    }
    const [a, b] = replicas;
    const session = await a.bearer.createSession({ userId: 'alice', roles: [], scopes: [] });
    log('Demo 1: default opaque bearer tokens and shared-store logout');
    await check('Device A bearer', `${a.origin}/resource/alice`, session.accessToken, 200);
    await check('Copied bearer on Device B (expected to work)', `${b.origin}/resource/alice`, session.accessToken, 200);
    await check('Logout on Device A', `${a.origin}/logout`, session.accessToken, 204, { method: 'POST' });
    await check('Reuse on Device B after completed logout', `${b.origin}/resource/alice`, session.accessToken, 401);

    log('Demo 2: opt-in proof of possession');
    const owner = generateDpopKeyPair();
    const thief = generateDpopKeyPair();
    const loginUrl = `${a.origin}/bound-login`;
    const login = await fetch(loginUrl, {
      method: 'POST', signal: AbortSignal.timeout(5000),
      headers: { DPoP: createDpopProof(owner, { method: 'POST', url: loginUrl }) },
    });
    assert.equal(login.status, 200, 'DPoP login');
    const { accessToken } = await login.json();
    const url = `${b.origin}/bound`;
    await check('Missing DPoP proof', url, accessToken, 401);
    await check('Different client key', url, accessToken, 401, {
      proof: createDpopProof(thief, { method: 'GET', url, accessToken }),
    });
    const proof = createDpopProof(owner, { method: 'GET', url, accessToken });
    await check('Valid DPoP proof', url, accessToken, 200, { proof });
    await check('Replayed DPoP proof', url, accessToken, 401, { proof });

    log('Demo 3: resource ownership');
    const fresh = await a.bearer.createSession({ userId: 'alice', roles: [], scopes: [] });
    await check('Alice reads Alice', `${b.origin}/resource/alice`, fresh.accessToken, 200);
    await check('Alice reads Bob', `${b.origin}/resource/bob`, fresh.accessToken, 403);
    return results;
  } finally {
    const cleanup = await Promise.allSettled(servers.map(server => new Promise((resolve, reject) => {
      server.close(error => error ? reject(error) : resolve());
      server.closeAllConnections();
    })));
    await Promise.all(stores.map(store => store.close()));
    try {
      if (admin.status === 'ready') {
        // Only this run's random namespace; never FLUSHDB/FLUSHALL.
        let cursor = '0';
        do {
          const [next, keys] = await admin.scan(cursor, 'MATCH', `${prefix}*`, 'COUNT', 100);
          cursor = next;
          if (keys.length) await admin.del(...keys);
        } while (cursor !== '0');
        assert.deepEqual(await admin.keys(`${prefix}*`), [], 'demo Redis keys cleaned up');
      }
    } finally {
      admin.disconnect();
    }
    const failed = cleanup.find(result => result.status === 'rejected');
    if (failed) throw failed.reason;
    log('Cleanup complete: HTTP servers, Redis connections, and demo keys removed.');
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runThreeDemos(process.env.REDIS_URL).catch(error => {
    console.error(error);
    process.exitCode = 1;
  });
}
