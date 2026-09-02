import { describe, it, expect } from 'vitest';
import { MemoryStore } from '../store/memory.js';
import { MemoryAuditSink } from '../audit.js';
import { OneTimeTokenManager } from '../tokens/one-time.js';

describe('probe: concurrent issue', () => {
  it('how many tokens survive when two issues race?', async () => {
    let surviving = 0;
    const rounds = 40;

    for (let i = 0; i < rounds; i += 1) {
      const store = new MemoryStore();
      const tokens = new OneTimeTokenManager({ store, audit: new MemoryAuditSink() });

      const [a, b] = await Promise.all([
        tokens.issue({ purpose: 'password-reset', subject: 'u' }),
        tokens.issue({ purpose: 'password-reset', subject: 'u' }),
      ]);

      const results = await Promise.allSettled([
        tokens.consume('password-reset', a.token),
        tokens.consume('password-reset', b.token),
      ]);
      surviving += results.filter((r) => r.status === 'fulfilled').length;
      await store.close();
    }

    console.log(`PROBE: ${surviving} of ${rounds * 2} tokens usable across ${rounds} races (1 per race is intended)`);
    expect(surviving).toBeLessThanOrEqual(rounds * 2);
  });
});
