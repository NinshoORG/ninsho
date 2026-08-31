/**
 * Bounded-concurrency mapping.
 *
 * ─── Why not just Promise.all ─────────────────────────────────────────────
 * Two failure modes sit either side of this, and both are real.
 *
 * A serial `for` loop is latency-bound: revoking 500 sessions took 4,502
 * round trips with never more than one in flight, which is roughly two and a
 * half seconds against a Redis with 0.5ms latency. "Sign out everywhere" is
 * precisely the operation invoked during an incident, and one that slow risks
 * timing out partway — leaving some sessions live and the caller unsure which.
 *
 * An unbounded `Promise.all` fixes the latency and introduces a worse problem:
 * a user with tens of thousands of sessions would issue that many commands at
 * once, exhausting the connection pool and starving every other request on the
 * process. A library should not be able to take an application down because
 * someone had a lot of sessions.
 *
 * A bounded pool gets the parallelism without the fan-out.
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * Default pool size.
 *
 * Chosen to be comfortably below a typical connection pool while still
 * collapsing hundreds of sequential round trips into a manageable number of
 * batches. Higher values buy little once latency stops being the bottleneck.
 */
export const DEFAULT_CONCURRENCY = 16;

/**
 * Applies `worker` to every item, with at most `limit` running at once.
 *
 * Results are returned in input order regardless of completion order, so
 * callers can pair them with their inputs.
 *
 * Rejections propagate. Callers that must not fail wholesale — session
 * revocation, for one, where one bad record should not abandon the rest —
 * should catch inside the worker and return a sentinel.
 */
export async function mapConcurrent<T, R>(
  items: readonly T[],
  worker: (item: T, index: number) => Promise<R>,
  limit: number = DEFAULT_CONCURRENCY,
): Promise<R[]> {
  if (items.length === 0) return [];

  const effective = Math.max(1, Math.min(limit, items.length));
  const results = new Array<R>(items.length);
  let next = 0;

  // Each runner pulls the next index until the queue is drained. Incrementing
  // `next` is safe without a lock: there is no await between the read and the
  // write, so no other runner can interleave.
  async function runner(): Promise<void> {
    for (;;) {
      const index = next;
      next += 1;
      if (index >= items.length) return;
      results[index] = await worker(items[index] as T, index);
    }
  }

  await Promise.all(Array.from({ length: effective }, () => runner()));
  return results;
}
