/**
 * Runnable entry point.
 *
 *   npm run dev --workspace @ninshorg/example-express-api
 *
 * Set REDIS_URL to use Redis; without it the example runs on MemoryStore,
 * which refuses to start under NODE_ENV=production.
 */
import { createApp, createRedisStore } from './app.js';

const port = Number.parseInt(process.env['PORT'] ?? '3000', 10);
const redisUrl = process.env['REDIS_URL'];

const { app } = createApp({
  ...(redisUrl !== undefined && { store: createRedisStore(redisUrl) }),
  // Match this to your deployment: false when directly exposed, or the number
  // of proxies in front of this process.
  trustProxy: false,
});

app.listen(port, () => {
  console.log(`ninsho example listening on http://localhost:${port}`);
  console.log(`store: ${redisUrl === undefined ? 'MemoryStore (development only)' : 'Redis'}`);
});
