import { openDatabase } from './db.js';
import { createJwtSigner, createNinshoSide } from './auth.js';
import { createApp } from './app.js';

const port = Number(process.env.PORT) || 3100;
// Loopback by default. Set HOST=0.0.0.0 on purpose to show it to another device.
const host = process.env.HOST || '127.0.0.1';

const db = await openDatabase();
const ninsho = createNinshoSide();
if (!(await ninsho.auth.health())) {
  console.error(`Redis is not reachable at ${process.env.REDIS_URL}. Start it, then try again.`);
  process.exit(1);
}

const app = createApp({ db, jwt: createJwtSigner(), ninsho });
const server = app.listen(port, host, () => {
  console.log(`\nJWT vs Ninsho running at http://localhost:${port}`);
  console.log('  accounts: Postgres   ninsho sessions: Redis\n');
});

const shutdown = () => {
  server.close();
  void Promise.allSettled([ninsho.close(), db.close()]).then(() => process.exit(0));
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
