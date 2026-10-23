import pg from 'pg';
import { randomBytes, scrypt, timingSafeEqual, type ScryptOptions } from 'node:crypto';

/**
 * Accounts live in Postgres and are shared by both sides of the page: the JWT
 * column and the Ninsho column sign in the *same* user, so any difference you
 * see comes from how the session is handled, not from who is signing in.
 *
 * Sessions are deliberately NOT stored here. The JWT side has no session
 * storage at all — that is the point of a stateless token — and Ninsho keeps
 * its sessions in Redis, where every key expires on its own.
 */

export interface User {
  readonly id: string;
  readonly email: string;
  readonly name: string;
  readonly createdAt: string;
}

export interface Database {
  readonly pool: pg.Pool;
  createUser(input: { email: string; name: string; password: string }): Promise<User | null>;
  checkPassword(email: unknown, password: unknown): Promise<User | null>;
  findUserById(id: string): Promise<User | null>;
  deleteUser(id: string): Promise<void>;
  close(): Promise<void>;
}

const TABLE = 'jvn_users';

/**
 * node-postgres treats `sslmode=require` as `verify-full` and warns that the
 * meaning will change. Spell out the behaviour it already has, so certificate
 * checking stays on and the warning goes away. `channel_binding=require` is a
 * libpq option that pg reads as `enableChannelBinding` instead.
 */
function connectionConfig(raw: string): pg.PoolConfig {
  const url = new URL(raw);
  const channelBinding = url.searchParams.get('channel_binding') === 'require';
  url.searchParams.delete('channel_binding');
  if (url.searchParams.get('sslmode') === 'require') url.searchParams.set('sslmode', 'verify-full');
  return { connectionString: url.toString(), enableChannelBinding: channelBinding, max: 5 } as pg.PoolConfig;
}

export async function openDatabase(databaseUrl = process.env.DATABASE_URL): Promise<Database> {
  if (!databaseUrl) throw new Error('DATABASE_URL is not set. Copy env.example to .env and fill it in.');
  const pool = new pg.Pool(connectionConfig(databaseUrl));

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ${TABLE} (
      id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
      email         text        NOT NULL UNIQUE,
      name          text        NOT NULL,
      password_hash text        NOT NULL,
      created_at    timestamptz NOT NULL DEFAULT now()
    )
  `);

  const toUser = (row: { id: string; email: string; name: string; created_at: Date }): User => ({
    id: row.id,
    email: row.email,
    name: row.name,
    createdAt: row.created_at.toISOString(),
  });

  return {
    pool,

    async createUser({ email, name, password }) {
      const hash = await hashPassword(password);
      const result = await pool.query(
        `INSERT INTO ${TABLE} (email, name, password_hash) VALUES ($1, $2, $3)
         ON CONFLICT (email) DO NOTHING
         RETURNING id, email, name, created_at`,
        [normaliseEmail(email), name.trim(), hash],
      );
      const row = result.rows[0];
      return row ? toUser(row) : null;
    },

    async checkPassword(email, password) {
      if (typeof email !== 'string' || typeof password !== 'string') return null;
      const result = await pool.query(
        `SELECT id, email, name, created_at, password_hash FROM ${TABLE} WHERE email = $1`,
        [normaliseEmail(email)],
      );
      const row = result.rows[0];
      // An unknown email still pays for one scrypt, so response time does not
      // reveal which addresses have accounts.
      const ok = await verifyPassword(password, row?.password_hash ?? DUMMY_HASH);
      return row && ok ? toUser(row) : null;
    },

    async findUserById(id) {
      const result = await pool.query(`SELECT id, email, name, created_at FROM ${TABLE} WHERE id = $1`, [id]);
      const row = result.rows[0];
      return row ? toUser(row) : null;
    },

    async deleteUser(id) {
      await pool.query(`DELETE FROM ${TABLE} WHERE id = $1`, [id]);
    },

    close: () => pool.end(),
  };
}

export function normaliseEmail(email: string): string {
  return email.trim().toLowerCase();
}

// ─── Passwords ────────────────────────────────────────────────────────────
// scrypt from node:crypto, so the demo needs no native bcrypt build. Stored as
// `scrypt$N$r$p$salt$hash`, which keeps the parameters next to the hash.

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 } as const;

function scryptAsync(password: string, salt: Buffer, keylen: number, options: ScryptOptions): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keylen, options, (err, key) => (err ? reject(err) : resolve(key)));
  });
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const { N, r, p, keylen } = SCRYPT;
  const key = await scryptAsync(password.normalize('NFKC'), salt, keylen, { N, r, p });
  return ['scrypt', N, r, p, salt.toString('base64'), key.toString('base64')].join('$');
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [scheme, n, r, p, saltB64, hashB64] = stored.split('$');
  if (scheme !== 'scrypt' || !saltB64 || !hashB64) return false;
  const expected = Buffer.from(hashB64, 'base64');
  const actual = await scryptAsync(password.normalize('NFKC'), Buffer.from(saltB64, 'base64'), expected.length, {
    N: Number(n),
    r: Number(r),
    p: Number(p),
  });
  return timingSafeEqual(actual, expected);
}

/** A real hash of a random password, compared against when the email is unknown. */
const DUMMY_HASH = await hashPassword(randomBytes(16).toString('hex'));
