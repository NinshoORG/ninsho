/**
 * Seeded mock accounts, products, and orders for SecureShop.
 *
 * NOTE: For demonstration purposes only. These accounts and passwords
 * are hardcoded fixtures with zero security value outside this local demo.
 */

import { createHash, timingSafeEqual } from 'node:crypto';

export interface DemoUser {
  readonly id: string;
  readonly email: string;
  readonly name: string;
  readonly role: 'admin' | 'customer';
  readonly avatar: string;
}

export interface DemoProduct {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly price: number;
  readonly stock: number;
  readonly category: string;
}

export interface DemoOrder {
  readonly id: string;
  readonly userId: string;
  readonly items: Array<{
    readonly productId: string;
    readonly productName: string;
    readonly quantity: number;
    readonly price: number;
  }>;
  readonly total: number;
  readonly status: 'processing' | 'shipped' | 'delivered';
  readonly tracking: string;
  readonly placedAt: string;
}

export const DEMO_USERS: Record<string, { user: DemoUser; demoPassword: string }> = {
  'alice@example.com': {
    user: {
      id: 'usr_alice_secureshop',
      email: 'alice@example.com',
      name: 'Alice Vance',
      role: 'admin',
      avatar: '👩‍💼',
    },
    // A fixture, not a hash: the demo never stores a real credential. The
    // comparison below is still constant-time so the demo models the habit.
    demoPassword: 'password123',
  },
  'bob@example.com': {
    user: {
      id: 'usr_bob_secureshop',
      email: 'bob@example.com',
      name: 'Bob Smith',
      role: 'customer',
      avatar: '👨‍💼',
    },
    // Password is "password123"
    demoPassword: 'password123',
  },
};

export const DEMO_PRODUCTS: DemoProduct[] = [
  {
    id: 'prod_01',
    name: 'Quantum-Resistant YubiKey 5C',
    description: 'Hardware authenticator supporting FIDO2/WebAuthn, U2F, and Ed25519.',
    price: 65,
    stock: 140,
    category: 'Hardware Token',
  },
  {
    id: 'prod_02',
    name: 'Nitrokey HSM 2 Micro',
    description: 'Hardware Security Module with USB-C for secure Ed25519 key custody.',
    price: 389,
    stock: 24,
    category: 'Crypto Hardware',
  },
  {
    id: 'prod_03',
    name: 'Trezor Safe 5 Enterprise',
    description: 'Hardware cold wallet and certified FIDO authenticator.',
    price: 169,
    stock: 58,
    category: 'Custody Module',
  },
  {
    id: 'prod_04',
    name: 'NFC Zero-Knowledge Smart Badge',
    description: 'Proximity access card with isolated secure element.',
    price: 45,
    stock: 210,
    category: 'Physical Security',
  },
];

export const DEMO_ORDERS: DemoOrder[] = [
  {
    id: 'ord_1001',
    userId: 'usr_alice_secureshop',
    items: [
      {
        productId: 'prod_01',
        productName: 'Quantum-Resistant YubiKey 5C',
        quantity: 2,
        price: 65,
      },
    ],
    total: 130,
    status: 'shipped',
    tracking: 'TRK-9921-USPS-EXPRESS',
    placedAt: '2026-10-12T14:22:00.000Z',
  },
  {
    id: 'ord_1004',
    userId: 'usr_alice_secureshop',
    items: [
      {
        productId: 'prod_02',
        productName: 'Nitrokey HSM 2 Micro',
        quantity: 1,
        price: 389,
      },
    ],
    total: 389,
    status: 'delivered',
    tracking: 'TRK-5501-FEDEX-PRIORITY',
    placedAt: '2026-10-08T09:15:00.000Z',
  },
  {
    id: 'ord_1002',
    userId: 'usr_bob_secureshop',
    items: [
      {
        productId: 'prod_03',
        productName: 'Trezor Safe 5 Enterprise',
        quantity: 1,
        price: 169,
      },
    ],
    total: 169,
    status: 'processing',
    tracking: 'TRK-1029-UPS-GROUND',
    placedAt: '2026-10-14T11:45:00.000Z',
  },
];

/**
 * Own-property lookup only. A plain index would resolve `__proto__` or
 * `constructor` to something on Object.prototype.
 */
function lookup(email: unknown): (typeof DEMO_USERS)[string] | undefined {
  if (typeof email !== 'string') return undefined;
  const key = email.toLowerCase().trim();
  return Object.hasOwn(DEMO_USERS, key) ? DEMO_USERS[key] : undefined;
}

function digest(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

export function findUserByEmail(email: unknown): DemoUser | null {
  return lookup(email)?.user ?? null;
}

/**
 * Request bodies are untyped, so both arguments are checked rather than
 * trusted: a JSON array or object for `email` must be a 401, not a 500.
 * Fixed-length digests make the comparison take the same time whatever the
 * guess, and an unknown email is compared against an empty string so it does
 * not return measurably earlier than a wrong password.
 */
export function verifyUserPassword(email: unknown, password: unknown): DemoUser | null {
  if (typeof password !== 'string') return null;
  const record = lookup(email);
  const matches = timingSafeEqual(digest(password), digest(record?.demoPassword ?? ''));
  return record !== undefined && matches ? record.user : null;
}

export function getOrdersForUser(userId: string): DemoOrder[] {
  return DEMO_ORDERS.filter((o) => o.userId === userId);
}
