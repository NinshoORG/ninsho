import { describeKey, type DpopKey } from './keys.js';

/**
 * Where the DPoP key lives between page loads.
 *
 * ─── Why this is an interface, and why IndexedDB ──────────────────────────
 * A non-extractable `CryptoKey` can be structured-cloned into IndexedDB and
 * read back later, still non-extractable. That is the only browser storage
 * that can hold one: `localStorage` and `sessionStorage` take strings, so
 * using them would force `extractable: true` and hand any XSS the private key
 * — destroying the property the whole mechanism rests on.
 *
 * The interface exists so the choice is visible and testable, the same reason
 * `NinshoStore` is injected on the server. A React Native or Electron client
 * can supply its own without the library guessing.
 * ──────────────────────────────────────────────────────────────────────────
 */
export interface DpopKeyStore {
  /** Returns the stored key, or `null` if there is none. */
  load(): Promise<DpopKey | null>;
  /** Persists a key, replacing any existing one. */
  save(key: DpopKey): Promise<void>;
  /** Removes the stored key. Called on sign-out. */
  clear(): Promise<void>;
}

const DB_NAME = 'ninsho';
const DB_VERSION = 1;
const STORE_NAME = 'dpop-keys';
const RECORD_ID = 'current';

/** Promisifies an IDBRequest. */
function promisify<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = (): void => resolve(request.result);
    request.onerror = (): void => reject(request.error ?? new Error('IndexedDB request failed'));
  });
}

/**
 * The browser implementation. Holds the key pair as `CryptoKey` handles.
 *
 * SECURITY: only handles are stored. Even with full read access to the
 * database — through the devtools, or through script — the private key's bytes
 * are not there to be read.
 */
export class IndexedDbKeyStore implements DpopKeyStore {
  readonly #dbName: string;

  constructor(dbName: string = DB_NAME) {
    if (typeof indexedDB === 'undefined') {
      throw new Error(
        'ninsho: IndexedDB is not available. In a non-browser environment, ' +
          'supply your own DpopKeyStore — do not fall back to string storage, ' +
          'which would require an extractable key.',
      );
    }
    this.#dbName = dbName;
  }

  async #open(): Promise<IDBDatabase> {
    const request = indexedDB.open(this.#dbName, DB_VERSION);
    request.onupgradeneeded = (): void => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    return promisify(request);
  }

  async #transaction<T>(
    mode: IDBTransactionMode,
    run: (store: IDBObjectStore) => IDBRequest<T>,
  ): Promise<T> {
    const db = await this.#open();
    try {
      return await promisify(run(db.transaction(STORE_NAME, mode).objectStore(STORE_NAME)));
    } finally {
      db.close();
    }
  }

  async load(): Promise<DpopKey | null> {
    const record = await this.#transaction<unknown>('readonly', (store) =>
      store.get(RECORD_ID),
    );

    if (typeof record !== 'object' || record === null) return null;
    const { privateKey, publicKey } = record as {
      privateKey?: CryptoKey;
      publicKey?: CryptoKey;
    };
    if (privateKey === undefined || publicKey === undefined) return null;

    // A key that came back extractable was not created by this library, or was
    // tampered with. Refuse it rather than silently operating without the
    // property the caller believes they have.
    if (privateKey.extractable) {
      await this.clear();
      return null;
    }

    return describeKey(privateKey, publicKey);
  }

  async save(key: DpopKey): Promise<void> {
    await this.#transaction('readwrite', (store) =>
      store.put({ privateKey: key.privateKey, publicKey: key.publicKey }, RECORD_ID),
    );
  }

  async clear(): Promise<void> {
    await this.#transaction('readwrite', (store) => store.delete(RECORD_ID));
  }
}

/**
 * In-process key storage, for tests and for non-browser clients.
 *
 * Holds the same `CryptoKey` handles, so the non-extractable property is
 * preserved — this is a different persistence choice, not a weaker one. It
 * simply does not survive a restart.
 */
export class MemoryKeyStore implements DpopKeyStore {
  #key: DpopKey | null = null;

  async load(): Promise<DpopKey | null> {
    return this.#key;
  }

  async save(key: DpopKey): Promise<void> {
    this.#key = key;
  }

  async clear(): Promise<void> {
    this.#key = null;
  }
}
