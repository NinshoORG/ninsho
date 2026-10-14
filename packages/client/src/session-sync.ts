/** Internal, credential-free invalidation transport. Not an authorization input. */
type EventType = 'logout' | 'identity-change';
interface Notice {
  readonly version: 1;
  readonly context: string;
  readonly type: EventType;
  readonly id: string;
}

export class SessionSync {
  readonly #context: string;
  #channel: BroadcastChannel | null = null;
  // Bounded duplicate suppression, not a durable replay/security boundary.
  readonly #seen = new Set<string>();

  constructor(context: string, invalidate: () => void) {
    if (typeof context !== 'string' || context.trim().length === 0 || context.length > 128) {
      throw new Error('ninsho: sessionSync.context must be a nonempty string of at most 128 characters');
    }
    this.#context = context;
    if (typeof globalThis.BroadcastChannel !== 'function') return;
    try {
      this.#channel = new BroadcastChannel(`ninsho:session:v1:${context}`);
      this.#channel.onmessage = (event: MessageEvent<unknown>): void => {
        const data = event.data;
        if (typeof data !== 'object' || data === null || Array.isArray(data)) return;
        const message = data as Partial<Notice>;
        if (Object.keys(data).length !== 4 || message.version !== 1 || message.context !== context ||
            (message.type !== 'logout' && message.type !== 'identity-change') ||
            typeof message.id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(message.id)) return;
        if (this.#seen.has(message.id)) return;
        this.#remember(message.id);
        invalidate();
      };
    } catch {
      // Some hosts expose the API but deny construction. Authentication still
      // works locally; delivery is best-effort, as when the API is absent.
      this.close();
    }
  }

  #remember(id: string): void {
    this.#seen.add(id);
    if (this.#seen.size > 128) {
      const first = this.#seen.values().next().value;
      if (first !== undefined) this.#seen.delete(first);
    }
  }

  publish(type: EventType): void {
    if (this.#channel === null) return;
    try {
      const message: Notice = { version: 1, context: this.#context, type, id: crypto.randomUUID() };
      this.#remember(message.id);
      this.#channel.postMessage(message);
    } catch {
      // Transport failure cannot change the outcome of a server operation.
    }
  }

  close(): void {
    if (this.#channel !== null) {
      this.#channel.onmessage = null;
      this.#channel.close();
      this.#channel = null;
    }
    this.#seen.clear();
  }
}
