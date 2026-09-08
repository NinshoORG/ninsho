import type { AuditSink, SecurityEvent } from '@ninshorg/core';

/**
 * Default sink: one JSON object per line on stdout, for collection by whatever
 * ships the process's logs.
 *
 * SECURITY: this writes exactly the fields declared on {@link SecurityEvent}
 * and nothing else. There is no spread of an arbitrary payload, so a caller
 * cannot accidentally route a raw token, a password, or a request body into
 * the log by attaching it to an event.
 */
export class ConsoleAuditSink implements AuditSink {
  emit(event: SecurityEvent): void {
    process.stdout.write(`${JSON.stringify({ level: 'security', ...event })}\n`);
  }
}

/** Discards every event. For tests that assert on behaviour rather than logs. */
export class NullAuditSink implements AuditSink {
  emit(): void {
    // intentionally empty
  }
}

/** Retains events in memory. For tests that assert an event was emitted. */
export class MemoryAuditSink implements AuditSink {
  readonly events: SecurityEvent[] = [];

  emit(event: SecurityEvent): void {
    this.events.push(event);
  }

  /** Every event of the given type, in emission order. */
  ofType(type: SecurityEvent['type']): SecurityEvent[] {
    return this.events.filter((e) => e.type === type);
  }

  clear(): void {
    this.events.length = 0;
  }
}

/**
 * Wraps a sink so a throwing implementation cannot fail an authentication.
 *
 * Auditing is best-effort by design. A misbehaving log transport must not be
 * able to deny service — but the failure is not swallowed silently either, or
 * a broken audit pipeline could go unnoticed for months, which is its own
 * security problem. It surfaces on stderr, once per process, so a persistently
 * broken sink is visible without flooding the logs it is failing to write.
 */
export function safeSink(sink: AuditSink): AuditSink {
  let warned = false;

  return {
    emit(event: SecurityEvent): void {
      try {
        sink.emit(event);
      } catch (error) {
        if (!warned) {
          warned = true;
          process.stderr.write(
            `${JSON.stringify({
              level: 'error',
              message: 'ninsho: audit sink threw; security events are being dropped',
              reason: error instanceof Error ? error.message : String(error),
              at: new Date().toISOString(),
            })}\n`,
          );
        }
      }
    },
  };
}
