import { createHash } from 'node:crypto';
import type { Clock } from './clock.ts';
import { systemClock } from './clock.ts';

/**
 * §18 — Audit architecture.
 *
 * Entries are append-only and hash-chained: each record commits to its
 * predecessor, so removal or edit of any historical entry is detectable by
 * re-walking the chain (§93 requires audit to be provably functioning, not
 * merely asserted).
 */
export interface AuditEntry {
  readonly seq: number;
  readonly timestamp: number;
  /** 'user' | 'agent' | 'system' */
  readonly actorType: 'user' | 'agent' | 'system';
  readonly actorId: string;
  readonly tenantId: string | null;
  readonly action: string;
  readonly target: string;
  readonly result: 'allowed' | 'denied' | 'succeeded' | 'failed' | 'blocked';
  readonly reason: string;
  readonly correlationId: string;
  readonly policy?: string;
  readonly approvalId?: string;
  readonly metadata: Record<string, unknown>;
  /** SHA-256 over the canonical form of this entry plus prevHash. */
  readonly hash: string;
  readonly prevHash: string;
}

export type AuditInput = Omit<AuditEntry, 'seq' | 'timestamp' | 'hash' | 'prevHash'>;

/**
 * §4/§18/§52 — secrets must never reach the audit log. Redaction is applied at
 * write time so a careless caller cannot persist a credential.
 */
const SECRET_KEY_PATTERN =
  /(pass(word)?|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|credential|authorization|cookie|session)/i;

export const REDACTED = '[REDACTED]';

export function redact(value: unknown, depth = 0): unknown {
  if (depth > 6) return '[TRUNCATED]';
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = SECRET_KEY_PATTERN.test(k) ? REDACTED : redact(v, depth + 1);
    }
    return out;
  }
  return value;
}

/** Stable serialisation so the hash does not depend on key insertion order. */
function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(',')}}`;
}

export const GENESIS_HASH = '0'.repeat(64);

export class AuditLog {
  #entries: AuditEntry[] = [];
  #clock: Clock;

  constructor(clock: Clock = systemClock) {
    this.#clock = clock;
  }

  append(input: AuditInput): AuditEntry {
    const prevHash = this.#entries.at(-1)?.hash ?? GENESIS_HASH;
    const seq = this.#entries.length;
    const base = {
      ...input,
      metadata: redact(input.metadata) as Record<string, unknown>,
      seq,
      timestamp: this.#clock.now(),
      prevHash,
    };
    const hash = createHash('sha256').update(canonical(base)).digest('hex');
    const entry: AuditEntry = Object.freeze({ ...base, hash });
    this.#entries.push(entry);
    return entry;
  }

  /** Re-walks the chain. Returns the first index that fails, or -1 if intact. */
  verifyChain(): number {
    let prevHash = GENESIS_HASH;
    for (let i = 0; i < this.#entries.length; i++) {
      const e = this.#entries[i]!;
      if (e.prevHash !== prevHash || e.seq !== i) return i;
      const { hash, ...base } = e;
      if (createHash('sha256').update(canonical(base)).digest('hex') !== hash) return i;
      prevHash = hash;
    }
    return -1;
  }

  get length(): number {
    return this.#entries.length;
  }

  all(): readonly AuditEntry[] {
    return this.#entries;
  }

  /** §18 — audit history must be searchable and filterable. */
  query(f: {
    actorId?: string;
    tenantId?: string | null;
    action?: string;
    result?: AuditEntry['result'];
    correlationId?: string;
    from?: number;
    to?: number;
  }): AuditEntry[] {
    return this.#entries.filter(
      (e) =>
        (f.actorId === undefined || e.actorId === f.actorId) &&
        (f.tenantId === undefined || e.tenantId === f.tenantId) &&
        (f.action === undefined || e.action === f.action) &&
        (f.result === undefined || e.result === f.result) &&
        (f.correlationId === undefined || e.correlationId === f.correlationId) &&
        (f.from === undefined || e.timestamp >= f.from) &&
        (f.to === undefined || e.timestamp <= f.to),
    );
  }

  /** Test-only seam used to prove tampering is detected. */
  __tamperForTest(index: number, patch: Partial<AuditEntry>): void {
    this.#entries[index] = { ...this.#entries[index]!, ...patch } as AuditEntry;
  }
}
