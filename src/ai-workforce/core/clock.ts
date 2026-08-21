/**
 * Injectable time source. §16 approval expiry and §46 heartbeat detection are
 * time-dependent controls, so time must be deterministic under test rather than
 * read from the ambient system clock.
 */
export interface Clock {
  now(): number;
}

export const systemClock: Clock = { now: () => Date.now() };

export class FixedClock implements Clock {
  #t: number;
  constructor(startMs: number) {
    this.#t = startMs;
  }
  now(): number {
    return this.#t;
  }
  advance(ms: number): void {
    this.#t += ms;
  }
}
