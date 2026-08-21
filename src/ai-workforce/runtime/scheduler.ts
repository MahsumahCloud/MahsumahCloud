import type { Clock } from '../core/clock.ts';
import { systemClock } from '../core/clock.ts';
import type { AuditLog } from '../core/audit.ts';

/**
 * Section 9 - periodic execution.
 *
 * A deterministic scheduler with no wall-clock dependency of its own: it is
 * driven by an injected Clock and an explicit tick(), so the whole schedule is
 * testable without waiting in real time.
 *
 * In production one process calls tick() on a timer. The scheduler owns WHAT is
 * due; the host owns WHEN to ask. That split is what makes section 95 Q1
 * ("do agents keep running when the laptop closes?") a deployment question
 * rather than a code question - see docs/ai-workforce/14-deployment.md.
 */

export interface ScheduledJob {
  readonly name: string;
  readonly intervalMs: number;
  /** Returns nothing; failures are caught and surfaced, never thrown upward. */
  readonly run: () => Promise<void>;
  /** Skip a run if the previous one is still going (section 11 concurrency). */
  readonly singleFlight?: boolean;
}

interface JobState {
  readonly job: ScheduledJob;
  nextDueAt: number;
  running: boolean;
  runs: number;
  failures: number;
  lastError?: string;
  lastRunAt?: number;
  skipped: number;
}

export interface TickSummary {
  readonly ran: string[];
  readonly failed: string[];
  readonly skipped: string[];
}

export class Scheduler {
  #jobs = new Map<string, JobState>();
  #clock: Clock;
  #audit: AuditLog;
  #started = false;

  constructor(audit: AuditLog, clock: Clock = systemClock) {
    this.#audit = audit;
    this.#clock = clock;
  }

  register(job: ScheduledJob): void {
    if (this.#jobs.has(job.name)) throw new Error(`job already registered: ${job.name}`);
    if (job.intervalMs <= 0) throw new Error(`job ${job.name} needs a positive interval`);
    this.#jobs.set(job.name, {
      job,
      // First run is due immediately on the first tick after start().
      nextDueAt: this.#clock.now(),
      running: false,
      runs: 0,
      failures: 0,
      skipped: 0,
    });
  }

  start(): void {
    this.#started = true;
    const now = this.#clock.now();
    for (const state of this.#jobs.values()) state.nextDueAt = now;
  }

  stop(): void {
    this.#started = false;
  }

  /**
   * Runs every job whose time has come. Due jobs run concurrently with each
   * other; a single job never overlaps itself when singleFlight is set.
   *
   * Catch-up is deliberately NOT cumulative: if the process was asleep for an
   * hour, a 5-minute job runs once, not twelve times. Replaying a backlog of
   * monitoring sweeps is noise, and for mutating jobs it would multiply blast
   * radius (section 79).
   */
  async tick(): Promise<TickSummary> {
    if (!this.#started) return { ran: [], failed: [], skipped: [] };

    const now = this.#clock.now();
    const ran: string[] = [];
    const failed: string[] = [];
    const skipped: string[] = [];
    const pending: Promise<void>[] = [];

    for (const state of this.#jobs.values()) {
      if (state.nextDueAt > now) continue;

      if (state.running && state.job.singleFlight) {
        state.skipped++;
        skipped.push(state.job.name);
        continue;
      }

      // Schedule the next run from now, so a slow job cannot build a backlog.
      state.nextDueAt = now + state.job.intervalMs;
      state.running = true;
      state.lastRunAt = now;

      pending.push(
        state.job
          .run()
          .then(() => {
            state.runs++;
            ran.push(state.job.name);
          })
          .catch((err: unknown) => {
            state.runs++;
            state.failures++;
            state.lastError = err instanceof Error ? err.message : String(err);
            failed.push(state.job.name);
            // Section 57 - no silent failures.
            this.#audit.append({
              actorType: 'system',
              actorId: 'scheduler',
              tenantId: null,
              action: 'scheduler.job_failed',
              target: state.job.name,
              result: 'failed',
              reason: state.lastError,
              correlationId: `scheduler-${state.job.name}`,
              metadata: { runs: state.runs, failures: state.failures },
            });
          })
          .finally(() => {
            state.running = false;
          }),
      );
    }

    await Promise.all(pending);
    return { ran, failed, skipped };
  }

  stats(name: string): { runs: number; failures: number; skipped: number; lastError?: string } {
    const state = this.#jobs.get(name);
    if (!state) throw new Error(`job not found: ${name}`);
    return {
      runs: state.runs,
      failures: state.failures,
      skipped: state.skipped,
      lastError: state.lastError,
    };
  }

  get jobNames(): string[] {
    return [...this.#jobs.keys()];
  }

  get running(): boolean {
    return this.#started;
  }
}
