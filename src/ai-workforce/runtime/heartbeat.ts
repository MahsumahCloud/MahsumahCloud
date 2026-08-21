import type { Clock } from '../core/clock.ts';
import { systemClock } from '../core/clock.ts';
import type { AgentId, Severity } from '../core/types.ts';
import type { AuditLog } from '../core/audit.ts';

/**
 * Section 46 - Observability, and specifically: WHO MONITORS THE MONITOR?
 *
 * Each agent emits a heartbeat. A watchdog that is deliberately NOT an agent -
 * it has no policy, no LLM, no integrations, and cannot be disabled by the
 * per-agent kill switches - observes those heartbeats and reports staleness.
 *
 * The watchdog is intentionally trivial. Anything complicated enough to be
 * interesting is complicated enough to fail silently, which is the exact
 * failure it exists to catch.
 */

export type HealthState = 'healthy' | 'degraded' | 'stale' | 'never_started';

export interface Heartbeat {
  readonly agent: AgentId;
  lastBeatAt: number;
  lastRunStatus: 'ok' | 'error';
  consecutiveErrors: number;
  totalBeats: number;
}

export interface HealthReport {
  readonly agent: AgentId;
  readonly state: HealthState;
  readonly lastBeatAt: number | null;
  readonly ageMs: number | null;
  readonly consecutiveErrors: number;
  readonly severity: Severity;
  readonly detail: string;
}

export interface WatchdogConfig {
  /** How long an agent may go silent before it is considered stale. */
  readonly stalenessThresholdMs: number;
  /** Consecutive errored runs before the agent is considered degraded. */
  readonly errorThreshold: number;
}

export const DEFAULT_WATCHDOG: WatchdogConfig = {
  stalenessThresholdMs: 5 * 60_000,
  errorThreshold: 3,
};

export class HeartbeatMonitor {
  #beats = new Map<AgentId, Heartbeat>();
  #expected = new Set<AgentId>();
  #clock: Clock;
  #audit: AuditLog;
  #config: WatchdogConfig;
  /** Agents already reported unhealthy, so we alert on transition, not every sweep. */
  #alerted = new Set<AgentId>();

  constructor(audit: AuditLog, config: WatchdogConfig = DEFAULT_WATCHDOG, clock: Clock = systemClock) {
    this.#audit = audit;
    this.#config = config;
    this.#clock = clock;
  }

  /** Declares that an agent is supposed to be running. */
  expect(agent: AgentId): void {
    this.#expected.add(agent);
  }

  beat(agent: AgentId, status: 'ok' | 'error'): void {
    const existing = this.#beats.get(agent);
    const now = this.#clock.now();
    if (existing) {
      existing.lastBeatAt = now;
      existing.lastRunStatus = status;
      existing.consecutiveErrors = status === 'error' ? existing.consecutiveErrors + 1 : 0;
      existing.totalBeats++;
    } else {
      this.#beats.set(agent, {
        agent,
        lastBeatAt: now,
        lastRunStatus: status,
        consecutiveErrors: status === 'error' ? 1 : 0,
        totalBeats: 1,
      });
    }
  }

  report(agent: AgentId): HealthReport {
    const beat = this.#beats.get(agent);
    const now = this.#clock.now();

    if (!beat) {
      return {
        agent,
        state: 'never_started',
        lastBeatAt: null,
        ageMs: null,
        consecutiveErrors: 0,
        severity: 'HIGH',
        detail: 'agent has never reported a heartbeat',
      };
    }

    const ageMs = now - beat.lastBeatAt;
    if (ageMs > this.#config.stalenessThresholdMs) {
      return {
        agent,
        state: 'stale',
        lastBeatAt: beat.lastBeatAt,
        ageMs,
        consecutiveErrors: beat.consecutiveErrors,
        severity: 'HIGH',
        detail: `no heartbeat for ${ageMs}ms (threshold ${this.#config.stalenessThresholdMs}ms)`,
      };
    }

    if (beat.consecutiveErrors >= this.#config.errorThreshold) {
      return {
        agent,
        state: 'degraded',
        lastBeatAt: beat.lastBeatAt,
        ageMs,
        consecutiveErrors: beat.consecutiveErrors,
        severity: 'MEDIUM',
        detail: `${beat.consecutiveErrors} consecutive failed runs`,
      };
    }

    // Report the real error count even when it is below the threshold.
    // Hard-coding 0 here would tell an operator "no recent errors" while the
    // agent was in fact failing intermittently - the exact signal that
    // precedes a degraded agent, hidden at the moment it is most useful.
    return {
      agent,
      state: 'healthy',
      lastBeatAt: beat.lastBeatAt,
      ageMs,
      consecutiveErrors: beat.consecutiveErrors,
      severity: 'INFO',
      detail: beat.consecutiveErrors > 0 ? `ok, ${beat.consecutiveErrors} recent error(s)` : 'ok',
    };
  }

  /**
   * Checks every expected agent. Returns the unhealthy ones and audits each
   * transition into an unhealthy state exactly once (section 73: a stopped
   * agent must never fail silently).
   */
  sweep(): HealthReport[] {
    const unhealthy: HealthReport[] = [];
    for (const agent of this.#expected) {
      const report = this.report(agent);
      if (report.state === 'healthy') {
        if (this.#alerted.delete(agent)) {
          this.#audit.append({
            actorType: 'system',
            actorId: 'watchdog',
            tenantId: null,
            action: 'agent.health_recovered',
            target: agent,
            result: 'succeeded',
            reason: 'agent heartbeat recovered',
            correlationId: `watchdog-${agent}`,
            metadata: {},
          });
        }
        continue;
      }

      unhealthy.push(report);
      if (!this.#alerted.has(agent)) {
        this.#alerted.add(agent);
        this.#audit.append({
          actorType: 'system',
          actorId: 'watchdog',
          tenantId: null,
          action: 'agent.health_degraded',
          target: agent,
          result: 'failed',
          reason: report.detail,
          correlationId: `watchdog-${agent}`,
          metadata: { state: report.state, severity: report.severity },
        });
      }
    }
    return unhealthy;
  }

  all(): HealthReport[] {
    return [...this.#expected].map((a) => this.report(a));
  }
}
