import { randomUUID } from 'node:crypto';
import type { Clock } from '../core/clock.ts';
import { systemClock } from '../core/clock.ts';
import type { AuditLog } from '../core/audit.ts';
import type { IncidentEngine, Incident, ImpactFacts } from '../core/incident.ts';
import type { HeartbeatMonitor } from '../runtime/heartbeat.ts';
import { TenantScope } from '../core/tenant.ts';
import type { Environment, RunStatus, Severity } from '../core/types.ts';
import type { AuthEvent, SecuritySignalReader } from '../integrations/business-ports.ts';

/**
 * Section 27 - Security Operations Agent.
 *
 * Section 27 is explicit that this must NOT pretend to be a SIEM. It does three
 * honest things: correlate the signals an adapter actually provides, classify
 * them by deterministic rules, and open an incident with a containment
 * RECOMMENDATION.
 *
 * It never contains anything itself. Every containment action worth taking -
 * firewall changes, credential rotation, blocking traffic - is P4 in the
 * catalogue and therefore unreachable by any agent. This agent's output is
 * evidence and a proposal; a human executes.
 */

export interface SecurityRun {
  readonly runId: string;
  readonly correlationId: string;
  readonly startedAt: number;
  endedAt?: number;
  status: RunStatus;
  eventsExamined: number;
  alertsExamined: number;
  incidentsOpened: number;
  errors: string[];
}

export interface SecurityConfig {
  /** Failed logins from one actor within the window before it is suspicious. */
  readonly failedLoginThreshold: number;
  /** Correlation window. */
  readonly windowMs: number;
  /** Distinct source countries for one actor before it is impossible travel. */
  readonly distinctCountryThreshold: number;
  readonly environment: Environment;
}

export const DEFAULT_SECURITY: SecurityConfig = {
  failedLoginThreshold: 5,
  windowMs: 15 * 60_000,
  distinctCountryThreshold: 2,
  environment: 'production',
};

/** A correlated pattern, derived by rules only. */
export interface Finding {
  readonly kind: 'brute_force' | 'impossible_travel' | 'privilege_spike' | 'external_alert';
  readonly actorId: string;
  readonly tenantId: string | null;
  readonly evidence: readonly string[];
  readonly severity: Severity;
  readonly recommendation: string;
  readonly dedupeKey: string;
}

export class SecurityAgent {
  readonly id = 'security' as const;

  #reader: SecuritySignalReader;
  #incidents: IncidentEngine;
  #audit: AuditLog;
  #heartbeat: HeartbeatMonitor;
  #clock: Clock;
  #config: SecurityConfig;
  #runs: SecurityRun[] = [];

  constructor(deps: {
    reader: SecuritySignalReader;
    incidents: IncidentEngine;
    audit: AuditLog;
    heartbeat: HeartbeatMonitor;
    clock?: Clock;
    config?: SecurityConfig;
  }) {
    this.#reader = deps.reader;
    this.#incidents = deps.incidents;
    this.#audit = deps.audit;
    this.#heartbeat = deps.heartbeat;
    this.#clock = deps.clock ?? systemClock;
    this.#config = deps.config ?? DEFAULT_SECURITY;
  }

  get runs(): readonly SecurityRun[] {
    return this.#runs;
  }

  /**
   * Section 28 - correlation by deterministic rules. Returns findings; opening
   * incidents is a separate step so the rules stay independently testable.
   */
  correlate(events: readonly AuthEvent[]): Finding[] {
    const findings: Finding[] = [];
    const byActor = new Map<string, AuthEvent[]>();
    for (const e of events) {
      const list = byActor.get(e.actorId) ?? [];
      list.push(e);
      byActor.set(e.actorId, list);
    }

    for (const [actorId, actorEvents] of byActor) {
      const tenantId = actorEvents[0]!.tenantId;

      // Repeated authentication failure.
      const failures = actorEvents.filter(
        (e) => e.kind === 'login_failure' || e.kind === 'mfa_failure',
      );
      if (failures.length >= this.#config.failedLoginThreshold) {
        const succeeded = actorEvents.some((e) => e.kind === 'login_success');
        findings.push({
          kind: 'brute_force',
          actorId,
          tenantId,
          evidence: [
            `${failures.length} failed authentications in ${this.#config.windowMs}ms`,
            `distinct source IPs: ${new Set(failures.map((f) => f.sourceIp)).size}`,
            succeeded ? 'a successful login followed the failures' : 'no successful login observed',
          ],
          // A success after repeated failure is materially worse: the attempt
          // may have worked. Rules, not a model, make that distinction.
          severity: succeeded ? 'CRITICAL' : 'HIGH',
          recommendation: succeeded
            ? 'Review the session, force re-authentication, and confirm with the account owner before any lockout.'
            : 'Consider rate limiting the source and notifying the account owner.',
          dedupeKey: `security:brute_force:${actorId}`,
        });
      }

      // Same actor authenticating from several countries inside the window.
      const countries = new Set(
        actorEvents.map((e) => e.country).filter((c): c is string => c !== null),
      );
      if (countries.size >= this.#config.distinctCountryThreshold) {
        findings.push({
          kind: 'impossible_travel',
          actorId,
          tenantId,
          evidence: [
            `authentications from ${countries.size} countries: ${[...countries].sort().join(', ')}`,
            `within ${this.#config.windowMs}ms`,
          ],
          severity: 'HIGH',
          recommendation:
            'Confirm with the account owner whether a VPN or travel explains this before treating it as compromise.',
          dedupeKey: `security:impossible_travel:${actorId}`,
        });
      }

      // Privileged operations by an actor that also failed authentication.
      const privileged = actorEvents.filter(
        (e) => e.kind === 'privilege_grant' || e.kind === 'admin_action',
      );
      if (privileged.length > 0 && failures.length > 0) {
        findings.push({
          kind: 'privilege_spike',
          actorId,
          tenantId,
          evidence: [
            `${privileged.length} privileged operations`,
            `${failures.length} authentication failures by the same actor in the window`,
          ],
          severity: 'HIGH',
          recommendation:
            'Review the privileged operations against the change record; revoke only after confirming they were not authorised.',
          dedupeKey: `security:privilege_spike:${actorId}`,
        });
      }
    }

    return findings;
  }

  #factsFor(finding: Finding): ImpactFacts {
    return {
      environment: this.#config.environment,
      affectedTenants: finding.tenantId ? 1 : 0,
      serviceCritical: true,
      durationMs: this.#config.windowMs,
      dataAtRisk: false,
      // This is the security agent: a confirmed security signal sets the flag
      // that makes computeSeverity() escalate, regardless of tenant count.
      securityRisk: true,
      slaBreached: false,
    };
  }

  /** One sweep: read signals, correlate, open security incidents. */
  async sweep(): Promise<SecurityRun> {
    const run: SecurityRun = {
      runId: randomUUID(),
      correlationId: `security-${randomUUID().slice(0, 8)}`,
      startedAt: this.#clock.now(),
      status: 'running',
      eventsExamined: 0,
      alertsExamined: 0,
      incidentsOpened: 0,
      errors: [],
    };
    this.#runs.push(run);
    const since = this.#clock.now() - this.#config.windowMs;

    let events: readonly AuthEvent[] = [];
    try {
      events = await this.#reader.listAuthEvents(since);
      run.eventsExamined = events.length;
    } catch (err) {
      run.errors.push(err instanceof Error ? err.message : String(err));
    }

    let alertFindings: Finding[] = [];
    try {
      const alerts = await this.#reader.listSecurityAlerts(since);
      run.alertsExamined = alerts.length;
      alertFindings = alerts.map((a) => ({
        kind: 'external_alert' as const,
        actorId: a.source,
        tenantId: a.tenantId,
        evidence: [`source=${a.source}`, a.detail],
        // Trust the reporter's severity when given, but never below MEDIUM:
        // an external tool bothered to raise it.
        severity: a.reportedSeverity ?? 'MEDIUM',
        recommendation: 'Triage against the source tool before acting.',
        dedupeKey: `security:alert:${a.id}`,
      }));
    } catch (err) {
      run.errors.push(err instanceof Error ? err.message : String(err));
    }

    if (run.errors.length > 0 && run.eventsExamined === 0 && run.alertsExamined === 0) {
      // Section 75 - a dead signal source must never read as "no threats".
      run.status = 'failed';
      run.endedAt = this.#clock.now();
      this.#audit.append({
        actorType: 'agent',
        actorId: this.id,
        tenantId: null,
        action: 'security.sweep',
        target: this.#reader.name,
        result: 'failed',
        reason: `signal source unreachable: ${run.errors.join('; ')}`,
        correlationId: run.correlationId,
        metadata: {},
      });
      this.#heartbeat.beat(this.id, 'error');
      return run;
    }

    for (const finding of [...this.correlate(events), ...alertFindings]) {
      const before = this.#incidents.open(TenantScope.internalScope()).length;
      const incident = this.#incidents.detect({
        dedupeKey: finding.dedupeKey,
        tenantId: finding.tenantId,
        category: 'security',
        title: `${finding.kind.replace(/_/g, ' ')} involving ${finding.actorId}`,
        owner: this.id,
        correlationId: run.correlationId,
        evidence: finding.evidence,
        facts: this.#factsFor(finding),
      });
      if (this.#incidents.open(TenantScope.internalScope()).length > before) {
        run.incidentsOpened++;
        // Section 27 - the agent recommends containment; it never contains.
        this.#incidents.transition(incident.id, 'confirmed', this.id, 'signal correlated');
        this.#incidents.transition(incident.id, 'investigating', this.id, 'gathering context');
        this.#incidents.transition(incident.id, 'recommendation', this.id, finding.recommendation);
        this.#incidents.attachAnalysis(incident.id, {
          probableCause: finding.kind,
          confidence: 'medium',
          recommendation: finding.recommendation,
        });
      }
    }

    run.status = run.errors.length > 0 ? 'partially_completed' : 'completed';
    run.endedAt = this.#clock.now();
    this.#heartbeat.beat(this.id, run.errors.length > 0 ? 'error' : 'ok');
    this.#audit.append({
      actorType: 'agent',
      actorId: this.id,
      tenantId: null,
      action: 'security.sweep',
      target: this.#reader.name,
      result: run.errors.length > 0 ? 'failed' : 'succeeded',
      reason: `${run.eventsExamined} events, ${run.alertsExamined} alerts`,
      correlationId: run.correlationId,
      metadata: { incidentsOpened: run.incidentsOpened },
    });
    return run;
  }

  openIncidents(): Incident[] {
    return this.#incidents
      .open(TenantScope.internalScope())
      .filter((i) => i.category === 'security');
  }
}
