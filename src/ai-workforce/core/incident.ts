import { randomUUID } from 'node:crypto';
import type { Clock } from './clock.ts';
import { systemClock } from './clock.ts';
import type { AgentId, Environment, Severity } from './types.ts';
import type { AuditLog } from './audit.ts';
import type { TenantScope } from './tenant.ts';

/**
 * Sections 25/26 - Incident engine and severity.
 *
 * Severity is computed by deterministic rules, never by a model (section 12:
 * "Never make basic infrastructure monitoring dependent on an LLM"). An AI may
 * later attach a probable cause and a recommendation to an incident, but it
 * cannot change how urgent the incident is.
 */

/** Section 25 - incident lifecycle. */
export type IncidentStatus =
  | 'detected'
  | 'confirmed'
  | 'investigating'
  | 'recommendation'
  | 'awaiting_approval'
  | 'mitigating'
  | 'verifying'
  | 'monitoring'
  | 'resolved';

/** Legal forward transitions. Anything else is rejected. */
const TRANSITIONS: Record<IncidentStatus, readonly IncidentStatus[]> = {
  detected: ['confirmed', 'resolved'],
  confirmed: ['investigating', 'resolved'],
  investigating: ['recommendation', 'monitoring', 'resolved'],
  recommendation: ['awaiting_approval', 'mitigating', 'monitoring'],
  awaiting_approval: ['mitigating', 'monitoring', 'resolved'],
  mitigating: ['verifying', 'investigating'],
  verifying: ['monitoring', 'investigating'],
  monitoring: ['resolved', 'investigating'],
  resolved: [],
};

/** The measurable facts severity is derived from. All deterministic. */
export interface ImpactFacts {
  readonly environment: Environment;
  /** Distinct customers observably affected. */
  readonly affectedTenants: number;
  /** Is the affected service on the critical path for customers? */
  readonly serviceCritical: boolean;
  /** How long the condition has persisted. */
  readonly durationMs: number;
  /** Risk of data loss or corruption. */
  readonly dataAtRisk: boolean;
  /** Confirmed or suspected security compromise. */
  readonly securityRisk: boolean;
  /** An SLA commitment is already breached or imminently will be. */
  readonly slaBreached: boolean;
}

const HOUR = 3_600_000;

/**
 * Section 26 - deterministic severity.
 *
 * Data and security risk dominate: either forces at least HIGH regardless of
 * how few customers are affected, because blast radius is not yet known when
 * they are detected. Non-production caps at MEDIUM unless data is at risk, so
 * staging noise cannot page anyone at 3am.
 */
export function computeSeverity(f: ImpactFacts): Severity {
  if (f.dataAtRisk) return f.affectedTenants > 0 ? 'CRITICAL' : 'HIGH';
  if (f.securityRisk) return f.environment === 'production' ? 'CRITICAL' : 'HIGH';

  if (f.environment !== 'production') {
    // A broken staging pipeline matters, but never more than MEDIUM.
    return f.serviceCritical && f.durationMs >= HOUR ? 'MEDIUM' : 'LOW';
  }

  if (f.affectedTenants === 0) {
    // Production, but no observed customer impact yet.
    return f.serviceCritical ? 'MEDIUM' : 'LOW';
  }

  let score = 0;
  score += f.affectedTenants >= 10 ? 3 : f.affectedTenants >= 3 ? 2 : 1;
  if (f.serviceCritical) score += 2;
  if (f.slaBreached) score += 2;
  if (f.durationMs >= 4 * HOUR) score += 2;
  else if (f.durationMs >= HOUR) score += 1;

  if (score >= 7) return 'CRITICAL';
  if (score >= 5) return 'HIGH';
  if (score >= 3) return 'MEDIUM';
  return 'LOW';
}

export interface IncidentEvent {
  readonly at: number;
  readonly status: IncidentStatus;
  readonly note: string;
  readonly actor: string;
}

export interface Incident {
  readonly id: string;
  readonly tenantId: string | null;
  readonly environment: Environment;
  readonly category: string;
  readonly title: string;
  readonly owner: AgentId;
  readonly correlationId: string;
  /** Deterministic detection evidence. Never model output. */
  readonly evidence: readonly string[];
  readonly facts: ImpactFacts;
  severity: Severity;
  status: IncidentStatus;
  /** Optional AI contribution - advisory only, never drives severity. */
  probableCause?: string;
  confidence?: 'low' | 'medium' | 'high';
  recommendation?: string;
  readonly detectedAt: number;
  resolvedAt?: number;
  readonly timeline: IncidentEvent[];
  /** Deduplication key: same condition on same target must not re-open. */
  readonly dedupeKey: string;
}

export class IncidentEngine {
  #byId = new Map<string, Incident>();
  #openByDedupe = new Map<string, string>();
  #clock: Clock;
  #audit: AuditLog;

  constructor(audit: AuditLog, clock: Clock = systemClock) {
    this.#audit = audit;
    this.#clock = clock;
  }

  /**
   * Section 57 - a repeated signal for an already-open incident updates it
   * rather than creating a duplicate.
   */
  detect(input: {
    dedupeKey: string;
    tenantId: string | null;
    category: string;
    title: string;
    owner: AgentId;
    correlationId: string;
    evidence: readonly string[];
    facts: ImpactFacts;
  }): Incident {
    const existing = this.#openByDedupe.get(input.dedupeKey);
    if (existing) {
      const incident = this.#byId.get(existing)!;
      // Re-evaluate severity: a condition that persists usually escalates.
      const next = computeSeverity(input.facts);
      if (next !== incident.severity) {
        const from = incident.severity;
        incident.severity = next;
        incident.timeline.push({
          at: this.#clock.now(),
          status: incident.status,
          note: `severity ${from} -> ${next}`,
          actor: input.owner,
        });
        this.#audit.append({
          actorType: 'system',
          actorId: input.owner,
          tenantId: input.tenantId,
          action: 'incident.severity_changed',
          target: incident.id,
          result: 'succeeded',
          reason: `severity ${from} -> ${next}`,
          correlationId: input.correlationId,
          metadata: { from, to: next },
        });
      }
      return incident;
    }

    const now = this.#clock.now();
    const incident: Incident = {
      id: randomUUID(),
      tenantId: input.tenantId,
      environment: input.facts.environment,
      category: input.category,
      title: input.title,
      owner: input.owner,
      correlationId: input.correlationId,
      evidence: input.evidence,
      facts: input.facts,
      severity: computeSeverity(input.facts),
      status: 'detected',
      detectedAt: now,
      timeline: [{ at: now, status: 'detected', note: 'detected', actor: input.owner }],
      dedupeKey: input.dedupeKey,
    };
    this.#byId.set(incident.id, incident);
    this.#openByDedupe.set(input.dedupeKey, incident.id);
    this.#audit.append({
      actorType: 'system',
      actorId: input.owner,
      tenantId: input.tenantId,
      action: 'incident.detected',
      target: incident.id,
      result: 'succeeded',
      reason: input.title,
      correlationId: input.correlationId,
      metadata: { severity: incident.severity, category: input.category, evidence: input.evidence },
    });
    return incident;
  }

  /** Advances the lifecycle, rejecting illegal transitions. */
  transition(id: string, to: IncidentStatus, actor: string, note: string): Incident {
    const incident = this.#byId.get(id);
    if (!incident) throw new Error(`incident not found: ${id}`);
    if (!TRANSITIONS[incident.status].includes(to)) {
      throw new Error(`illegal incident transition: ${incident.status} -> ${to}`);
    }
    incident.status = to;
    incident.timeline.push({ at: this.#clock.now(), status: to, note, actor });
    if (to === 'resolved') {
      incident.resolvedAt = this.#clock.now();
      this.#openByDedupe.delete(incident.dedupeKey);
    }
    this.#audit.append({
      actorType: actor.includes(':') ? 'user' : 'agent',
      actorId: actor,
      tenantId: incident.tenantId,
      action: 'incident.transition',
      target: incident.id,
      result: 'succeeded',
      reason: note,
      correlationId: incident.correlationId,
      metadata: { to },
    });
    return incident;
  }

  /**
   * Attaches AI analysis. Deliberately cannot change severity or status -
   * section 12 keeps the model advisory.
   */
  attachAnalysis(
    id: string,
    analysis: { probableCause: string; confidence: 'low' | 'medium' | 'high'; recommendation: string },
  ): Incident {
    const incident = this.#byId.get(id);
    if (!incident) throw new Error(`incident not found: ${id}`);
    incident.probableCause = analysis.probableCause;
    incident.confidence = analysis.confidence;
    incident.recommendation = analysis.recommendation;
    return incident;
  }

  get(id: string): Incident | undefined {
    return this.#byId.get(id);
  }

  /** Section 7 - listing is tenant scoped. */
  list(scope: TenantScope, filter: { status?: IncidentStatus; severity?: Severity } = {}): Incident[] {
    return [...this.#byId.values()]
      .filter((i) => scope.canAccess(i.tenantId))
      .filter((i) => filter.status === undefined || i.status === filter.status)
      .filter((i) => filter.severity === undefined || i.severity === filter.severity);
  }

  open(scope: TenantScope): Incident[] {
    return this.list(scope).filter((i) => i.status !== 'resolved');
  }

  /** Section 47 - MTTR over resolved incidents, or null when there are none. */
  meanTimeToResolveMs(scope: TenantScope): number | null {
    const resolved = this.list(scope).filter((i) => i.resolvedAt !== undefined);
    if (resolved.length === 0) return null;
    const total = resolved.reduce((sum, i) => sum + (i.resolvedAt! - i.detectedAt), 0);
    return Math.round(total / resolved.length);
  }
}
