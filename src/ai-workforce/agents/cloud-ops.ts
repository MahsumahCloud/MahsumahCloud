import { randomUUID } from 'node:crypto';
import type { Clock } from '../core/clock.ts';
import { systemClock } from '../core/clock.ts';
import type { AuditLog } from '../core/audit.ts';
import type { ActionExecutor } from '../core/executor.ts';
import type { ApprovalEngine } from '../core/approval.ts';
import type { IncidentEngine, Incident, ImpactFacts } from '../core/incident.ts';
import type { HeartbeatMonitor } from '../runtime/heartbeat.ts';
import { TenantScope } from '../core/tenant.ts';
import type { RunStatus } from '../core/types.ts';
import type {
  InfrastructureReader,
  InfrastructureWriter,
  Workload,
  WorkloadHealth,
} from '../integrations/ports.ts';

/**
 * Section 24 - Cloud Operations Agent.
 *
 * The agent's job is orchestration, not decision-making. It gathers facts from
 * an integration port, hands them to the deterministic incident engine, and
 * routes any proposed action through the executor - which applies policy,
 * approval, verification and audit. The agent itself has no authority: it
 * cannot bypass the executor, and every mutation it wants must be a declared
 * action in the catalogue.
 *
 * Section 12 boundary: nothing here calls an AI provider. Detection and
 * severity are rules. A model may later enrich an incident through
 * IncidentEngine.attachAnalysis(), which cannot alter severity or status.
 */

/** Section 10 - one execution of the agent. */
export interface AgentRun {
  readonly runId: string;
  readonly correlationId: string;
  readonly startedAt: number;
  endedAt?: number;
  status: RunStatus;
  workloadsChecked: number;
  incidentsOpened: number;
  approvalsRequested: number;
  actionsExecuted: number;
  errors: string[];
}

export interface CloudOpsConfig {
  /** Failed checks before a workload is treated as an incident. */
  readonly failureThreshold: number;
  /** How long an approval to restart stays valid. */
  readonly approvalTtlMs: number;
  /** Who approval requests are addressed to. */
  readonly requesterId: string;
}

export const DEFAULT_CLOUD_OPS: CloudOpsConfig = {
  failureThreshold: 3,
  approvalTtlMs: 30 * 60_000,
  requesterId: 'agent:cloud_ops',
};

export class CloudOpsAgent {
  readonly id = 'cloud_ops' as const;

  #reader: InfrastructureReader;
  #writer: InfrastructureWriter | null;
  #incidents: IncidentEngine;
  #executor: ActionExecutor;
  #approvals: ApprovalEngine;
  #audit: AuditLog;
  #heartbeat: HeartbeatMonitor;
  #clock: Clock;
  #config: CloudOpsConfig;
  #runs: AgentRun[] = [];

  constructor(deps: {
    reader: InfrastructureReader;
    /** Optional: a deployment may run read-only (gate 1) with no writer. */
    writer?: InfrastructureWriter | null;
    incidents: IncidentEngine;
    executor: ActionExecutor;
    approvals: ApprovalEngine;
    audit: AuditLog;
    heartbeat: HeartbeatMonitor;
    clock?: Clock;
    config?: CloudOpsConfig;
  }) {
    this.#reader = deps.reader;
    this.#writer = deps.writer ?? null;
    this.#incidents = deps.incidents;
    this.#executor = deps.executor;
    this.#approvals = deps.approvals;
    this.#audit = deps.audit;
    this.#heartbeat = deps.heartbeat;
    this.#clock = deps.clock ?? systemClock;
    this.#config = deps.config ?? DEFAULT_CLOUD_OPS;
  }

  get runs(): readonly AgentRun[] {
    return this.#runs;
  }

  get lastRun(): AgentRun | undefined {
    return this.#runs.at(-1);
  }

  /**
   * Turns an observation into the measurable facts severity is derived from.
   * Kept separate and pure so the mapping is reviewable and testable.
   */
  #factsFor(workload: Workload, health: WorkloadHealth): ImpactFacts {
    return {
      environment: workload.environment,
      // A workload with a tenant that is down is one affected customer.
      affectedTenants: workload.tenantId ? 1 : 0,
      serviceCritical: workload.critical,
      durationMs: health.inStateMs,
      // This agent observes availability, not data integrity or intrusion.
      // Claiming either without evidence would inflate severity dishonestly.
      dataAtRisk: false,
      securityRisk: false,
      slaBreached: false,
    };
  }

  #isUnhealthy(health: WorkloadHealth): boolean {
    return (
      health.state === 'unhealthy' ||
      health.state === 'stopped' ||
      health.consecutiveFailures >= this.#config.failureThreshold
    );
  }

  /**
   * One full sweep: observe -> detect -> incident -> recommend -> request
   * approval. Executing an approved restart is a separate call
   * (executeApprovedRestart) because approval is asynchronous by design.
   */
  async sweep(): Promise<AgentRun> {
    const run: AgentRun = {
      runId: randomUUID(),
      correlationId: `cloud_ops-${randomUUID().slice(0, 8)}`,
      startedAt: this.#clock.now(),
      status: 'running',
      workloadsChecked: 0,
      incidentsOpened: 0,
      approvalsRequested: 0,
      actionsExecuted: 0,
      errors: [],
    };
    this.#runs.push(run);

    let workloads: readonly Workload[];
    try {
      workloads = await this.#reader.listWorkloads();
    } catch (err) {
      // Section 75 - an integration failure must never read as "all healthy".
      const detail = err instanceof Error ? err.message : String(err);
      run.status = 'failed';
      run.endedAt = this.#clock.now();
      run.errors.push(detail);
      this.#audit.append({
        actorType: 'agent',
        actorId: this.id,
        tenantId: null,
        action: 'cloud_ops.sweep',
        target: this.#reader.name,
        result: 'failed',
        reason: `integration unreachable: ${detail}`,
        correlationId: run.correlationId,
        metadata: { integration: this.#reader.name },
      });
      this.#heartbeat.beat(this.id, 'error');
      return run;
    }

    for (const workload of workloads) {
      let health: WorkloadHealth;
      try {
        health = await this.#reader.getHealth(workload.id);
      } catch (err) {
        // One unreachable workload must not abort the whole sweep.
        run.errors.push(`${workload.id}: ${err instanceof Error ? err.message : String(err)}`);
        continue;
      }
      run.workloadsChecked++;

      if (!this.#isUnhealthy(health)) continue;

      const before = this.#incidents.open(TenantScope.internalScope()).length;
      const incident = this.#incidents.detect({
        dedupeKey: `workload:${workload.id}:unhealthy`,
        tenantId: workload.tenantId,
        category: 'availability',
        title: `${workload.name} is ${health.state}`,
        owner: this.id,
        correlationId: run.correlationId,
        evidence: [
          `state=${health.state}`,
          `consecutiveFailures=${health.consecutiveFailures}`,
          `inStateMs=${health.inStateMs}`,
          `host=${workload.host}`,
          health.cpuPercent === null ? 'cpu=unavailable' : `cpu=${health.cpuPercent}%`,
          health.memoryPercent === null ? 'memory=unavailable' : `memory=${health.memoryPercent}%`,
        ],
        facts: this.#factsFor(workload, health),
      });
      if (this.#incidents.open(TenantScope.internalScope()).length > before) run.incidentsOpened++;

      await this.#proposeRemediation(incident, workload, run);
    }

    run.status = run.errors.length > 0 ? 'partially_completed' : 'completed';
    run.endedAt = this.#clock.now();
    this.#heartbeat.beat(this.id, run.errors.length > 0 ? 'error' : 'ok');
    this.#audit.append({
      actorType: 'agent',
      actorId: this.id,
      tenantId: null,
      action: 'cloud_ops.sweep',
      target: this.#reader.name,
      result: run.errors.length > 0 ? 'failed' : 'succeeded',
      reason: `checked ${run.workloadsChecked} workloads`,
      correlationId: run.correlationId,
      metadata: {
        incidentsOpened: run.incidentsOpened,
        approvalsRequested: run.approvalsRequested,
        errors: run.errors.length,
      },
    });
    return run;
  }

  /**
   * Section 19 - records a concise operational justification and raises a
   * scoped approval. Restarting a worker is P3, so the agent may only ASK.
   */
  async #proposeRemediation(incident: Incident, workload: Workload, run: AgentRun): Promise<void> {
    if (incident.status !== 'detected') return; // already being handled
    if (!this.#writer) return; // read-only deployment: detect and report only

    this.#incidents.transition(incident.id, 'confirmed', this.id, 'unhealthy on observation');
    this.#incidents.transition(incident.id, 'investigating', this.id, 'collecting evidence');
    this.#incidents.transition(
      incident.id,
      'recommendation',
      this.id,
      'restart proposed as least-invasive remediation',
    );

    const approval = this.#approvals.request({
      action: 'cloud_ops.restart_worker',
      target: {
        resourceType: 'worker',
        resourceId: workload.id,
        tenantId: workload.tenantId,
        environment: workload.environment,
      },
      agent: this.id,
      requestedBy: this.#config.requesterId,
      reason: `${workload.name} is ${incident.title}`,
      evidence: incident.evidence,
      risk: incident.severity,
      predictedEffect: 'worker restarts and returns to healthy on two consecutive checks',
      rollback: 'worker may be stopped again; it is already unhealthy, so the prior state is not preferable',
      correlationId: run.correlationId,
      incidentId: incident.id,
      ttlMs: this.#config.approvalTtlMs,
    });
    run.approvalsRequested++;
    this.#incidents.transition(
      incident.id,
      'awaiting_approval',
      this.id,
      `approval ${approval.id} requested`,
    );
  }

  /**
   * Called once a human has approved. Routes through the executor, so policy,
   * approval scope, verification and audit all apply - the agent cannot skip
   * any of them.
   */
  async executeApprovedRestart(
    incidentId: string,
    workload: Workload,
    approvalId: string,
  ): Promise<{ ok: boolean; reason: string }> {
    const incident = this.#incidents.get(incidentId);
    if (!incident) return { ok: false, reason: 'incident not found' };

    const run = this.lastRun;
    const correlationId = run?.correlationId ?? `cloud_ops-${randomUUID().slice(0, 8)}`;

    this.#incidents.transition(incident.id, 'mitigating', this.id, 'executing approved restart');

    const result = await this.#executor.run(
      {
        action: 'cloud_ops.restart_worker',
        target: {
          resourceType: 'worker',
          resourceId: workload.id,
          tenantId: workload.tenantId,
          environment: workload.environment,
        },
        agent: this.id,
        runId: run?.runId ?? randomUUID(),
        correlationId,
        reason: incident.title,
        evidence: incident.evidence,
        approvalId,
      },
      TenantScope.internalScope(),
    );

    if (result.status !== 'succeeded') {
      // Section 58 - an unverified action leaves the incident open.
      this.#incidents.transition(
        incident.id,
        'investigating',
        this.id,
        `remediation did not succeed: ${result.reason}`,
      );
      return { ok: false, reason: result.reason };
    }

    if (run) run.actionsExecuted++;
    this.#incidents.transition(incident.id, 'verifying', this.id, 'restart verified by executor');
    this.#incidents.transition(incident.id, 'monitoring', this.id, 'watching for recurrence');
    return { ok: true, reason: result.reason };
  }

  /** Closes an incident once the workload has stayed healthy. */
  async confirmRecovery(incidentId: string, workloadId: string): Promise<boolean> {
    const incident = this.#incidents.get(incidentId);
    if (!incident || incident.status !== 'monitoring') return false;
    const health = await this.#reader.getHealth(workloadId);
    if (health.state !== 'running') return false;
    this.#incidents.transition(incident.id, 'resolved', this.id, 'healthy on re-observation');
    return true;
  }
}
