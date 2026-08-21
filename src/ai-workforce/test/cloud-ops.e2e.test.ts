import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { AuditLog } from '../core/audit.ts';
import { FixedClock } from '../core/clock.ts';
import { KillSwitchRegistry } from '../core/killswitch.ts';
import { TenantScope } from '../core/tenant.ts';
import { PolicyEngine } from '../core/policy.ts';
import { ApprovalEngine } from '../core/approval.ts';
import type { ApproverDirectory } from '../core/approval.ts';
import { ActionExecutor } from '../core/executor.ts';
import { IncidentEngine } from '../core/incident.ts';
import { HeartbeatMonitor } from '../runtime/heartbeat.ts';
import { buildActionRegistry } from '../actions/registry.ts';
import { PermissionLevel, defaultLaunchAutonomy } from '../core/types.ts';
import { CloudOpsAgent } from '../agents/cloud-ops.ts';
import type {
  InfrastructureReader,
  InfrastructureWriter,
  Workload,
  WorkloadHealth,
} from '../integrations/ports.ts';

/**
 * Section 68 - Cloud Ops end-to-end test.
 *
 * The infrastructure provider below is a TEST DOUBLE, confined to this test
 * file. It is not an adapter and ships nowhere near production (section 64
 * permits fixtures only in test/dev and requires them to be clearly isolated).
 * Everything it feeds - the incident engine, policy, approvals, executor,
 * audit - is the real implementation.
 */

const T0 = 1_700_000_000_000;
const MIN = 60_000;

const WORKLOAD: Workload = {
  id: 'wl-42',
  name: 'api-worker',
  tenantId: 'tenant-a',
  environment: 'staging',
  critical: true,
  host: 'node-3',
};

/** Controllable stand-in for a real provider. */
class FakeInfrastructure implements InfrastructureReader, InfrastructureWriter {
  readonly name = 'fake-provider';
  #health: WorkloadHealth;
  #workloads: Workload[];
  restartCalls = 0;
  /** When true, the restart call succeeds but the workload stays unhealthy. */
  restartIsIneffective = false;
  listShouldThrow = false;

  constructor(workloads: Workload[], initial: Partial<WorkloadHealth> = {}) {
    this.#workloads = workloads;
    this.#health = {
      workloadId: workloads[0]!.id,
      state: 'unhealthy',
      consecutiveFailures: 3,
      inStateMs: 4 * MIN,
      cpuPercent: 12,
      memoryPercent: 40,
      checkedAt: T0,
      ...initial,
    };
  }

  async listWorkloads(): Promise<readonly Workload[]> {
    if (this.listShouldThrow) throw new Error('provider timeout after 30s');
    return this.#workloads;
  }

  async getHealth(): Promise<WorkloadHealth> {
    return this.#health;
  }

  async restartWorkload(): Promise<{ operationId: string }> {
    this.restartCalls++;
    if (!this.restartIsIneffective) {
      this.#health = { ...this.#health, state: 'running', consecutiveFailures: 0 };
    }
    return { operationId: `op-${this.restartCalls}` };
  }

  async probeHealth(): Promise<WorkloadHealth> {
    return this.#health;
  }
}

const approvers: ApproverDirectory = { canApprove: (userId) => userId === 'ahmed' };

function harness(opts: { readOnly?: boolean; workloads?: Workload[] } = {}) {
  const clock = new FixedClock(T0);
  const audit = new AuditLog(clock);
  const kill = new KillSwitchRegistry(audit);
  const registry = buildActionRegistry();
  const policy = new PolicyEngine(registry, kill, audit, defaultLaunchAutonomy(), clock);
  const approvals = new ApprovalEngine(audit, approvers, clock);
  const executor = new ActionExecutor(registry, policy, approvals, audit);
  const incidents = new IncidentEngine(audit, clock);
  const heartbeat = new HeartbeatMonitor(audit, undefined, clock);
  const provider = new FakeInfrastructure(opts.workloads ?? [WORKLOAD]);

  // The handler is where section 58 verification lives: it re-observes the
  // workload rather than trusting the restart call's return value.
  executor.registerHandler('cloud_ops.restart_worker', {
    async execute() {
      return provider.restartWorkload();
    },
    async verify() {
      const health = await provider.probeHealth();
      return health.state === 'running';
    },
  });

  heartbeat.expect('cloud_ops');
  const agent = new CloudOpsAgent({
    reader: provider,
    writer: opts.readOnly ? null : provider,
    incidents,
    executor,
    approvals,
    audit,
    heartbeat,
    clock,
  });

  return { clock, audit, kill, policy, approvals, executor, incidents, heartbeat, provider, agent };
}

// ---------------------------------------------------------------------------
describe('Section 68 - Cloud Ops end-to-end', () => {
  test('the full chain runs: detect -> incident -> approval -> verified action -> resolved', async () => {
    const h = harness();
    const internal = TenantScope.internalScope();

    // 1. Sweep detects the unhealthy workload and opens an incident.
    const run = await h.agent.sweep();
    assert.equal(run.status, 'completed');
    assert.equal(run.workloadsChecked, 1);
    assert.equal(run.incidentsOpened, 1);
    assert.equal(run.approvalsRequested, 1);

    const [incident] = h.incidents.open(internal);
    assert.ok(incident);
    assert.equal(incident.status, 'awaiting_approval');
    // Staging, critical, but only 4 minutes in state: below the one-hour bar,
    // so section 26 keeps it LOW. Staging never pages anyone on its own.
    assert.equal(incident.severity, 'LOW');
    assert.ok(incident.evidence.some((e) => e.startsWith('consecutiveFailures=3')));

    // 2. Nothing has been mutated yet - P3 requires a human.
    assert.equal(h.provider.restartCalls, 0);

    // 3. A human approves the exact scoped request.
    const [pending] = h.approvals.pending();
    assert.ok(pending);
    assert.equal(pending.action, 'cloud_ops.restart_worker');
    assert.equal(pending.target.resourceId, 'wl-42');
    h.approvals.approve(pending.id, 'ahmed', 'confirmed by on-call');

    // 4. The agent executes through the executor, which verifies the result.
    const result = await h.agent.executeApprovedRestart(incident.id, WORKLOAD, pending.id);
    assert.equal(result.ok, true);
    assert.equal(h.provider.restartCalls, 1);
    assert.equal(h.incidents.get(incident.id)!.status, 'monitoring');

    // 5. Recovery confirmed, incident resolved.
    h.clock.advance(5 * MIN);
    assert.equal(await h.agent.confirmRecovery(incident.id, WORKLOAD.id), true);
    assert.equal(h.incidents.get(incident.id)!.status, 'resolved');
    assert.equal(h.incidents.open(internal).length, 0);

    // 6. The whole chain is auditable and the log is intact.
    assert.equal(h.audit.verifyChain(), -1);
    const byCorrelation = h.audit.query({ correlationId: run.correlationId });
    assert.ok(byCorrelation.length >= 4, 'sweep, approval request, decision and action all audited');
    assert.ok(byCorrelation.some((e) => e.action === 'cloud_ops.restart_worker' && e.result === 'succeeded'));
    assert.ok(byCorrelation.some((e) => e.action === 'incident.detected'));

    // 7. Section 95 Q7 - who approved is recoverable.
    assert.equal(h.approvals.get(pending.id)!.decidedBy, 'ahmed');
  });

  test('without approval the agent never mutates anything', async () => {
    const h = harness();
    await h.agent.sweep();
    const [incident] = h.incidents.open(TenantScope.internalScope());
    const [pending] = h.approvals.pending();

    // Try to execute while the approval is still pending.
    const result = await h.agent.executeApprovedRestart(incident!.id, WORKLOAD, pending!.id);
    assert.equal(result.ok, false);
    assert.equal(h.provider.restartCalls, 0, 'no mutation without a granted approval');
    assert.equal(h.incidents.get(incident!.id)!.status, 'investigating', 'incident stays open');
  });

  test('an ineffective restart is reported as failure, not success', async () => {
    const h = harness();
    h.provider.restartIsIneffective = true;

    await h.agent.sweep();
    const [incident] = h.incidents.open(TenantScope.internalScope());
    const [pending] = h.approvals.pending();
    h.approvals.approve(pending!.id, 'ahmed');

    const result = await h.agent.executeApprovedRestart(incident!.id, WORKLOAD, pending!.id);

    assert.equal(h.provider.restartCalls, 1, 'the call was made');
    assert.equal(result.ok, false, 'but the target state was not reached');
    assert.match(result.reason, /did not reach the intended state/);
    assert.equal(
      h.incidents.get(incident!.id)!.status,
      'investigating',
      'section 58 - the incident must stay open when verification fails',
    );
    assert.ok(h.audit.query({ result: 'failed' }).length > 0);
  });

  test('a read-only deployment detects and reports but never proposes mutation', async () => {
    const h = harness({ readOnly: true });
    const run = await h.agent.sweep();

    assert.equal(run.incidentsOpened, 1);
    assert.equal(run.approvalsRequested, 0, 'no writer means no restart proposal');
    assert.equal(h.approvals.pending().length, 0);
    assert.equal(h.incidents.open(TenantScope.internalScope())[0]!.status, 'detected');
    assert.equal(h.provider.restartCalls, 0);
  });

  test('an unreachable integration fails loudly and never reports healthy', async () => {
    const h = harness();
    h.provider.listShouldThrow = true;

    const run = await h.agent.sweep();

    assert.equal(run.status, 'failed');
    assert.equal(run.workloadsChecked, 0);
    assert.equal(h.incidents.open(TenantScope.internalScope()).length, 0);
    // Section 75 - the failure is explicit in the audit trail.
    const failures = h.audit.query({ action: 'cloud_ops.sweep', result: 'failed' });
    assert.equal(failures.length, 1);
    assert.match(failures[0]!.reason, /integration unreachable/);
    // Section 73 - and the agent's health reflects it.
    assert.equal(h.heartbeat.report('cloud_ops').consecutiveErrors, 1);
  });

  test('the kill switch stops the agent mid-flight', async () => {
    const h = harness();
    await h.agent.sweep();
    const [incident] = h.incidents.open(TenantScope.internalScope());
    const [pending] = h.approvals.pending();
    h.approvals.approve(pending!.id, 'ahmed');

    h.kill.engageGlobal('ahmed', 'emergency freeze');

    const result = await h.agent.executeApprovedRestart(incident!.id, WORKLOAD, pending!.id);
    assert.equal(result.ok, false);
    assert.match(result.reason, /kill switch/);
    assert.equal(h.provider.restartCalls, 0, 'an approved action still cannot run while frozen');
  });

  test('a repeated sweep does not open duplicate incidents', async () => {
    const h = harness();
    await h.agent.sweep();
    await h.agent.sweep();
    await h.agent.sweep();
    assert.equal(h.incidents.open(TenantScope.internalScope()).length, 1);
  });

  test('one unreachable workload does not abort the sweep', async () => {
    const second: Workload = { ...WORKLOAD, id: 'wl-99', name: 'other-worker' };
    const h = harness({ workloads: [WORKLOAD, second] });
    let calls = 0;
    const original = h.provider.getHealth.bind(h.provider);
    h.provider.getHealth = async () => {
      calls++;
      if (calls === 1) throw new Error('probe timeout');
      return original();
    };

    const run = await h.agent.sweep();
    assert.equal(run.status, 'partially_completed');
    assert.equal(run.workloadsChecked, 1, 'the reachable one was still checked');
    assert.equal(run.errors.length, 1);
    assert.equal(run.incidentsOpened, 1);
  });

  test('tenant isolation holds across the incident surface', async () => {
    const other: Workload = { ...WORKLOAD, id: 'wl-b', tenantId: 'tenant-b' };
    const h = harness({ workloads: [WORKLOAD, other] });
    await h.agent.sweep();

    assert.equal(h.incidents.list(TenantScope.forTenant('tenant-a')).length, 1);
    assert.equal(h.incidents.list(TenantScope.forTenant('tenant-b')).length, 1);
    assert.equal(h.incidents.list(TenantScope.internalScope()).length, 2);

    const aView = h.incidents.list(TenantScope.forTenant('tenant-a'));
    assert.ok(aView.every((i) => i.tenantId === 'tenant-a'));
  });

  test('AI analysis can enrich the incident without changing its urgency', async () => {
    const h = harness();
    await h.agent.sweep();
    const [incident] = h.incidents.open(TenantScope.internalScope());
    const severityBefore = incident!.severity;

    h.incidents.attachAnalysis(incident!.id, {
      probableCause: 'worker exited after exceeding its memory limit',
      confidence: 'medium',
      recommendation: 'restart, then raise the limit if it recurs',
    });

    const after = h.incidents.get(incident!.id)!;
    assert.equal(after.severity, severityBefore);
    assert.equal(after.status, 'awaiting_approval');
    assert.equal(after.confidence, 'medium');
  });

  test('a production critical outage escalates above the staging case', async () => {
    const prod: Workload = { ...WORKLOAD, environment: 'production' };
    const h = harness({ workloads: [prod] });
    await h.agent.sweep();
    const [incident] = h.incidents.open(TenantScope.internalScope());
    // production + 1 tenant + critical = score 3 -> MEDIUM; staging would cap LOW.
    assert.equal(incident!.severity, 'MEDIUM');
    assert.equal(incident!.environment, 'production');
  });
});
