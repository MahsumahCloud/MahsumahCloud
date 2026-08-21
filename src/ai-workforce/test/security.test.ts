import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { AuditLog, REDACTED } from '../core/audit.ts';
import { FixedClock } from '../core/clock.ts';
import { KillSwitchRegistry } from '../core/killswitch.ts';
import { TenantScope } from '../core/tenant.ts';
import { PolicyEngine } from '../core/policy.ts';
import { ApprovalEngine } from '../core/approval.ts';
import type { ApproverDirectory } from '../core/approval.ts';
import { ActionExecutor } from '../core/executor.ts';
import type { ActionHandler } from '../core/executor.ts';
import { buildActionRegistry } from '../actions/registry.ts';
import { PermissionLevel, defaultLaunchAutonomy } from '../core/types.ts';
import type { ActionRequest, ActionTarget, AutonomyConfig } from '../core/types.ts';

/**
 * Section 67 - Mandatory security tests.
 *
 * Every test in this file corresponds to a named release-blocking requirement.
 * A failure here blocks production autonomous mode (section 91).
 */

const T0 = 1_700_000_000_000;

/** Approver directory used across tests: 'ahmed' may approve, 'staff' may not. */
const approvers: ApproverDirectory = {
  canApprove: (userId) => userId === 'ahmed',
};

function target(over: Partial<ActionTarget> = {}): ActionTarget {
  return {
    resourceType: 'worker',
    resourceId: 'worker-1',
    tenantId: 'tenant-a',
    environment: 'staging',
    ...over,
  };
}

function req(over: Partial<ActionRequest> = {}): ActionRequest {
  return {
    action: 'cloud_ops.restart_worker',
    target: target(),
    agent: 'cloud_ops',
    runId: `run-${Math.random().toString(36).slice(2)}`,
    correlationId: 'corr-1',
    reason: 'three consecutive failed health checks',
    evidence: ['health check failed at T-3', 'host CPU normal', 'database reachable'],
    ...over,
  };
}

/** A handler whose verification outcome is controllable. */
function handler(opts: { verified?: boolean; throwOnExecute?: boolean } = {}): ActionHandler & {
  executeCount: number;
} {
  const h = {
    executeCount: 0,
    async execute() {
      h.executeCount++;
      if (opts.throwOnExecute) throw new Error('provider timeout');
      return { ok: true };
    },
    async verify() {
      return opts.verified ?? true;
    },
  };
  return h;
}

interface Harness {
  audit: AuditLog;
  clock: FixedClock;
  kill: KillSwitchRegistry;
  policy: PolicyEngine;
  approvals: ApprovalEngine;
  executor: ActionExecutor;
  registry: ReturnType<typeof buildActionRegistry>;
}

function harness(autonomy: AutonomyConfig = defaultLaunchAutonomy()): Harness {
  const clock = new FixedClock(T0);
  const audit = new AuditLog(clock);
  const kill = new KillSwitchRegistry(audit);
  const registry = buildActionRegistry();
  const policy = new PolicyEngine(registry, kill, audit, autonomy, clock);
  const approvals = new ApprovalEngine(audit, approvers, clock);
  const executor = new ActionExecutor(registry, policy, approvals, audit);
  return { audit, clock, kill, policy, approvals, executor, registry };
}

/** Requests, approves and returns a valid approval id for the given target. */
function approvedFor(h: Harness, action: string, tgt: ActionTarget, ttlMs = 60_000): string {
  const a = h.approvals.request({
    action,
    target: tgt,
    agent: 'cloud_ops',
    requestedBy: 'agent:cloud_ops',
    reason: 'health checks failing',
    evidence: ['e1'],
    risk: 'MEDIUM',
    predictedEffect: 'worker restarts and returns healthy',
    rollback: 'worker may be stopped again',
    correlationId: 'corr-1',
    ttlMs,
  });
  h.approvals.approve(a.id, 'ahmed', 'confirmed');
  return a.id;
}

// ---------------------------------------------------------------------------
describe('Section 67 - Tenant isolation', () => {
  test('customer A cannot access customer B resources', () => {
    const a = TenantScope.forTenant('tenant-a');
    assert.equal(a.canAccess('tenant-a'), true);
    assert.equal(a.canAccess('tenant-b'), false);
    assert.throws(() => a.assertCanAccess('tenant-b', 'workload'), {
      code: 'TENANT_ISOLATION_VIOLATION',
    });
  });

  test('customer scope cannot read platform-internal records', () => {
    assert.equal(TenantScope.forTenant('tenant-a').canAccess(null), false);
  });

  test('list reads are filtered, so a missed check cannot leak rows', () => {
    const rows = [
      { id: 1, tenantId: 'tenant-a' },
      { id: 2, tenantId: 'tenant-b' },
      { id: 3, tenantId: null },
      { id: 4, tenantId: 'tenant-a' },
    ];
    const visible = TenantScope.forTenant('tenant-a').filter(rows, (r) => r.tenantId);
    assert.deepEqual(
      visible.map((r) => r.id),
      [1, 4],
    );
  });

  test('policy denies an action targeting another tenant', async () => {
    const h = harness();
    const result = await h.executor.run(
      req({ target: target({ tenantId: 'tenant-b' }) }),
      TenantScope.forTenant('tenant-a'),
    );
    assert.equal(result.status, 'denied');
    assert.equal(result.policy, 'tenant.isolation');
  });
});

// ---------------------------------------------------------------------------
describe('Section 67 - P4 critical operations are blocked', () => {
  const P4_ACTIONS = [
    'cloud_ops.delete_server',
    'cloud_ops.delete_backup',
    'cloud_ops.modify_dns_nameservers',
    'security.modify_firewall_rules',
    'security.rotate_root_credentials',
    'customer_ops.delete_customer_account',
    'finance.initiate_transfer',
  ];

  test('every declared P4 action is denied by policy', async () => {
    const h = harness();
    for (const name of P4_ACTIONS) {
      const descriptor = h.registry.get(name);
      assert.ok(descriptor, `${name} should be declared`);
      assert.equal(descriptor.level, PermissionLevel.P4_MANUAL_CRITICAL, name);
      const result = await h.executor.run(
        req({ action: name, agent: descriptor.owner, target: target({ resourceType: descriptor.resourceType }) }),
        TenantScope.internalScope(),
      );
      assert.equal(result.status, 'denied', `${name} must be denied`);
      assert.equal(result.policy, 'autonomy.p4_blocked', name);
    }
  });

  test('P4 remains blocked even with every level an operator can enable', async () => {
    const h = harness({
      enabledLevels: new Set([
        PermissionLevel.P0_READ,
        PermissionLevel.P1_RECOMMEND,
        PermissionLevel.P2_SAFE_AUTONOMOUS,
        PermissionLevel.P3_APPROVAL_REQUIRED,
      ]),
      enabledP2Actions: new Set(['cloud_ops.delete_server']),
    });
    const result = await h.executor.run(
      req({ action: 'cloud_ops.delete_server', target: target({ resourceType: 'server' }) }),
      TenantScope.internalScope(),
    );
    assert.equal(result.status, 'denied');
    assert.equal(result.policy, 'autonomy.p4_blocked');
  });

  test('P4 cannot be enabled in autonomy configuration at all', () => {
    const h = harness();
    assert.throws(
      () =>
        h.policy.setAutonomy(
          {
            enabledLevels: new Set([PermissionLevel.P4_MANUAL_CRITICAL]),
            enabledP2Actions: new Set(),
          },
          'ahmed',
        ),
      /P4_MANUAL_CRITICAL can never be enabled/,
    );
  });

  test('a P4 action cannot even have an executable handler attached', () => {
    const h = harness();
    assert.throws(
      () => h.executor.registerHandler('cloud_ops.delete_server', handler()),
      /must not have an executable handler/,
    );
  });

  test('an action absent from the registry is denied', async () => {
    const h = harness();
    const result = await h.executor.run(
      req({ action: 'cloud_ops.do_anything_i_want' }),
      TenantScope.internalScope(),
    );
    assert.equal(result.status, 'denied');
    assert.equal(result.policy, 'registry.unknown_action');
  });
});

// ---------------------------------------------------------------------------
describe('Section 67 - Approval controls', () => {
  test('an unauthorised user cannot approve', () => {
    const h = harness();
    const a = h.approvals.request({
      action: 'cloud_ops.restart_worker',
      target: target(),
      agent: 'cloud_ops',
      requestedBy: 'agent:cloud_ops',
      reason: 'r',
      evidence: [],
      risk: 'MEDIUM',
      predictedEffect: 'restart',
      rollback: 'stop again',
      correlationId: 'c',
      ttlMs: 60_000,
    });
    assert.throws(() => h.approvals.approve(a.id, 'staff'), { code: 'APPROVAL_INVALID' });
    assert.equal(h.approvals.get(a.id)?.status, 'pending');
  });

  test('the requester cannot approve their own request', () => {
    const h = harness();
    const a = h.approvals.request({
      action: 'cloud_ops.restart_worker',
      target: target(),
      agent: 'cloud_ops',
      requestedBy: 'ahmed',
      reason: 'r',
      evidence: [],
      risk: 'MEDIUM',
      predictedEffect: 'restart',
      rollback: 'stop again',
      correlationId: 'c',
      ttlMs: 60_000,
    });
    assert.throws(() => h.approvals.approve(a.id, 'ahmed'), /may not approve their own/);
  });

  test('an expired approval is refused at execution time', async () => {
    const h = harness();
    const approvalId = approvedFor(h, 'cloud_ops.restart_worker', target(), 60_000);
    h.executor.registerHandler('cloud_ops.restart_worker', handler());

    h.clock.advance(60_001); // past expiry

    const result = await h.executor.run(
      req({ approvalId }),
      TenantScope.forTenant('tenant-a'),
    );
    assert.equal(result.status, 'denied');
    assert.match(result.reason, /expired/);
  });

  test('changing the target after approval invalidates it', async () => {
    const h = harness();
    const approvalId = approvedFor(h, 'cloud_ops.restart_worker', target({ resourceId: 'worker-1' }));
    h.executor.registerHandler('cloud_ops.restart_worker', handler());

    // Same action, same tenant - but a different worker than was approved.
    const result = await h.executor.run(
      req({ approvalId, target: target({ resourceId: 'worker-2' }) }),
      TenantScope.forTenant('tenant-a'),
    );
    assert.equal(result.status, 'denied');
    assert.match(result.reason, /scope does not match/);
  });

  test('changing the environment after approval invalidates it', async () => {
    const h = harness();
    const approvalId = approvedFor(h, 'cloud_ops.restart_worker', target({ environment: 'staging' }));
    h.executor.registerHandler('cloud_ops.restart_worker', handler());

    const result = await h.executor.run(
      req({ approvalId, target: target({ environment: 'production' }) }),
      TenantScope.forTenant('tenant-a'),
    );
    assert.equal(result.status, 'denied');
    assert.match(result.reason, /scope does not match/);
  });

  test('an approval is single-use', async () => {
    const h = harness();
    const approvalId = approvedFor(h, 'cloud_ops.restart_worker', target());
    h.executor.registerHandler('cloud_ops.restart_worker', handler());

    const first = await h.executor.run(req({ approvalId, runId: 'run-1' }), TenantScope.forTenant('tenant-a'));
    assert.equal(first.status, 'succeeded');

    const second = await h.executor.run(req({ approvalId, runId: 'run-2' }), TenantScope.forTenant('tenant-a'));
    assert.equal(second.status, 'denied');
    assert.match(second.reason, /already been used/);
  });

  test('a P3 action with no approval waits rather than executing', async () => {
    const h = harness();
    const h1 = handler();
    h.executor.registerHandler('cloud_ops.restart_worker', h1);

    const result = await h.executor.run(req(), TenantScope.forTenant('tenant-a'));
    assert.equal(result.status, 'awaiting_approval');
    assert.equal(h1.executeCount, 0, 'handler must not run without approval');
  });

  test('a rejected approval cannot be consumed', async () => {
    const h = harness();
    const a = h.approvals.request({
      action: 'cloud_ops.restart_worker',
      target: target(),
      agent: 'cloud_ops',
      requestedBy: 'agent:cloud_ops',
      reason: 'r',
      evidence: [],
      risk: 'MEDIUM',
      predictedEffect: 'restart',
      rollback: 'stop again',
      correlationId: 'c',
      ttlMs: 60_000,
    });
    h.approvals.reject(a.id, 'ahmed', 'not now');
    h.executor.registerHandler('cloud_ops.restart_worker', handler());

    const result = await h.executor.run(req({ approvalId: a.id }), TenantScope.forTenant('tenant-a'));
    assert.equal(result.status, 'denied');
  });
});

// ---------------------------------------------------------------------------
describe('Section 15 - Default launch policy', () => {
  test('P2 is disabled at launch', async () => {
    const h = harness();
    h.executor.registerHandler('cloud_ops.retry_health_check', handler());
    const result = await h.executor.run(
      req({ action: 'cloud_ops.retry_health_check', target: target({ resourceType: 'monitoring_check' }) }),
      TenantScope.forTenant('tenant-a'),
    );
    assert.equal(result.status, 'denied');
    assert.equal(result.policy, 'autonomy.level_disabled');
  });

  test('enabling P2 wholesale still requires per-action allowlisting', async () => {
    const h = harness({
      enabledLevels: new Set([
        PermissionLevel.P0_READ,
        PermissionLevel.P1_RECOMMEND,
        PermissionLevel.P2_SAFE_AUTONOMOUS,
        PermissionLevel.P3_APPROVAL_REQUIRED,
      ]),
      enabledP2Actions: new Set(), // nothing allowlisted yet
    });
    h.executor.registerHandler('cloud_ops.retry_health_check', handler());
    const result = await h.executor.run(
      req({ action: 'cloud_ops.retry_health_check', target: target({ resourceType: 'monitoring_check' }) }),
      TenantScope.forTenant('tenant-a'),
    );
    assert.equal(result.status, 'denied');
    assert.equal(result.policy, 'autonomy.p2_not_allowlisted');
  });

  test('an allowlisted P2 action runs and is verified', async () => {
    const h = harness({
      enabledLevels: new Set([PermissionLevel.P2_SAFE_AUTONOMOUS]),
      enabledP2Actions: new Set(['cloud_ops.retry_health_check']),
    });
    const hd = handler({ verified: true });
    h.executor.registerHandler('cloud_ops.retry_health_check', hd);
    const result = await h.executor.run(
      req({ action: 'cloud_ops.retry_health_check', target: target({ resourceType: 'monitoring_check' }) }),
      TenantScope.forTenant('tenant-a'),
    );
    assert.equal(result.status, 'succeeded');
    assert.equal(hd.executeCount, 1);
  });

  test('P0 reads are enabled at launch', async () => {
    const h = harness();
    h.executor.registerHandler('cloud_ops.read_workload_health', handler());
    const result = await h.executor.run(
      req({ action: 'cloud_ops.read_workload_health', target: target({ resourceType: 'workload' }) }),
      TenantScope.forTenant('tenant-a'),
    );
    assert.equal(result.status, 'succeeded');
  });
});

// ---------------------------------------------------------------------------
describe('Section 17 - Kill switches', () => {
  const p2Autonomy: AutonomyConfig = {
    enabledLevels: new Set([PermissionLevel.P0_READ, PermissionLevel.P2_SAFE_AUTONOMOUS]),
    enabledP2Actions: new Set(['cloud_ops.retry_health_check']),
  };

  let h: Harness;
  beforeEach(() => {
    h = harness(p2Autonomy);
    h.executor.registerHandler('cloud_ops.retry_health_check', handler());
    h.executor.registerHandler('cloud_ops.read_workload_health', handler());
  });

  const p2Req = () =>
    req({ action: 'cloud_ops.retry_health_check', target: target({ resourceType: 'monitoring_check' }) });
  const p0Req = () =>
    req({ action: 'cloud_ops.read_workload_health', target: target({ resourceType: 'workload' }) });

  test('the global switch stops everything, including reads', async () => {
    h.kill.engageGlobal('ahmed', 'incident');
    assert.equal((await h.executor.run(p2Req(), TenantScope.forTenant('tenant-a'))).status, 'denied');
    assert.equal((await h.executor.run(p0Req(), TenantScope.forTenant('tenant-a'))).status, 'denied');
  });

  test('the autonomy switch stops P2 but keeps monitoring alive', async () => {
    h.kill.disableAutonomousActions('ahmed', 'precaution');
    const mutating = await h.executor.run(p2Req(), TenantScope.forTenant('tenant-a'));
    const reading = await h.executor.run(p0Req(), TenantScope.forTenant('tenant-a'));
    assert.equal(mutating.status, 'denied');
    assert.equal(mutating.policy, 'killswitch');
    assert.equal(reading.status, 'succeeded', 'monitoring must survive the autonomy switch');
  });

  test('the per-agent switch isolates one agent', async () => {
    h.kill.engageAgent('cloud_ops', 'ahmed', 'misbehaving');
    assert.equal((await h.executor.run(p0Req(), TenantScope.forTenant('tenant-a'))).status, 'denied');
    h.kill.releaseAgent('cloud_ops', 'ahmed', 'resolved');
    assert.equal((await h.executor.run(p0Req(), TenantScope.forTenant('tenant-a'))).status, 'succeeded');
  });

  test('every kill-switch operation is audited', () => {
    const before = h.audit.length;
    h.kill.engageGlobal('ahmed', 'drill');
    h.kill.releaseGlobal('ahmed', 'drill over');
    const events = h.audit.query({ actorId: 'ahmed' });
    assert.equal(h.audit.length, before + 2);
    assert.ok(events.some((e) => e.action === 'killswitch.engage'));
    assert.ok(events.some((e) => e.action === 'killswitch.release'));
  });
});

// ---------------------------------------------------------------------------
describe('Section 58 - Action verification', () => {
  test('a 200 response is not success: unverified actions fail', async () => {
    const h = harness();
    const approvalId = approvedFor(h, 'cloud_ops.restart_worker', target());
    h.executor.registerHandler('cloud_ops.restart_worker', handler({ verified: false }));

    const result = await h.executor.run(req({ approvalId }), TenantScope.forTenant('tenant-a'));
    assert.equal(result.status, 'verification_failed');
    assert.match(result.reason, /did not reach the intended state/);
  });

  test('rollback runs when verification fails', async () => {
    const h = harness();
    const approvalId = approvedFor(h, 'cloud_ops.restart_worker', target());
    let rolledBack = false;
    h.executor.registerHandler('cloud_ops.restart_worker', {
      async execute() {
        return { ok: true };
      },
      async verify() {
        return false;
      },
      async rollback() {
        rolledBack = true;
      },
    });

    const result = await h.executor.run(req({ approvalId }), TenantScope.forTenant('tenant-a'));
    assert.equal(result.status, 'verification_failed');
    assert.equal(result.rolledBack, true);
    assert.equal(rolledBack, true);
  });

  test('an execution failure is reported, never silently swallowed', async () => {
    const h = harness();
    const approvalId = approvedFor(h, 'cloud_ops.restart_worker', target());
    h.executor.registerHandler('cloud_ops.restart_worker', handler({ throwOnExecute: true }));

    const result = await h.executor.run(req({ approvalId }), TenantScope.forTenant('tenant-a'));
    assert.equal(result.status, 'failed');
    assert.match(result.error ?? '', /provider timeout/);
    assert.ok(
      h.audit.query({ result: 'failed' }).length > 0,
      'section 57 - no silent failures',
    );
  });

  test('a replayed event does not execute twice', async () => {
    const h = harness({
      enabledLevels: new Set([PermissionLevel.P2_SAFE_AUTONOMOUS]),
      enabledP2Actions: new Set(['cloud_ops.retry_health_check']),
    });
    const hd = handler();
    h.executor.registerHandler('cloud_ops.retry_health_check', hd);
    const request = req({
      action: 'cloud_ops.retry_health_check',
      target: target({ resourceType: 'monitoring_check' }),
      runId: 'run-fixed',
    });

    await h.executor.run(request, TenantScope.forTenant('tenant-a'));
    await h.executor.run(request, TenantScope.forTenant('tenant-a'));
    assert.equal(hd.executeCount, 1, 'duplicate delivery must be deduplicated');
  });
});

// ---------------------------------------------------------------------------
describe('Section 18/93 - Audit integrity and secret handling', () => {
  test('credentials never reach the audit log', () => {
    const h = harness();
    h.audit.append({
      actorType: 'system',
      actorId: 'integration',
      tenantId: null,
      action: 'integration.configure',
      target: 'whm',
      result: 'succeeded',
      reason: 'configured',
      correlationId: 'c',
      metadata: {
        WHM_API_TOKEN: 'super-secret-value',
        nested: { huawei_secret_key: 'another-secret' },
        host: 'whm.example.internal',
      },
    });
    const entry = h.audit.all().at(-1)!;
    const serialised = JSON.stringify(entry);
    assert.ok(!serialised.includes('super-secret-value'));
    assert.ok(!serialised.includes('another-secret'));
    assert.equal((entry.metadata as Record<string, unknown>).WHM_API_TOKEN, REDACTED);
    assert.equal(
      ((entry.metadata as Record<string, unknown>).nested as Record<string, unknown>)
        .huawei_secret_key,
      REDACTED,
    );
    assert.equal((entry.metadata as Record<string, unknown>).host, 'whm.example.internal');
  });

  test('tampering with history is detectable', () => {
    const h = harness();
    for (let i = 0; i < 5; i++) {
      h.audit.append({
        actorType: 'agent',
        actorId: 'cloud_ops',
        tenantId: 'tenant-a',
        action: 'cloud_ops.read_workload_health',
        target: `workload:${i}`,
        result: 'succeeded',
        reason: 'ok',
        correlationId: 'c',
        metadata: {},
      });
    }
    assert.equal(h.audit.verifyChain(), -1, 'chain should start intact');
    h.audit.__tamperForTest(2, { reason: 'rewritten after the fact' });
    assert.equal(h.audit.verifyChain(), 2, 'tampering must be located exactly');
  });

  test('every denied action is attributable at a point in time', async () => {
    const h = harness();
    await h.executor.run(
      req({ target: target({ tenantId: 'tenant-b' }), correlationId: 'corr-xyz' }),
      TenantScope.forTenant('tenant-a'),
    );
    const [entry] = h.audit.query({ correlationId: 'corr-xyz', result: 'denied' });
    assert.ok(entry, 'the denial must be recorded');
    assert.equal(entry.actorId, 'cloud_ops');
    assert.equal(entry.policy, 'tenant.isolation');
    assert.equal(entry.timestamp, T0);
  });

  test('an approved action records who approved it', async () => {
    const h = harness();
    const approvalId = approvedFor(h, 'cloud_ops.restart_worker', target());
    h.executor.registerHandler('cloud_ops.restart_worker', handler());
    await h.executor.run(req({ approvalId }), TenantScope.forTenant('tenant-a'));

    const decision = h.audit
      .query({ action: 'approval.decision' })
      .find((e) => e.approvalId === approvalId);
    assert.ok(decision, 'the approval decision must be audited');
    assert.equal(decision.actorId, 'ahmed');
    assert.equal(h.approvals.get(approvalId)?.decidedBy, 'ahmed');
  });
});

// ---------------------------------------------------------------------------
describe('Section 79 - Catalogue integrity', () => {
  test('no P0 or P1 action is declared as mutating', () => {
    const registry = buildActionRegistry();
    for (const a of registry.all()) {
      if (a.level === PermissionLevel.P0_READ || a.level === PermissionLevel.P1_RECOMMEND) {
        assert.equal(a.mutates, false, `${a.name} must not mutate`);
      }
    }
  });

  test('every action declares blast radius, verification and rollback', () => {
    for (const a of buildActionRegistry().all()) {
      assert.ok(a.blastRadius.length > 0, `${a.name} blastRadius`);
      assert.ok(a.verification.length > 0, `${a.name} verification`);
      assert.ok(a.rollback.length > 0, `${a.name} rollback`);
      assert.ok(a.allowedEnvironments.length > 0, `${a.name} environments`);
    }
  });

  test('an action cannot be invoked by an agent that does not own it', async () => {
    const h = harness();
    const result = await h.executor.run(
      req({ action: 'finance.read_overdue_invoices', agent: 'cloud_ops', target: target({ resourceType: 'invoice' }) }),
      TenantScope.internalScope(),
    );
    assert.equal(result.status, 'denied');
    assert.equal(result.policy, 'registry.wrong_owner');
  });

  test('environment restrictions are enforced', async () => {
    const h = harness({
      enabledLevels: new Set([PermissionLevel.P2_SAFE_AUTONOMOUS]),
      enabledP2Actions: new Set(['finance.generate_renewal_reminder']),
    });
    h.executor.registerHandler('finance.generate_renewal_reminder', handler());
    const result = await h.executor.run(
      req({
        action: 'finance.generate_renewal_reminder',
        agent: 'finance',
        target: target({ resourceType: 'subscription', environment: 'production' }),
      }),
      TenantScope.forTenant('tenant-a'),
    );
    assert.equal(result.status, 'denied');
    assert.equal(result.policy, 'environment.not_allowed');
  });

  test('rate limits cap blast radius', async () => {
    const h = harness({
      enabledLevels: new Set([PermissionLevel.P2_SAFE_AUTONOMOUS]),
      enabledP2Actions: new Set(['cloud_ops.retry_health_check']),
    });
    h.executor.registerHandler('cloud_ops.retry_health_check', handler());
    const limit = h.registry.get('cloud_ops.retry_health_check')!.rateLimitPerHour!;

    let denied = 0;
    for (let i = 0; i < limit + 3; i++) {
      const r = await h.executor.run(
        req({
          action: 'cloud_ops.retry_health_check',
          target: target({ resourceType: 'monitoring_check' }),
          runId: `run-${i}`,
        }),
        TenantScope.forTenant('tenant-a'),
      );
      if (r.status === 'denied' && r.policy === 'ratelimit.exceeded') denied++;
    }
    assert.equal(denied, 3, 'calls beyond the hourly limit must be denied');
  });
});
