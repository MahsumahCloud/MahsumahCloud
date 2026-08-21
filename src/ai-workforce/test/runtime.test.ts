import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { AuditLog } from '../core/audit.ts';
import { FixedClock } from '../core/clock.ts';
import { TenantScope } from '../core/tenant.ts';
import { Scheduler } from '../runtime/scheduler.ts';
import { HeartbeatMonitor, DEFAULT_WATCHDOG } from '../runtime/heartbeat.ts';
import { IncidentEngine, computeSeverity } from '../core/incident.ts';
import type { ImpactFacts } from '../core/incident.ts';

const T0 = 1_700_000_000_000;
const MIN = 60_000;
const HOUR = 3_600_000;

function facts(over: Partial<ImpactFacts> = {}): ImpactFacts {
  return {
    environment: 'production',
    affectedTenants: 0,
    serviceCritical: false,
    durationMs: 0,
    dataAtRisk: false,
    securityRisk: false,
    slaBreached: false,
    ...over,
  };
}

// ---------------------------------------------------------------------------
describe('Section 26 - Deterministic severity', () => {
  test('data at risk with customer impact is CRITICAL', () => {
    assert.equal(computeSeverity(facts({ dataAtRisk: true, affectedTenants: 1 })), 'CRITICAL');
  });

  test('data at risk with no observed impact is still HIGH', () => {
    assert.equal(computeSeverity(facts({ dataAtRisk: true, affectedTenants: 0 })), 'HIGH');
  });

  test('security risk in production is CRITICAL', () => {
    assert.equal(computeSeverity(facts({ securityRisk: true })), 'CRITICAL');
  });

  test('staging noise never exceeds MEDIUM', () => {
    const worst = computeSeverity(
      facts({
        environment: 'staging',
        affectedTenants: 50,
        serviceCritical: true,
        durationMs: 10 * HOUR,
        slaBreached: true,
      }),
    );
    assert.equal(worst, 'MEDIUM');
  });

  test('staging still escalates to CRITICAL when data is at risk', () => {
    assert.equal(
      computeSeverity(facts({ environment: 'staging', dataAtRisk: true, affectedTenants: 2 })),
      'CRITICAL',
    );
  });

  test('severity rises with customer count', () => {
    const one = computeSeverity(facts({ affectedTenants: 1, serviceCritical: true }));
    const many = computeSeverity(facts({ affectedTenants: 12, serviceCritical: true }));
    assert.equal(one, 'MEDIUM');
    assert.equal(many, 'HIGH');
  });

  test('a long critical outage breaching SLA is CRITICAL', () => {
    assert.equal(
      computeSeverity(
        facts({ affectedTenants: 12, serviceCritical: true, slaBreached: true, durationMs: 5 * HOUR }),
      ),
      'CRITICAL',
    );
  });

  test('severity is a pure function - identical facts give identical results', () => {
    const f = facts({ affectedTenants: 4, serviceCritical: true, durationMs: 2 * HOUR });
    assert.equal(computeSeverity(f), computeSeverity(f));
  });
});

// ---------------------------------------------------------------------------
describe('Section 25 - Incident engine', () => {
  const build = () => {
    const clock = new FixedClock(T0);
    const audit = new AuditLog(clock);
    return { clock, audit, engine: new IncidentEngine(audit, clock) };
  };

  const detect = (engine: IncidentEngine, over: Partial<ImpactFacts> = {}) =>
    engine.detect({
      dedupeKey: 'workload:w1:down',
      tenantId: 'tenant-a',
      category: 'availability',
      title: 'workload unreachable',
      owner: 'cloud_ops',
      correlationId: 'corr-1',
      evidence: ['3 consecutive failed health checks'],
      facts: facts(over),
    });

  test('a repeated signal updates the incident instead of duplicating it', () => {
    const { engine } = build();
    const first = detect(engine, { affectedTenants: 1, serviceCritical: true });
    const second = detect(engine, { affectedTenants: 1, serviceCritical: true });
    assert.equal(first.id, second.id);
    assert.equal(engine.open(TenantScope.internalScope()).length, 1);
  });

  test('a persisting incident escalates severity and records it', () => {
    const { engine, audit } = build();
    const incident = detect(engine, { affectedTenants: 1, serviceCritical: true });
    assert.equal(incident.severity, 'MEDIUM');

    detect(engine, { affectedTenants: 12, serviceCritical: true, slaBreached: true });
    assert.equal(engine.get(incident.id)!.severity, 'CRITICAL');
    assert.ok(audit.query({ action: 'incident.severity_changed' }).length === 1);
  });

  test('illegal lifecycle transitions are rejected', () => {
    const { engine } = build();
    const incident = detect(engine);
    assert.throws(
      () => engine.transition(incident.id, 'mitigating', 'cloud_ops', 'skip ahead'),
      /illegal incident transition/,
    );
  });

  test('the full lifecycle reaches resolved and reopens the dedupe key', () => {
    const { engine, clock } = build();
    const incident = detect(engine, { affectedTenants: 1 });
    for (const [to, note] of [
      ['confirmed', 'confirmed by second check'],
      ['investigating', 'gathering evidence'],
      ['recommendation', 'restart proposed'],
      ['awaiting_approval', 'sent to operator'],
      ['mitigating', 'approved, restarting'],
      ['verifying', 'checking health'],
      ['monitoring', 'healthy, watching'],
    ] as const) {
      engine.transition(incident.id, to, 'cloud_ops', note);
    }
    clock.advance(30 * MIN);
    engine.transition(incident.id, 'resolved', 'cloud_ops', 'stable');

    assert.equal(engine.get(incident.id)!.status, 'resolved');
    assert.equal(engine.open(TenantScope.internalScope()).length, 0);
    assert.equal(engine.meanTimeToResolveMs(TenantScope.internalScope()), 30 * MIN);

    // A new occurrence after resolution creates a genuinely new incident.
    const reopened = detect(engine, { affectedTenants: 1 });
    assert.notEqual(reopened.id, incident.id);
  });

  test('AI analysis is advisory and cannot change severity or status', () => {
    const { engine } = build();
    const incident = detect(engine, { affectedTenants: 1, serviceCritical: true });
    const severityBefore = incident.severity;
    const statusBefore = incident.status;

    engine.attachAnalysis(incident.id, {
      probableCause: 'worker process exited after OOM',
      confidence: 'high',
      recommendation: 'restart the worker and raise the memory limit',
    });

    const after = engine.get(incident.id)!;
    assert.equal(after.severity, severityBefore, 'model must not change severity');
    assert.equal(after.status, statusBefore, 'model must not change status');
    assert.equal(after.probableCause, 'worker process exited after OOM');
  });

  test('incident listing is tenant scoped', () => {
    const { engine } = build();
    detect(engine); // tenant-a
    engine.detect({
      dedupeKey: 'workload:w9:down',
      tenantId: 'tenant-b',
      category: 'availability',
      title: 'other tenant workload down',
      owner: 'cloud_ops',
      correlationId: 'corr-2',
      evidence: [],
      facts: facts(),
    });

    assert.equal(engine.list(TenantScope.forTenant('tenant-a')).length, 1);
    assert.equal(engine.list(TenantScope.forTenant('tenant-b')).length, 1);
    assert.equal(engine.list(TenantScope.internalScope()).length, 2);

    const aOnly = engine.list(TenantScope.forTenant('tenant-a'));
    assert.ok(aOnly.every((i) => i.tenantId === 'tenant-a'));
  });
});

// ---------------------------------------------------------------------------
describe('Section 9 - Scheduler', () => {
  const build = () => {
    const clock = new FixedClock(T0);
    const audit = new AuditLog(clock);
    return { clock, audit, scheduler: new Scheduler(audit, clock) };
  };

  test('nothing runs before start()', async () => {
    const { scheduler } = build();
    let runs = 0;
    scheduler.register({ name: 'j', intervalMs: MIN, run: async () => void runs++ });
    assert.deepEqual((await scheduler.tick()).ran, []);
    assert.equal(runs, 0);
  });

  test('a job runs on the first tick, then on its interval', async () => {
    const { scheduler, clock } = build();
    let runs = 0;
    scheduler.register({ name: 'health', intervalMs: 5 * MIN, run: async () => void runs++ });
    scheduler.start();

    await scheduler.tick();
    assert.equal(runs, 1);

    clock.advance(MIN); // not due yet
    await scheduler.tick();
    assert.equal(runs, 1);

    clock.advance(4 * MIN); // now due
    await scheduler.tick();
    assert.equal(runs, 2);
  });

  test('a long sleep does not replay a backlog', async () => {
    const { scheduler, clock } = build();
    let runs = 0;
    scheduler.register({ name: 'sweep', intervalMs: 5 * MIN, run: async () => void runs++ });
    scheduler.start();
    await scheduler.tick();
    assert.equal(runs, 1);

    clock.advance(HOUR); // asleep for an hour = 12 missed intervals
    await scheduler.tick();
    assert.equal(runs, 2, 'catch-up must not be cumulative');
  });

  test('a failing job is recorded and audited, and does not stop others', async () => {
    const { scheduler, audit } = build();
    let goodRuns = 0;
    scheduler.register({
      name: 'bad',
      intervalMs: MIN,
      run: async () => {
        throw new Error('integration timeout');
      },
    });
    scheduler.register({ name: 'good', intervalMs: MIN, run: async () => void goodRuns++ });
    scheduler.start();

    const summary = await scheduler.tick();
    assert.deepEqual(summary.failed, ['bad']);
    assert.deepEqual(summary.ran, ['good']);
    assert.equal(goodRuns, 1, 'one failing job must not stop the others');
    assert.equal(scheduler.stats('bad').failures, 1);
    assert.match(scheduler.stats('bad').lastError ?? '', /integration timeout/);
    assert.equal(audit.query({ action: 'scheduler.job_failed' }).length, 1);
  });

  test('singleFlight prevents a slow job overlapping itself', async () => {
    const { scheduler, clock } = build();
    let started = 0;
    let release!: () => void;
    const gate = new Promise<void>((r) => {
      release = r;
    });

    scheduler.register({
      name: 'slow',
      intervalMs: MIN,
      singleFlight: true,
      run: async () => {
        started++;
        await gate;
      },
    });
    scheduler.start();

    const first = scheduler.tick(); // starts and blocks
    await Promise.resolve();
    clock.advance(2 * MIN);
    const second = await scheduler.tick(); // due again, but still running

    assert.deepEqual(second.skipped, ['slow']);
    assert.equal(started, 1);

    release();
    await first;
    assert.equal(scheduler.stats('slow').skipped, 1);
  });
});

// ---------------------------------------------------------------------------
describe('Section 46/73 - Heartbeat watchdog', () => {
  const build = () => {
    const clock = new FixedClock(T0);
    const audit = new AuditLog(clock);
    return { clock, audit, monitor: new HeartbeatMonitor(audit, DEFAULT_WATCHDOG, clock) };
  };

  test('an agent that never starts is reported, not silently absent', () => {
    const { monitor } = build();
    monitor.expect('cloud_ops');
    const unhealthy = monitor.sweep();
    assert.equal(unhealthy.length, 1);
    assert.equal(unhealthy[0]!.state, 'never_started');
    assert.equal(unhealthy[0]!.severity, 'HIGH');
  });

  test('a healthy agent produces no alert', () => {
    const { monitor } = build();
    monitor.expect('cloud_ops');
    monitor.beat('cloud_ops', 'ok');
    assert.deepEqual(monitor.sweep(), []);
    assert.equal(monitor.report('cloud_ops').state, 'healthy');
  });

  test('a stopped agent goes stale and is audited exactly once', () => {
    const { monitor, clock, audit } = build();
    monitor.expect('cloud_ops');
    monitor.beat('cloud_ops', 'ok');

    clock.advance(DEFAULT_WATCHDOG.stalenessThresholdMs + 1000);

    assert.equal(monitor.sweep()[0]!.state, 'stale');
    monitor.sweep();
    monitor.sweep();

    assert.equal(
      audit.query({ action: 'agent.health_degraded' }).length,
      1,
      'alert on transition, not on every sweep',
    );
  });

  test('recovery is detected and audited', () => {
    const { monitor, clock, audit } = build();
    monitor.expect('cloud_ops');
    monitor.beat('cloud_ops', 'ok');
    clock.advance(DEFAULT_WATCHDOG.stalenessThresholdMs + 1000);
    monitor.sweep();

    monitor.beat('cloud_ops', 'ok');
    assert.deepEqual(monitor.sweep(), []);
    assert.equal(audit.query({ action: 'agent.health_recovered' }).length, 1);
  });

  test('repeated errors mark the agent degraded', () => {
    const { monitor } = build();
    monitor.expect('security');
    monitor.beat('security', 'error');
    monitor.beat('security', 'error');
    assert.equal(monitor.report('security').state, 'healthy', 'below threshold');

    monitor.beat('security', 'error');
    assert.equal(monitor.report('security').state, 'degraded');

    monitor.beat('security', 'ok');
    assert.equal(monitor.report('security').state, 'healthy', 'a success resets the streak');
  });

  test('the watchdog is independent of the agents it watches', () => {
    // Section 46 - the watchdog has no policy engine, no kill switch and no
    // integrations, so nothing that disables an agent can also silence its alarm.
    const { monitor, clock, audit } = build();
    monitor.expect('cloud_ops');
    monitor.expect('security');
    monitor.beat('security', 'ok');

    clock.advance(DEFAULT_WATCHDOG.stalenessThresholdMs + 1);
    monitor.beat('security', 'ok'); // security still alive

    const unhealthy = monitor.sweep();
    assert.equal(unhealthy.length, 1);
    assert.equal(unhealthy[0]!.agent, 'cloud_ops');
    assert.equal(audit.query({ action: 'agent.health_degraded' }).length, 1);
  });
});
