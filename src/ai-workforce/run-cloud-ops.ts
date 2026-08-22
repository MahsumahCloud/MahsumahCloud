import { homedir } from 'node:os';

import { AuditLog } from './core/audit.ts';
import { systemClock } from './core/clock.ts';
import { KillSwitchRegistry } from './core/killswitch.ts';
import { TenantScope } from './core/tenant.ts';
import { PolicyEngine } from './core/policy.ts';
import { ApprovalEngine } from './core/approval.ts';
import type { ApproverDirectory } from './core/approval.ts';
import { ActionExecutor } from './core/executor.ts';
import { IncidentEngine } from './core/incident.ts';
import { HeartbeatMonitor } from './runtime/heartbeat.ts';
import { buildActionRegistry } from './actions/registry.ts';
import { defaultLaunchAutonomy } from './core/types.ts';
import { CloudOpsAgent } from './agents/cloud-ops.ts';
import { MahsumahSshReader } from './integrations/adapters/mahsumah-ssh-reader.ts';

/**
 * Real, READ-ONLY activation of the Cloud Operations agent against the live
 * Mahsumah nodes (deployment gate 1). No writer is provided, so the agent can
 * only observe, detect and report — it can never restart or mutate anything.
 *
 *   node --experimental-strip-types src/ai-workforce/run-cloud-ops.ts
 *
 * Output contract (so a deploy wrapper can decide whether to SMS the owner):
 *   - prints a human report to stdout
 *   - prints one machine line   ALERT<TAB>{json}   when action is warranted
 *   - exit 0 = healthy, 1 = incident(s) found, 2 = integration unreachable
 * SMS is intentionally NOT sent from here; the server-side cron wrapper pipes
 * an ALERT line into the platform's existing msegat sender (which owns the
 * credentials), keeping this process free of any outbound or write authority.
 */

const SSH_KEY = process.env.MAHC_SSH_KEY ?? `${homedir()}/.ssh/mahsumaah_deploy`;

async function main(): Promise<number> {
  const clock = systemClock;
  const audit = new AuditLog(clock);
  const kill = new KillSwitchRegistry(audit);
  const registry = buildActionRegistry();
  const policy = new PolicyEngine(registry, kill, audit, defaultLaunchAutonomy(), clock);
  const approvers: ApproverDirectory = { canApprove: (userId) => userId === 'ahmed' };
  const approvals = new ApprovalEngine(audit, approvers, clock);
  const executor = new ActionExecutor(registry, policy, approvals, audit);
  const incidents = new IncidentEngine(audit, clock);
  const heartbeat = new HeartbeatMonitor(audit, undefined, clock);
  heartbeat.expect('cloud_ops');

  const reader = new MahsumahSshReader({
    sshKey: SSH_KEY,
    hosts: [
      { ip: '80.238.198.115', label: 'app-01 (Huawei ECS)' },
      { ip: '80.238.197.90', label: 'paas-node (Riyadh)' },
    ],
    // The main app cluster, customer sites and databases are customer-impacting.
    isCritical: (name) => /^(mahsumaah-cloud|site-|db-)/.test(name),
  });

  // writer: null → READ-ONLY. The agent detects and reports; it cannot restart.
  const agent = new CloudOpsAgent({
    reader,
    writer: null,
    incidents,
    executor,
    approvals,
    audit,
    heartbeat,
    clock,
  });

  const runResult = await agent.sweep();
  const open = incidents.open(TenantScope.internalScope());

  console.log('── cloud-ops sweep ──────────────────────────────');
  console.log(`status:            ${runResult.status}`);
  console.log(`workloads checked: ${runResult.workloadsChecked}`);
  console.log(`incidents opened:  ${runResult.incidentsOpened}`);
  console.log(`errors:            ${runResult.errors.length}`);
  for (const e of runResult.errors) console.log(`  ! ${e}`);
  for (const inc of open) {
    console.log(`\n  ! [${inc.severity}] ${inc.title}`);
    for (const ev of inc.evidence) console.log(`      ${ev}`);
  }
  console.log('-------------------------------------------------');

  // Machine-readable ALERT line for the (separate) SMS wrapper to act on.
  if (runResult.status === 'failed') {
    const detail = runResult.errors[0] ?? 'integration unreachable';
    console.log(`ALERT\t${JSON.stringify({ kind: 'integration_unreachable', detail })}`);
    return 2;
  }
  if (open.length > 0) {
    const summary = open.slice(0, 5).map((i) => `[${i.severity}] ${i.title}`);
    console.log(
      `ALERT\t${JSON.stringify({ kind: 'incidents', count: open.length, checked: runResult.workloadsChecked, summary })}`,
    );
    return 1;
  }

  console.log(`OK\t${JSON.stringify({ checked: runResult.workloadsChecked })}`);
  return 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error('run-cloud-ops crashed:', err);
    process.exit(2);
  });
