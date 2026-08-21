import type { Clock } from '../core/clock.ts';
import { systemClock } from '../core/clock.ts';
import type { AuditLog } from '../core/audit.ts';
import type { ApprovalEngine, ApprovalRequest } from '../core/approval.ts';
import type { IncidentEngine, Incident } from '../core/incident.ts';
import type { HeartbeatMonitor, HealthReport } from '../runtime/heartbeat.ts';
import type { KillSwitchRegistry } from '../core/killswitch.ts';
import { TenantScope } from '../core/tenant.ts';
import type { AgentId, Severity } from '../core/types.ts';

/**
 * Section 39 - CEO Command Agent.
 *
 * Consumes only VERIFIED outputs of the other agents. It holds no integration,
 * requests no approval and executes nothing - it cannot bypass any permission
 * system because it has no action to bypass one with (section 39).
 *
 * Section 40 is the design constraint: Ahmed should not need ten tools to
 * understand Mahsumah. The brief's most important section is "decisions
 * needed", and it contains ONLY items that genuinely require management
 * judgement. Anything a policy or an agent can handle safely never appears.
 *
 * Where a value is unavailable, the brief says UNAVAILABLE with the reason
 * (section 90). It never estimates.
 */

export type Unavailable = { readonly unavailable: string };

export function isUnavailable<T>(v: T | Unavailable): v is Unavailable {
  return typeof v === 'object' && v !== null && 'unavailable' in v;
}

export interface DecisionItem {
  readonly kind: 'approval' | 'incident' | 'agent_health' | 'kill_switch';
  readonly urgency: Severity;
  readonly title: string;
  readonly why: string;
  readonly reference: string;
  /** What happens if nobody decides. Stated so triage is possible. */
  readonly ifIgnored: string;
}

export interface PlatformSection {
  readonly openIncidents: number;
  readonly criticalIncidents: number;
  readonly meanTimeToResolveMs: number | null;
  readonly agentsHealthy: number;
  readonly agentsTotal: number;
  readonly unhealthyAgents: readonly string[];
  readonly autonomyFrozen: boolean;
}

export interface DailyBrief {
  readonly generatedAt: number;
  readonly platform: PlatformSection;
  readonly security: { openIncidents: number; critical: number };
  readonly customers: { affectedTenants: number };
  /** Sections whose data source does not exist yet. */
  readonly sales: Unavailable | { qualified: number };
  readonly marketing: Unavailable | { awaitingApproval: number };
  readonly finance: Unavailable | { overdue: number; renewals: number };
  /** Section 40 - the section that matters. Ordered most urgent first. */
  readonly decisionsNeeded: readonly DecisionItem[];
}

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

export interface CeoCommandInputs {
  /** Populated only when the corresponding agent actually ran. */
  readonly sales?: { qualified: number };
  readonly marketing?: { awaitingApproval: number };
  readonly finance?: { overdue: number; renewals: number };
}

export class CeoCommandAgent {
  readonly id = 'ceo_command' as const;

  #incidents: IncidentEngine;
  #approvals: ApprovalEngine;
  #heartbeat: HeartbeatMonitor;
  #killSwitches: KillSwitchRegistry;
  #audit: AuditLog;
  #clock: Clock;
  #expectedAgents: readonly AgentId[];

  constructor(deps: {
    incidents: IncidentEngine;
    approvals: ApprovalEngine;
    heartbeat: HeartbeatMonitor;
    killSwitches: KillSwitchRegistry;
    audit: AuditLog;
    expectedAgents: readonly AgentId[];
    clock?: Clock;
  }) {
    this.#incidents = deps.incidents;
    this.#approvals = deps.approvals;
    this.#heartbeat = deps.heartbeat;
    this.#killSwitches = deps.killSwitches;
    this.#audit = deps.audit;
    this.#expectedAgents = deps.expectedAgents;
    this.#clock = deps.clock ?? systemClock;
  }

  #decisionsFrom(
    incidents: readonly Incident[],
    approvals: readonly ApprovalRequest[],
    unhealthy: readonly HealthReport[],
  ): DecisionItem[] {
    const items: DecisionItem[] = [];

    // Pending approvals are by definition awaiting a human.
    for (const a of approvals) {
      items.push({
        kind: 'approval',
        urgency: a.risk,
        title: `Approve or reject: ${a.action}`,
        why: a.reason,
        reference: a.id,
        ifIgnored: `The action expires at ${a.expiresAt} and will not run.`,
      });
    }

    // Only incidents that are actually stuck on a person.
    for (const i of incidents) {
      if (i.status === 'awaiting_approval') {
        items.push({
          kind: 'incident',
          urgency: i.severity,
          title: i.title,
          why: 'Remediation is proposed and waiting on a decision.',
          reference: i.id,
          ifIgnored: 'The incident stays open and unmitigated.',
        });
      } else if (i.severity === 'CRITICAL' && i.status !== 'resolved') {
        items.push({
          kind: 'incident',
          urgency: 'CRITICAL',
          title: i.title,
          why: `Critical incident in ${i.status} state.`,
          reference: i.id,
          ifIgnored: 'Customer impact continues.',
        });
      }
    }

    // A dead agent is a management problem: nothing behind it is being watched.
    for (const h of unhealthy) {
      items.push({
        kind: 'agent_health',
        urgency: h.severity,
        title: `Agent ${h.agent} is ${h.state}`,
        why: h.detail,
        reference: h.agent,
        ifIgnored: `Whatever ${h.agent} monitors is currently unmonitored.`,
      });
    }

    if (this.#killSwitches.autonomousActionsDisabled) {
      items.push({
        kind: 'kill_switch',
        urgency: 'MEDIUM',
        title: 'Autonomous actions are disabled',
        why: 'A kill switch is engaged, so no agent can act even where policy would allow it.',
        reference: 'killswitch:autonomy',
        ifIgnored: 'Every remediation continues to require a human.',
      });
    }

    return items.sort((a, b) => SEVERITY_ORDER[a.urgency] - SEVERITY_ORDER[b.urgency]);
  }

  /**
   * Section 39 - compile the brief. Staff scope: this is an internal management
   * document, so it reads across tenants by design.
   */
  compile(inputs: CeoCommandInputs = {}): DailyBrief {
    const scope = TenantScope.internalScope();
    const open = this.#incidents.open(scope);
    const security = open.filter((i) => i.category === 'security');
    const pending = this.#approvals.pending();
    const health = this.#heartbeat.all();
    const unhealthy = health.filter((h) => h.state !== 'healthy');

    const affectedTenants = new Set(
      open.map((i) => i.tenantId).filter((t): t is string => t !== null),
    ).size;

    const brief: DailyBrief = {
      generatedAt: this.#clock.now(),
      platform: {
        openIncidents: open.length,
        criticalIncidents: open.filter((i) => i.severity === 'CRITICAL').length,
        meanTimeToResolveMs: this.#incidents.meanTimeToResolveMs(scope),
        agentsHealthy: health.length - unhealthy.length,
        agentsTotal: this.#expectedAgents.length,
        unhealthyAgents: unhealthy.map((h) => h.agent),
        autonomyFrozen: this.#killSwitches.autonomousActionsDisabled,
      },
      security: {
        openIncidents: security.length,
        critical: security.filter((i) => i.severity === 'CRITICAL').length,
      },
      customers: { affectedTenants },
      // Section 90 - an absent data source is named, never estimated.
      sales: inputs.sales ?? { unavailable: 'no CRM integration configured' },
      marketing: inputs.marketing ?? { unavailable: 'no marketing channel connected' },
      finance: inputs.finance ?? { unavailable: 'no billing integration configured' },
      decisionsNeeded: this.#decisionsFrom(open, pending, unhealthy),
    };

    this.#audit.append({
      actorType: 'agent',
      actorId: this.id,
      tenantId: null,
      action: 'ceo_command.compile_daily_brief',
      target: 'daily_brief',
      result: 'succeeded',
      reason: `${brief.decisionsNeeded.length} decisions needed`,
      correlationId: `ceo_command-${brief.generatedAt}`,
      metadata: {
        openIncidents: brief.platform.openIncidents,
        unhealthyAgents: brief.platform.unhealthyAgents,
      },
    });
    return brief;
  }

  /** Renders the brief as text. Unavailable sections say why. */
  render(brief: DailyBrief): string {
    const L: string[] = [];
    const val = <T,>(v: T | Unavailable, fmt: (t: T) => string): string =>
      isUnavailable(v) ? `UNAVAILABLE - ${v.unavailable}` : fmt(v);

    L.push('MAHSUMAH DAILY BRIEF');
    L.push('');
    L.push('PLATFORM');
    L.push(`  Open incidents:     ${brief.platform.openIncidents} (${brief.platform.criticalIncidents} critical)`);
    L.push(
      `  MTTR:               ${brief.platform.meanTimeToResolveMs === null ? 'UNAVAILABLE - no incident resolved yet' : `${Math.round(brief.platform.meanTimeToResolveMs / 60000)} min`}`,
    );
    L.push(`  Agents healthy:     ${brief.platform.agentsHealthy}/${brief.platform.agentsTotal}`);
    if (brief.platform.unhealthyAgents.length > 0) {
      L.push(`  Unhealthy:          ${brief.platform.unhealthyAgents.join(', ')}`);
    }
    if (brief.platform.autonomyFrozen) L.push('  Autonomy:           FROZEN');
    L.push('');
    L.push('SECURITY');
    L.push(`  Open incidents:     ${brief.security.openIncidents} (${brief.security.critical} critical)`);
    L.push('');
    L.push('CUSTOMERS');
    L.push(`  Tenants affected:   ${brief.customers.affectedTenants}`);
    L.push('');
    L.push(`SALES               ${val(brief.sales, (s) => `${s.qualified} qualified`)}`);
    L.push(`MARKETING           ${val(brief.marketing, (m) => `${m.awaitingApproval} awaiting approval`)}`);
    L.push(`FINANCE             ${val(brief.finance, (f) => `${f.overdue} overdue, ${f.renewals} renewals`)}`);
    L.push('');
    L.push('DECISIONS NEEDED');
    if (brief.decisionsNeeded.length === 0) {
      L.push('  None. Everything open is handled by policy or an agent.');
    } else {
      for (const d of brief.decisionsNeeded) {
        L.push(`  [${d.urgency}] ${d.title}`);
        L.push(`      why:        ${d.why}`);
        L.push(`      if ignored: ${d.ifIgnored}`);
        L.push(`      ref:        ${d.reference}`);
      }
    }
    return L.join('\n');
  }
}
