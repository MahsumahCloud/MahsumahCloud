import { randomUUID } from 'node:crypto';
import type { Clock } from '../core/clock.ts';
import { systemClock } from '../core/clock.ts';
import type { AuditLog } from '../core/audit.ts';
import type { ActionExecutor } from '../core/executor.ts';
import type { ApprovalEngine } from '../core/approval.ts';
import type { IncidentEngine } from '../core/incident.ts';
import type { HeartbeatMonitor } from '../runtime/heartbeat.ts';
import { TenantScope } from '../core/tenant.ts';
import type { Environment, RunStatus, Severity } from '../core/types.ts';
import type {
  CustomerService,
  Ticket,
  TicketReader,
  TicketWriter,
} from '../integrations/business-ports.ts';

/**
 * Section 29 - Customer Operations Agent.
 *
 * Every read is tenant scoped. The agent assembles the context a human would
 * need - which customer, what they own, what is currently broken for them - and
 * proposes a reply. It never sends anything: customer_ops.send_customer_message
 * is P3 and requires a scoped human approval, and a sent message cannot be
 * recalled.
 */

export type TicketCategory =
  | 'incident_report'
  | 'billing'
  | 'access'
  | 'how_to'
  | 'feature_request'
  | 'other';

export interface TicketAssessment {
  readonly ticketId: string;
  readonly tenantId: string;
  readonly category: TicketCategory;
  readonly urgency: Severity;
  /** True when the response-time commitment is already missed. */
  readonly slaBreached: boolean;
  /** Milliseconds until the SLA is missed; negative when already missed. */
  readonly slaRemainingMs: number | null;
  /** Open incidents that plausibly explain this ticket. */
  readonly relatedIncidentIds: readonly string[];
  readonly evidence: readonly string[];
}

export interface CustomerOpsRun {
  readonly runId: string;
  readonly correlationId: string;
  readonly startedAt: number;
  endedAt?: number;
  status: RunStatus;
  ticketsAssessed: number;
  notesCreated: number;
  draftsPrepared: number;
  escalations: number;
  errors: string[];
}

export interface CustomerOpsConfig {
  /** Fraction of the SLA window at which we warn rather than breach. */
  readonly slaWarnRatio: number;
  readonly environment: Environment;
}

export const DEFAULT_CUSTOMER_OPS: CustomerOpsConfig = {
  slaWarnRatio: 0.75,
  environment: 'production',
};

/** Deterministic classification. Keyword rules, not a model - section 12. */
const CATEGORY_RULES: ReadonlyArray<{ category: TicketCategory; patterns: RegExp }> = [
  { category: 'incident_report', patterns: /\b(down|outage|unavailable|error 5\d\d|not working|broken|timeout)\b/i },
  { category: 'billing', patterns: /\b(invoice|payment|charge|refund|billing|renewal|price)\b/i },
  { category: 'access', patterns: /\b(password|login|access|locked out|permission|2fa|mfa)\b/i },
  { category: 'how_to', patterns: /\b(how do i|how to|where is|can i|documentation|guide)\b/i },
  { category: 'feature_request', patterns: /\b(feature request|would be nice|please add|support for)\b/i },
];

export function classifyTicket(ticket: Ticket): TicketCategory {
  const text = `${ticket.subject} ${ticket.body}`;
  for (const rule of CATEGORY_RULES) {
    if (rule.patterns.test(text)) return rule.category;
  }
  return 'other';
}

export class CustomerOpsAgent {
  readonly id = 'customer_ops' as const;

  #reader: TicketReader;
  #writer: TicketWriter | null;
  #incidents: IncidentEngine;
  #executor: ActionExecutor;
  #approvals: ApprovalEngine;
  #audit: AuditLog;
  #heartbeat: HeartbeatMonitor;
  #clock: Clock;
  #config: CustomerOpsConfig;
  #runs: CustomerOpsRun[] = [];

  constructor(deps: {
    reader: TicketReader;
    writer?: TicketWriter | null;
    incidents: IncidentEngine;
    executor: ActionExecutor;
    approvals: ApprovalEngine;
    audit: AuditLog;
    heartbeat: HeartbeatMonitor;
    clock?: Clock;
    config?: CustomerOpsConfig;
  }) {
    this.#reader = deps.reader;
    this.#writer = deps.writer ?? null;
    this.#incidents = deps.incidents;
    this.#executor = deps.executor;
    this.#approvals = deps.approvals;
    this.#audit = deps.audit;
    this.#heartbeat = deps.heartbeat;
    this.#clock = deps.clock ?? systemClock;
    this.#config = deps.config ?? DEFAULT_CUSTOMER_OPS;
  }

  get runs(): readonly CustomerOpsRun[] {
    return this.#runs;
  }

  /**
   * Section 29 - assemble what the agent must know before it says anything:
   * who the customer is, what they own, and what is currently broken for them.
   * Read strictly through the ticket's own tenant scope.
   */
  async assess(ticket: Ticket): Promise<TicketAssessment> {
    const scope = TenantScope.forTenant(ticket.tenantId);
    const services = await this.#reader.listServices(ticket.tenantId);
    const service = ticket.serviceId
      ? services.find((s) => s.id === ticket.serviceId) ?? null
      : null;

    // Section 7 - only this tenant's incidents are ever visible.
    const related = this.#incidents
      .open(scope)
      .filter((i) => i.status !== 'resolved')
      .map((i) => i.id);

    const category = classifyTicket(ticket);
    const now = this.#clock.now();
    const { slaBreached, slaRemainingMs } = this.#sla(ticket, service, now);
    const urgency = this.#urgency(category, service, related.length, slaBreached);

    return {
      ticketId: ticket.id,
      tenantId: ticket.tenantId,
      category,
      urgency,
      slaBreached,
      slaRemainingMs,
      relatedIncidentIds: related,
      evidence: [
        `category=${category}`,
        `service=${service ? service.name : 'unidentified'}`,
        `openIncidentsForTenant=${related.length}`,
        slaRemainingMs === null
          ? 'sla=none'
          : `slaRemainingMs=${slaRemainingMs}${slaBreached ? ' (breached)' : ''}`,
        `ageMs=${now - ticket.createdAt}`,
      ],
    };
  }

  #sla(
    ticket: Ticket,
    service: CustomerService | null,
    now: number,
  ): { slaBreached: boolean; slaRemainingMs: number | null } {
    // The clock stops at first response; a ticket already answered is not
    // accruing breach even if it stays open.
    if (!service?.slaResponseMs) return { slaBreached: false, slaRemainingMs: null };
    if (ticket.firstResponseAt !== null) return { slaBreached: false, slaRemainingMs: null };
    const deadline = ticket.createdAt + service.slaResponseMs;
    const remaining = deadline - now;
    return { slaBreached: remaining < 0, slaRemainingMs: remaining };
  }

  #urgency(
    category: TicketCategory,
    service: CustomerService | null,
    relatedIncidents: number,
    slaBreached: boolean,
  ): Severity {
    if (slaBreached) return 'HIGH';
    // A customer reporting a problem we already know about is corroboration,
    // not a new unknown - but it is still the most urgent category.
    if (category === 'incident_report') return relatedIncidents > 0 ? 'HIGH' : 'MEDIUM';
    if (category === 'access') return 'MEDIUM';
    if (category === 'billing') return 'MEDIUM';
    if (service?.active === false) return 'MEDIUM';
    return 'LOW';
  }

  /**
   * Section 30 - proactive drafting. Produces a reply grounded in verified
   * state; it does not speculate about causes. The draft is saved unsent.
   */
  draftReply(ticket: Ticket, assessment: TicketAssessment): string {
    const lines: string[] = [];
    lines.push(`Regarding: ${ticket.subject}`);
    lines.push('');

    if (assessment.relatedIncidentIds.length > 0) {
      lines.push(
        'We have an active incident affecting your service and our team is working on it. ' +
          'We will update you as it progresses.',
      );
    } else if (assessment.category === 'incident_report') {
      lines.push(
        'Thank you for reporting this. We have not detected an incident on your service, ' +
          'so we are investigating your report specifically and will come back with what we find.',
      );
    } else if (assessment.category === 'billing') {
      lines.push('Thank you for getting in touch about your billing. We are reviewing your account and will respond shortly.');
    } else if (assessment.category === 'access') {
      lines.push('Thank you for contacting us about account access. We are checking this and will respond shortly.');
    } else {
      lines.push('Thank you for getting in touch. We are looking into this and will respond shortly.');
    }

    lines.push('');
    lines.push('Mahsumah Cloud Support');
    return lines.join('\n');
  }

  async sweep(): Promise<CustomerOpsRun> {
    const run: CustomerOpsRun = {
      runId: randomUUID(),
      correlationId: `customer_ops-${randomUUID().slice(0, 8)}`,
      startedAt: this.#clock.now(),
      status: 'running',
      ticketsAssessed: 0,
      notesCreated: 0,
      draftsPrepared: 0,
      escalations: 0,
      errors: [],
    };
    this.#runs.push(run);

    let tickets: readonly Ticket[];
    try {
      tickets = await this.#reader.listOpenTickets();
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      run.status = 'failed';
      run.endedAt = this.#clock.now();
      run.errors.push(detail);
      this.#audit.append({
        actorType: 'agent',
        actorId: this.id,
        tenantId: null,
        action: 'customer_ops.sweep',
        target: this.#reader.name,
        result: 'failed',
        reason: `ticket source unreachable: ${detail}`,
        correlationId: run.correlationId,
        metadata: {},
      });
      this.#heartbeat.beat(this.id, 'error');
      return run;
    }

    for (const ticket of tickets) {
      let assessment: TicketAssessment;
      try {
        assessment = await this.assess(ticket);
        run.ticketsAssessed++;
      } catch (err) {
        run.errors.push(`${ticket.id}: ${err instanceof Error ? err.message : String(err)}`);
        continue;
      }

      if (assessment.slaBreached || assessment.urgency === 'HIGH') run.escalations++;

      if (!this.#writer) continue; // read-only deployment

      // The internal note is P2 and never customer visible, so it goes through
      // the executor which enforces the allowlist and verifies it landed.
      const noteResult = await this.#executor.run(
        {
          action: 'customer_ops.create_internal_note',
          target: {
            resourceType: 'ticket',
            resourceId: ticket.id,
            tenantId: ticket.tenantId,
            environment: this.#config.environment,
          },
          agent: this.id,
          runId: run.runId,
          correlationId: run.correlationId,
          reason: `triage: ${assessment.category}, urgency ${assessment.urgency}`,
          evidence: assessment.evidence,
        },
        TenantScope.internalScope(),
      );
      if (noteResult.status === 'succeeded') run.notesCreated++;

      // Drafting is P1: it produces text, it does not send it.
      try {
        await this.#writer.saveDraftReply(ticket.id, this.draftReply(ticket, assessment));
        run.draftsPrepared++;
      } catch (err) {
        run.errors.push(`${ticket.id} draft: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    run.status = run.errors.length > 0 ? 'partially_completed' : 'completed';
    run.endedAt = this.#clock.now();
    this.#heartbeat.beat(this.id, run.errors.length > 0 ? 'error' : 'ok');
    this.#audit.append({
      actorType: 'agent',
      actorId: this.id,
      tenantId: null,
      action: 'customer_ops.sweep',
      target: this.#reader.name,
      result: run.errors.length > 0 ? 'failed' : 'succeeded',
      reason: `${run.ticketsAssessed} tickets assessed`,
      correlationId: run.correlationId,
      metadata: {
        notesCreated: run.notesCreated,
        draftsPrepared: run.draftsPrepared,
        escalations: run.escalations,
      },
    });
    return run;
  }

  /**
   * Requests approval to send a reply to the customer. Section 29 - sending is
   * P3, so this only ever produces a request.
   */
  requestSendApproval(ticket: Ticket, assessment: TicketAssessment, body: string) {
    return this.#approvals.request({
      action: 'customer_ops.send_customer_message',
      target: {
        resourceType: 'ticket',
        resourceId: ticket.id,
        tenantId: ticket.tenantId,
        environment: this.#config.environment,
      },
      agent: this.id,
      requestedBy: 'agent:customer_ops',
      reason: `reply to "${ticket.subject}"`,
      evidence: [...assessment.evidence, `bodyLength=${body.length}`],
      risk: assessment.urgency,
      predictedEffect: 'one message is delivered to the customer contact on this ticket',
      rollback: 'none - a sent message cannot be recalled',
      correlationId: `customer_ops-${ticket.id}`,
      ttlMs: 60 * 60_000,
    });
  }
}
