import { randomUUID } from 'node:crypto';
import type { Clock } from '../core/clock.ts';
import { systemClock } from '../core/clock.ts';
import type { AuditLog } from '../core/audit.ts';
import type { HeartbeatMonitor } from '../runtime/heartbeat.ts';
import type { RunStatus } from '../core/types.ts';
import type { Lead, LeadReader, LeadStage, LeadWriter } from '../integrations/business-ports.ts';

/**
 * Section 31 - Sales Agent.
 *
 * Section 32 sets hard limits: no unlawful scraping, no mass unsolicited
 * sending, no fabricated company information, no impersonation, no invented
 * discounts. This agent therefore does research, qualification and drafting
 * ONLY. Nothing it produces is sent: sales.draft_outreach is P1, and there is
 * no send action in the catalogue at all, so sending is not merely disabled -
 * it does not exist as a capability.
 *
 * Scoring uses only facts the lead itself supplied through the port. It never
 * infers company size, budget or intent from nothing, because a fabricated
 * score is worse than no score.
 */

export interface Qualification {
  readonly leadId: string;
  readonly score: number;
  readonly stage: LeadStage;
  readonly reason: string;
  readonly recommendedServices: readonly string[];
  readonly missingInformation: readonly string[];
}

export interface SalesRun {
  readonly runId: string;
  readonly correlationId: string;
  readonly startedAt: number;
  endedAt?: number;
  status: RunStatus;
  leadsExamined: number;
  qualified: number;
  needsResearch: number;
  staleFlagged: number;
  draftsPrepared: number;
  errors: string[];
}

export interface SalesConfig {
  /** Score at or above which a lead is considered qualified. */
  readonly qualifyThreshold: number;
  /** Inactivity after which a lead is flagged stale. */
  readonly staleAfterMs: number;
  /** Mahsumah services the agent may recommend. */
  readonly catalogue: readonly string[];
}

export const DEFAULT_SALES: SalesConfig = {
  qualifyThreshold: 60,
  staleAfterMs: 14 * 24 * 60 * 60_000,
  catalogue: [
    'Managed Hosting',
    'Managed Kubernetes',
    'Backup and Recovery',
    'Managed Databases',
    'AI Compute',
  ],
};

/**
 * Maps a stated need to services. Explicit rules; no invention.
 *
 * `generic: true` marks a term broad enough to appear inside a more specific
 * need - "kubernetes hosting" contains "hosting", but the customer is asking
 * for Kubernetes, not shared hosting. A generic match is therefore used only
 * when nothing specific matched the same phrase, so the broad term cannot
 * shadow the precise one.
 */
const NEED_TO_SERVICE: ReadonlyArray<{ pattern: RegExp; service: string; generic?: boolean }> = [
  { pattern: /\b(website|hosting|wordpress|cpanel)\b/i, service: 'Managed Hosting', generic: true },
  { pattern: /\b(kubernetes|k8s|container|docker)\b/i, service: 'Managed Kubernetes' },
  { pattern: /\b(backup|recovery|disaster|restore)\b/i, service: 'Backup and Recovery' },
  { pattern: /\b(database|postgres|mysql|rds)\b/i, service: 'Managed Databases' },
  { pattern: /\b(ai|ml|inference|gpu|model)\b/i, service: 'AI Compute' },
];

/** Services implied by one stated need, most specific winning. */
function servicesForNeed(need: string): string[] {
  const matched = NEED_TO_SERVICE.filter((r) => r.pattern.test(need));
  const specific = matched.filter((r) => !r.generic);
  return (specific.length > 0 ? specific : matched).map((r) => r.service);
}

export class SalesAgent {
  readonly id = 'sales' as const;

  #reader: LeadReader;
  #writer: LeadWriter | null;
  #audit: AuditLog;
  #heartbeat: HeartbeatMonitor;
  #clock: Clock;
  #config: SalesConfig;
  #runs: SalesRun[] = [];

  constructor(deps: {
    reader: LeadReader;
    writer?: LeadWriter | null;
    audit: AuditLog;
    heartbeat: HeartbeatMonitor;
    clock?: Clock;
    config?: SalesConfig;
  }) {
    this.#reader = deps.reader;
    this.#writer = deps.writer ?? null;
    this.#audit = deps.audit;
    this.#heartbeat = deps.heartbeat;
    this.#clock = deps.clock ?? systemClock;
    this.#config = deps.config ?? DEFAULT_SALES;
  }

  get runs(): readonly SalesRun[] {
    return this.#runs;
  }

  /**
   * Deterministic qualification. Every point is traceable to a fact the lead
   * actually provided; anything absent is reported as missing rather than
   * guessed.
   */
  qualify(lead: Lead): Qualification {
    let score = 0;
    const reasons: string[] = [];
    const missing: string[] = [];

    if (lead.statedNeeds.length > 0) {
      score += 30;
      reasons.push(`${lead.statedNeeds.length} stated need(s)`);
    } else {
      missing.push('stated needs');
    }

    if (lead.contactName) {
      score += 15;
      reasons.push('named contact');
    } else {
      missing.push('contact name');
    }

    if (lead.industry) {
      score += 10;
      reasons.push(`industry: ${lead.industry}`);
    } else {
      missing.push('industry');
    }

    if (lead.companySize !== null) {
      // Larger organisations are worth more only up to a point; this is a
      // coarse band, not a pretence at precision.
      const band = lead.companySize >= 200 ? 25 : lead.companySize >= 50 ? 20 : 10;
      score += band;
      reasons.push(`company size ${lead.companySize}`);
    } else {
      missing.push('company size');
    }

    // Inbound leads convert better than sourced ones; that is an observable
    // property of the source field, not a judgement about the company.
    if (/\b(inbound|referral|website|demo)\b/i.test(lead.source)) {
      score += 20;
      reasons.push(`warm source: ${lead.source}`);
    }

    const recommendedServices = [
      ...new Set(lead.statedNeeds.flatMap(servicesForNeed)),
    ].filter((s) => this.#config.catalogue.includes(s));

    const qualified = score >= this.#config.qualifyThreshold;
    const stage: LeadStage = qualified
      ? recommendedServices.length > 0
        ? 'contact_ready'
        : 'qualified'
      : missing.length > 0
        ? 'researching'
        : 'nurture';

    return {
      leadId: lead.id,
      score,
      stage,
      reason: reasons.length > 0 ? reasons.join('; ') : 'no qualifying signals present',
      recommendedServices,
      missingInformation: missing,
    };
  }

  /**
   * Section 32 - a draft, never a send. It states only what the lead told us
   * and what Mahsumah actually offers. No pricing, no discounts, no claims
   * about the lead's current provider.
   */
  draftOutreach(lead: Lead, q: Qualification): string {
    const services = q.recommendedServices.length > 0
      ? q.recommendedServices.join(', ')
      : 'our managed cloud services';
    const needs = lead.statedNeeds.length > 0 ? lead.statedNeeds.join('; ') : null;

    return [
      `Subject: ${lead.company} - managed cloud on Saudi infrastructure`,
      '',
      lead.contactName ? `Hello ${lead.contactName},` : 'Hello,',
      '',
      needs
        ? `You told us you are looking at: ${needs}.`
        : 'You reached out to us about managed cloud infrastructure.',
      '',
      `Mahsumah Cloud runs ${services} on Saudi infrastructure, so your team can focus on the product rather than the servers.`,
      '',
      'Would a short call be useful to see whether we are a fit?',
      '',
      'Mahsumah Cloud',
      '',
      '[DRAFT - not sent. Requires human review and send.]',
    ].join('\n');
  }

  async sweep(): Promise<SalesRun> {
    const run: SalesRun = {
      runId: randomUUID(),
      correlationId: `sales-${randomUUID().slice(0, 8)}`,
      startedAt: this.#clock.now(),
      status: 'running',
      leadsExamined: 0,
      qualified: 0,
      needsResearch: 0,
      staleFlagged: 0,
      draftsPrepared: 0,
      errors: [],
    };
    this.#runs.push(run);

    let leads: readonly Lead[];
    try {
      leads = await this.#reader.listLeads();
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      run.status = 'failed';
      run.endedAt = this.#clock.now();
      run.errors.push(detail);
      this.#audit.append({
        actorType: 'agent',
        actorId: this.id,
        tenantId: null,
        action: 'sales.sweep',
        target: this.#reader.name,
        result: 'failed',
        reason: `lead source unreachable: ${detail}`,
        correlationId: run.correlationId,
        metadata: {},
      });
      this.#heartbeat.beat(this.id, 'error');
      return run;
    }

    const now = this.#clock.now();
    for (const lead of leads) {
      run.leadsExamined++;
      const q = this.qualify(lead);

      if (q.score >= this.#config.qualifyThreshold) run.qualified++;
      if (q.missingInformation.length > 0) run.needsResearch++;
      if (now - lead.lastActivityAt > this.#config.staleAfterMs) run.staleFlagged++;

      if (!this.#writer) continue;

      try {
        await this.#writer.saveQualification(lead.id, {
          score: q.score,
          reason: q.reason,
          recommendedServices: q.recommendedServices,
          stage: q.stage,
        });
        if (q.stage === 'contact_ready') {
          this.draftOutreach(lead, q);
          run.draftsPrepared++;
        }
      } catch (err) {
        run.errors.push(`${lead.id}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    run.status = run.errors.length > 0 ? 'partially_completed' : 'completed';
    run.endedAt = this.#clock.now();
    this.#heartbeat.beat(this.id, run.errors.length > 0 ? 'error' : 'ok');
    this.#audit.append({
      actorType: 'agent',
      actorId: this.id,
      tenantId: null,
      action: 'sales.sweep',
      target: this.#reader.name,
      result: run.errors.length > 0 ? 'failed' : 'succeeded',
      reason: `${run.leadsExamined} leads examined`,
      correlationId: run.correlationId,
      metadata: {
        qualified: run.qualified,
        needsResearch: run.needsResearch,
        staleFlagged: run.staleFlagged,
        draftsPrepared: run.draftsPrepared,
      },
    });
    return run;
  }
}
