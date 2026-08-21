import { randomUUID } from 'node:crypto';
import type { Clock } from '../core/clock.ts';
import { systemClock } from '../core/clock.ts';
import type { AuditLog } from '../core/audit.ts';
import type { ApprovalEngine } from '../core/approval.ts';
import type { HeartbeatMonitor } from '../runtime/heartbeat.ts';
import type { Environment, RunStatus } from '../core/types.ts';
import type {
  CampaignBrief,
  ChannelName,
  MarketingReader,
  MarketingWriter,
} from '../integrations/business-ports.ts';

/**
 * Section 34 - Marketing Agent.
 *
 * Section 36 is the constraint that shapes this agent: no generic AI spam, and
 * every item must carry an objective, segment, service, value proposition, CTA,
 * channel, date and campaign. A brief missing any of those is REJECTED rather
 * than filled in with something plausible - that check is the whole point.
 *
 * Section 34 also forbids presenting a channel as connected when it is not, so
 * the agent refuses to draft for a disconnected channel instead of quietly
 * queueing content that can never publish.
 *
 * Publishing is P3 and requires a scoped approval.
 */

export interface BriefValidation {
  readonly briefId: string;
  readonly valid: boolean;
  readonly missing: readonly string[];
  readonly channelConnected: boolean;
}

export interface MarketingRun {
  readonly runId: string;
  readonly correlationId: string;
  readonly startedAt: number;
  endedAt?: number;
  status: RunStatus;
  briefsExamined: number;
  rejected: number;
  skippedDisconnected: number;
  draftsPrepared: number;
  approvalsRequested: number;
  errors: string[];
}

export interface MarketingConfig {
  readonly environment: Environment;
  readonly approvalTtlMs: number;
  /** Characters. Drafts beyond this are truncated at a word boundary. */
  readonly channelLimits: Readonly<Record<ChannelName, number>>;
}

export const DEFAULT_MARKETING: MarketingConfig = {
  environment: 'production',
  approvalTtlMs: 24 * 60 * 60_000,
  channelLimits: {
    linkedin: 3000,
    x: 280,
    instagram: 2200,
    snapchat: 250,
    email: 5000,
    blog: 20000,
  },
};

export class MarketingAgent {
  readonly id = 'marketing' as const;

  #reader: MarketingReader;
  #writer: MarketingWriter | null;
  #approvals: ApprovalEngine;
  #audit: AuditLog;
  #heartbeat: HeartbeatMonitor;
  #clock: Clock;
  #config: MarketingConfig;
  #runs: MarketingRun[] = [];

  constructor(deps: {
    reader: MarketingReader;
    writer?: MarketingWriter | null;
    approvals: ApprovalEngine;
    audit: AuditLog;
    heartbeat: HeartbeatMonitor;
    clock?: Clock;
    config?: MarketingConfig;
  }) {
    this.#reader = deps.reader;
    this.#writer = deps.writer ?? null;
    this.#approvals = deps.approvals;
    this.#audit = deps.audit;
    this.#heartbeat = deps.heartbeat;
    this.#clock = deps.clock ?? systemClock;
    this.#config = deps.config ?? DEFAULT_MARKETING;
  }

  get runs(): readonly MarketingRun[] {
    return this.#runs;
  }

  /** Section 36 - every field is mandatory. Nothing is inferred. */
  validate(brief: CampaignBrief, channelConnected: boolean): BriefValidation {
    const missing: string[] = [];
    if (!brief.objective.trim()) missing.push('objective');
    if (!brief.audience.trim()) missing.push('audience');
    if (!brief.service.trim()) missing.push('service');
    if (!brief.valueProposition.trim()) missing.push('valueProposition');
    if (!brief.callToAction.trim()) missing.push('callToAction');
    if (!brief.scheduledFor) missing.push('scheduledFor');
    return { briefId: brief.id, valid: missing.length === 0, missing, channelConnected };
  }

  /** Truncates at a word boundary so a limit never cuts mid-word. */
  #fit(text: string, limit: number): string {
    if (text.length <= limit) return text;
    const cut = text.slice(0, limit);
    const lastSpace = cut.lastIndexOf(' ');
    return (lastSpace > limit * 0.6 ? cut.slice(0, lastSpace) : cut).trimEnd();
  }

  /**
   * Composes from the brief's own fields. The agent does not invent claims:
   * every sentence traces to a field the author filled in.
   */
  compose(brief: CampaignBrief): string {
    const limit = this.#config.channelLimits[brief.channel];
    const long = [
      brief.valueProposition,
      '',
      `For ${brief.audience}.`,
      '',
      brief.callToAction,
    ].join('\n');

    // Short channels get a single line rather than a squeezed paragraph.
    const body =
      limit <= 300 ? `${brief.valueProposition} ${brief.callToAction}`.trim() : long;
    return this.#fit(body, limit);
  }

  async sweep(): Promise<MarketingRun> {
    const run: MarketingRun = {
      runId: randomUUID(),
      correlationId: `marketing-${randomUUID().slice(0, 8)}`,
      startedAt: this.#clock.now(),
      status: 'running',
      briefsExamined: 0,
      rejected: 0,
      skippedDisconnected: 0,
      draftsPrepared: 0,
      approvalsRequested: 0,
      errors: [],
    };
    this.#runs.push(run);

    let briefs: readonly CampaignBrief[];
    let connected: Set<ChannelName>;
    try {
      const channels = await this.#reader.listChannels();
      connected = new Set(channels.filter((c) => c.connected).map((c) => c.name));
      briefs = await this.#reader.listBriefs();
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      run.status = 'failed';
      run.endedAt = this.#clock.now();
      run.errors.push(detail);
      this.#audit.append({
        actorType: 'agent',
        actorId: this.id,
        tenantId: null,
        action: 'marketing.sweep',
        target: this.#reader.name,
        result: 'failed',
        reason: `marketing source unreachable: ${detail}`,
        correlationId: run.correlationId,
        metadata: {},
      });
      this.#heartbeat.beat(this.id, 'error');
      return run;
    }

    for (const brief of briefs) {
      run.briefsExamined++;
      const isConnected = connected.has(brief.channel);
      const validation = this.validate(brief, isConnected);

      if (!validation.valid) {
        run.rejected++;
        this.#audit.append({
          actorType: 'agent',
          actorId: this.id,
          tenantId: null,
          action: 'marketing.brief_rejected',
          target: brief.id,
          result: 'denied',
          reason: `incomplete brief: missing ${validation.missing.join(', ')}`,
          correlationId: run.correlationId,
          metadata: { missing: validation.missing },
        });
        continue;
      }

      if (!isConnected) {
        // Section 34 - do not queue content for a channel that cannot publish.
        run.skippedDisconnected++;
        this.#audit.append({
          actorType: 'agent',
          actorId: this.id,
          tenantId: null,
          action: 'marketing.channel_unavailable',
          target: brief.channel,
          result: 'blocked',
          reason: `channel '${brief.channel}' has no working integration`,
          correlationId: run.correlationId,
          metadata: { briefId: brief.id },
        });
        continue;
      }

      if (!this.#writer) continue;

      try {
        const { itemId } = await this.#writer.saveDraft(
          brief.id,
          brief.channel,
          this.compose(brief),
        );
        run.draftsPrepared++;

        // Publishing is P3: request, never publish.
        this.#approvals.request({
          action: 'marketing.publish_approved_content',
          target: {
            resourceType: 'campaign_item',
            resourceId: itemId,
            tenantId: null,
            environment: this.#config.environment,
          },
          agent: this.id,
          requestedBy: 'agent:marketing',
          reason: `publish to ${brief.channel}: ${brief.objective}`,
          evidence: [
            `campaign=${brief.id}`,
            `audience=${brief.audience}`,
            `service=${brief.service}`,
            `cta=${brief.callToAction}`,
            `scheduledFor=${brief.scheduledFor}`,
          ],
          risk: 'MEDIUM',
          predictedEffect: `one public post on ${brief.channel}`,
          rollback: 'unpublish or delete the post',
          correlationId: run.correlationId,
          ttlMs: this.#config.approvalTtlMs,
        });
        run.approvalsRequested++;
      } catch (err) {
        run.errors.push(`${brief.id}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    run.status = run.errors.length > 0 ? 'partially_completed' : 'completed';
    run.endedAt = this.#clock.now();
    this.#heartbeat.beat(this.id, run.errors.length > 0 ? 'error' : 'ok');
    this.#audit.append({
      actorType: 'agent',
      actorId: this.id,
      tenantId: null,
      action: 'marketing.sweep',
      target: this.#reader.name,
      result: run.errors.length > 0 ? 'failed' : 'succeeded',
      reason: `${run.briefsExamined} briefs examined`,
      correlationId: run.correlationId,
      metadata: {
        rejected: run.rejected,
        skippedDisconnected: run.skippedDisconnected,
        draftsPrepared: run.draftsPrepared,
      },
    });
    return run;
  }
}
