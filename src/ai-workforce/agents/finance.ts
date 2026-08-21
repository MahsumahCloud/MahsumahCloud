import { randomUUID } from 'node:crypto';
import type { Clock } from '../core/clock.ts';
import { systemClock } from '../core/clock.ts';
import type { AuditLog } from '../core/audit.ts';
import type { ActionExecutor } from '../core/executor.ts';
import type { HeartbeatMonitor } from '../runtime/heartbeat.ts';
import { TenantScope } from '../core/tenant.ts';
import type { Environment, RunStatus } from '../core/types.ts';
import type {
  BillingReader,
  BillingWriter,
  Invoice,
  Subscription,
} from '../integrations/business-ports.ts';

/**
 * Section 37 - Finance Operations Agent.
 *
 * An operational finance assistant, not autonomous banking. Section 37 is
 * explicit: never make bank transfers, never initiate financial transfers.
 * finance.initiate_transfer is P4 in the catalogue and therefore unreachable.
 *
 * Section 38 also says not to suspend customers automatically unless Mahsumah
 * explicitly configures such a policy later - there is no suspend action in the
 * catalogue, so the agent cannot suspend anyone.
 *
 * All money arithmetic is done in integer minor units. Floating point on
 * currency produces wrong totals, and a finance agent that reports a wrong
 * total is worse than one that reports nothing.
 */

export interface OverdueInvoice {
  readonly invoice: Invoice;
  readonly daysOverdue: number;
  readonly escalation: 'reminder' | 'follow_up' | 'escalate';
}

export interface UpcomingRenewal {
  readonly subscription: Subscription;
  readonly daysUntil: number;
}

export interface FinanceRun {
  readonly runId: string;
  readonly correlationId: string;
  readonly startedAt: number;
  endedAt?: number;
  status: RunStatus;
  invoicesExamined: number;
  overdueFound: number;
  renewalsUpcoming: number;
  remindersCreated: number;
  errors: string[];
}

export interface FinanceConfig {
  /** How far ahead a renewal is considered upcoming. */
  readonly renewalHorizonMs: number;
  /** Days overdue at which the tone escalates. */
  readonly followUpAfterDays: number;
  readonly escalateAfterDays: number;
  readonly environment: Environment;
}

const DAY = 24 * 60 * 60_000;

export const DEFAULT_FINANCE: FinanceConfig = {
  renewalHorizonMs: 30 * DAY,
  followUpAfterDays: 7,
  escalateAfterDays: 30,
  // Section 79 - finance.generate_renewal_reminder is declared non-production
  // only, so the default configuration matches what the catalogue permits.
  environment: 'staging',
};

/** Sums amounts in minor units. Returns null if currencies are mixed. */
export function sumSameCurrency(
  items: ReadonlyArray<{ amount: number; currency: string }>,
): { total: number; currency: string } | null {
  if (items.length === 0) return { total: 0, currency: 'SAR' };
  const currency = items[0]!.currency;
  if (!items.every((i) => i.currency === currency)) return null;
  return { total: items.reduce((sum, i) => sum + i.amount, 0), currency };
}

export class FinanceAgent {
  readonly id = 'finance' as const;

  #reader: BillingReader;
  #writer: BillingWriter | null;
  #executor: ActionExecutor;
  #audit: AuditLog;
  #heartbeat: HeartbeatMonitor;
  #clock: Clock;
  #config: FinanceConfig;
  #runs: FinanceRun[] = [];

  constructor(deps: {
    reader: BillingReader;
    writer?: BillingWriter | null;
    executor: ActionExecutor;
    audit: AuditLog;
    heartbeat: HeartbeatMonitor;
    clock?: Clock;
    config?: FinanceConfig;
  }) {
    this.#reader = deps.reader;
    this.#writer = deps.writer ?? null;
    this.#executor = deps.executor;
    this.#audit = deps.audit;
    this.#heartbeat = deps.heartbeat;
    this.#clock = deps.clock ?? systemClock;
    this.#config = deps.config ?? DEFAULT_FINANCE;
  }

  get runs(): readonly FinanceRun[] {
    return this.#runs;
  }

  overdue(invoices: readonly Invoice[]): OverdueInvoice[] {
    const now = this.#clock.now();
    return invoices
      .filter((i) => i.paidAt === null && i.dueAt < now)
      .map((invoice) => {
        const daysOverdue = Math.floor((now - invoice.dueAt) / DAY);
        const escalation: OverdueInvoice['escalation'] =
          daysOverdue >= this.#config.escalateAfterDays
            ? 'escalate'
            : daysOverdue >= this.#config.followUpAfterDays
              ? 'follow_up'
              : 'reminder';
        return { invoice, daysOverdue, escalation };
      })
      .sort((a, b) => b.daysOverdue - a.daysOverdue);
  }

  upcomingRenewals(subs: readonly Subscription[]): UpcomingRenewal[] {
    const now = this.#clock.now();
    return subs
      .filter((s) => s.renewsAt >= now && s.renewsAt - now <= this.#config.renewalHorizonMs)
      .map((subscription) => ({
        subscription,
        daysUntil: Math.floor((subscription.renewsAt - now) / DAY),
      }))
      .sort((a, b) => a.daysUntil - b.daysUntil);
  }

  /** Section 47 - collections and revenue metrics, tenant scoped. */
  metrics(
    invoices: readonly Invoice[],
    scope: TenantScope,
  ): { outstanding: number | null; currency: string | null; overdueCount: number } {
    const visible = invoices.filter((i) => scope.canAccess(i.tenantId));
    const unpaid = visible.filter((i) => i.paidAt === null);
    const sum = sumSameCurrency(unpaid);
    return {
      outstanding: sum?.total ?? null,
      currency: sum?.currency ?? null,
      overdueCount: this.overdue(visible).length,
    };
  }

  async sweep(): Promise<FinanceRun> {
    const run: FinanceRun = {
      runId: randomUUID(),
      correlationId: `finance-${randomUUID().slice(0, 8)}`,
      startedAt: this.#clock.now(),
      status: 'running',
      invoicesExamined: 0,
      overdueFound: 0,
      renewalsUpcoming: 0,
      remindersCreated: 0,
      errors: [],
    };
    this.#runs.push(run);

    let invoices: readonly Invoice[];
    let subs: readonly Subscription[];
    try {
      invoices = await this.#reader.listInvoices();
      subs = await this.#reader.listSubscriptions();
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      run.status = 'failed';
      run.endedAt = this.#clock.now();
      run.errors.push(detail);
      this.#audit.append({
        actorType: 'agent',
        actorId: this.id,
        tenantId: null,
        action: 'finance.sweep',
        target: this.#reader.name,
        result: 'failed',
        reason: `billing source unreachable: ${detail}`,
        correlationId: run.correlationId,
        metadata: {},
      });
      this.#heartbeat.beat(this.id, 'error');
      return run;
    }

    run.invoicesExamined = invoices.length;
    const overdue = this.overdue(invoices);
    run.overdueFound = overdue.length;
    const renewals = this.upcomingRenewals(subs);
    run.renewalsUpcoming = renewals.length;

    for (const { subscription, daysUntil } of renewals) {
      if (!this.#writer) break; // read-only deployment

      // Section 38 - a reminder record only. No customer contact, no charge.
      const result = await this.#executor.run(
        {
          action: 'finance.generate_renewal_reminder',
          target: {
            resourceType: 'subscription',
            resourceId: subscription.id,
            tenantId: subscription.tenantId,
            environment: this.#config.environment,
          },
          agent: this.id,
          runId: run.runId,
          correlationId: run.correlationId,
          reason: `${subscription.serviceName} renews in ${daysUntil} day(s)`,
          evidence: [
            `renewsAt=${subscription.renewsAt}`,
            `autoRenew=${subscription.autoRenew}`,
            `amountMinorUnits=${subscription.amount} ${subscription.currency}`,
          ],
        },
        TenantScope.internalScope(),
      );
      if (result.status === 'succeeded') run.remindersCreated++;
    }

    run.status = run.errors.length > 0 ? 'partially_completed' : 'completed';
    run.endedAt = this.#clock.now();
    this.#heartbeat.beat(this.id, run.errors.length > 0 ? 'error' : 'ok');
    this.#audit.append({
      actorType: 'agent',
      actorId: this.id,
      tenantId: null,
      action: 'finance.sweep',
      target: this.#reader.name,
      result: run.errors.length > 0 ? 'failed' : 'succeeded',
      reason: `${run.invoicesExamined} invoices, ${run.overdueFound} overdue`,
      correlationId: run.correlationId,
      metadata: {
        renewalsUpcoming: run.renewalsUpcoming,
        remindersCreated: run.remindersCreated,
      },
    });
    return run;
  }
}
