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
import type { AutonomyConfig } from '../core/types.ts';

import { SecurityAgent } from '../agents/security.ts';
import { CustomerOpsAgent, classifyTicket } from '../agents/customer-ops.ts';
import { SalesAgent } from '../agents/sales.ts';
import { MarketingAgent } from '../agents/marketing.ts';
import { FinanceAgent, sumSameCurrency } from '../agents/finance.ts';
import { CeoCommandAgent, isUnavailable } from '../agents/ceo-command.ts';

import type {
  AuthEvent,
  CampaignBrief,
  Channel,
  CustomerService,
  Invoice,
  Lead,
  Subscription,
  Ticket,
} from '../integrations/business-ports.ts';

/**
 * Tests for the six business agents. As in the Cloud Ops E2E suite, the
 * providers are TEST DOUBLES confined to this file; everything they feed -
 * policy, approvals, incidents, audit - is the real implementation.
 */

const T0 = 1_700_000_000_000;
const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

const approvers: ApproverDirectory = { canApprove: (u) => u === 'ahmed' };

function base(autonomy: AutonomyConfig = defaultLaunchAutonomy()) {
  const clock = new FixedClock(T0);
  const audit = new AuditLog(clock);
  const kill = new KillSwitchRegistry(audit);
  const registry = buildActionRegistry();
  const policy = new PolicyEngine(registry, kill, audit, autonomy, clock);
  const approvals = new ApprovalEngine(audit, approvers, clock);
  const executor = new ActionExecutor(registry, policy, approvals, audit);
  const incidents = new IncidentEngine(audit, clock);
  const heartbeat = new HeartbeatMonitor(audit, undefined, clock);
  return { clock, audit, kill, registry, policy, approvals, executor, incidents, heartbeat };
}

// ===========================================================================
describe('Section 27 - Security agent', () => {
  const evt = (o: Partial<AuthEvent> = {}): AuthEvent => ({
    id: `e-${Math.random()}`,
    kind: 'login_failure',
    actorId: 'user-1',
    tenantId: 'tenant-a',
    sourceIp: '1.2.3.4',
    country: 'SA',
    at: T0,
    userAgent: null,
    ...o,
  });

  function agent(events: AuthEvent[], alerts: never[] = [], throwOn = false) {
    const h = base();
    const reader = {
      name: 'fake-siem',
      async listAuthEvents() {
        if (throwOn) throw new Error('log source timeout');
        return events;
      },
      async listSecurityAlerts() {
        if (throwOn) throw new Error('log source timeout');
        return alerts;
      },
    };
    h.heartbeat.expect('security');
    return {
      ...h,
      agent: new SecurityAgent({
        reader,
        incidents: h.incidents,
        audit: h.audit,
        heartbeat: h.heartbeat,
        clock: h.clock,
      }),
    };
  }

  test('repeated failures are correlated into a brute-force finding', () => {
    const { agent: a } = agent([]);
    const findings = a.correlate(Array.from({ length: 6 }, () => evt()));
    assert.equal(findings.length, 1);
    assert.equal(findings[0]!.kind, 'brute_force');
    assert.equal(findings[0]!.severity, 'HIGH');
  });

  test('a success after repeated failure is CRITICAL, not HIGH', () => {
    const { agent: a } = agent([]);
    const events = [...Array.from({ length: 6 }, () => evt()), evt({ kind: 'login_success' })];
    const bruteForce = a.correlate(events).find((f) => f.kind === 'brute_force')!;
    assert.equal(bruteForce.severity, 'CRITICAL');
    assert.match(bruteForce.evidence.join(' '), /successful login followed/);
  });

  test('below threshold produces no finding', () => {
    const { agent: a } = agent([]);
    assert.deepEqual(a.correlate([evt(), evt()]), []);
  });

  test('multi-country authentication is flagged', () => {
    const { agent: a } = agent([]);
    const findings = a.correlate([
      evt({ kind: 'login_success', country: 'SA' }),
      evt({ kind: 'login_success', country: 'DE' }),
    ]);
    assert.equal(findings.length, 1);
    assert.equal(findings[0]!.kind, 'impossible_travel');
  });

  test('a sweep opens a security incident with escalated severity', async () => {
    const { agent: a, incidents } = agent(Array.from({ length: 6 }, () => evt()));
    const run = await a.sweep();
    assert.equal(run.status, 'completed');
    assert.equal(run.incidentsOpened, 1);
    const [incident] = incidents.open(TenantScope.internalScope());
    // securityRisk=true in production forces CRITICAL by section 26.
    assert.equal(incident!.severity, 'CRITICAL');
    assert.equal(incident!.category, 'security');
    assert.equal(incident!.status, 'recommendation');
  });

  test('the agent recommends containment but never contains', async () => {
    const { agent: a, incidents, audit } = agent(Array.from({ length: 6 }, () => evt()));
    await a.sweep();
    const [incident] = incidents.open(TenantScope.internalScope());
    assert.ok(incident!.recommendation, 'a recommendation is attached');
    // No mutating action was ever executed.
    assert.equal(audit.query({ action: 'security.modify_firewall_rules' }).length, 0);
  });

  test('a dead signal source fails loudly and never reports "no threats"', async () => {
    const { agent: a, audit, heartbeat, incidents } = agent([], [], true);
    const run = await a.sweep();
    assert.equal(run.status, 'failed');
    assert.equal(incidents.open(TenantScope.internalScope()).length, 0);
    assert.equal(audit.query({ action: 'security.sweep', result: 'failed' }).length, 1);
    assert.equal(heartbeat.report('security').consecutiveErrors, 1);
  });

  test('repeated sweeps do not duplicate incidents', async () => {
    const { agent: a, incidents } = agent(Array.from({ length: 6 }, () => evt()));
    await a.sweep();
    await a.sweep();
    assert.equal(incidents.open(TenantScope.internalScope()).length, 1);
  });
});

// ===========================================================================
describe('Section 29 - Customer Operations agent', () => {
  const SERVICE: CustomerService = {
    id: 'svc-1',
    tenantId: 'tenant-a',
    name: 'Managed Hosting',
    active: true,
    slaResponseMs: 4 * HOUR,
  };

  const ticket = (o: Partial<Ticket> = {}): Ticket => ({
    id: 't-1',
    tenantId: 'tenant-a',
    subject: 'Site is down',
    body: 'Our website returns error 503 and is not working.',
    status: 'new',
    createdAt: T0,
    lastCustomerReplyAt: null,
    firstResponseAt: null,
    serviceId: 'svc-1',
    ...o,
  });

  function agent(tickets: Ticket[], opts: { readOnly?: boolean; throwOn?: boolean } = {}) {
    const h = base({
      enabledLevels: new Set([
        PermissionLevel.P0_READ,
        PermissionLevel.P1_RECOMMEND,
        PermissionLevel.P2_SAFE_AUTONOMOUS,
        PermissionLevel.P3_APPROVAL_REQUIRED,
      ]),
      enabledP2Actions: new Set(['customer_ops.create_internal_note']),
    });
    const notes: string[] = [];
    const drafts: string[] = [];
    const reader = {
      name: 'fake-helpdesk',
      async listOpenTickets() {
        if (opts.throwOn) throw new Error('helpdesk unreachable');
        return tickets;
      },
      async listServices() {
        return [SERVICE];
      },
    };
    const writer = {
      async addInternalNote(_id: string, note: string) {
        notes.push(note);
        return { noteId: `n-${notes.length}` };
      },
      async saveDraftReply(_id: string, body: string) {
        drafts.push(body);
        return { draftId: `d-${drafts.length}` };
      },
      async getNote(id: string) {
        return { id, internal: true };
      },
      async getDraft(id: string) {
        return { id, sent: false };
      },
    };
    h.executor.registerHandler('customer_ops.create_internal_note', {
      async execute(req) {
        return writer.addInternalNote(req.target.resourceId, req.reason);
      },
      async verify(_req, res) {
        const note = await writer.getNote((res as { noteId: string }).noteId);
        return note?.internal === true;
      },
    });
    h.heartbeat.expect('customer_ops');
    return {
      ...h,
      notes,
      drafts,
      agent: new CustomerOpsAgent({
        reader,
        writer: opts.readOnly ? null : writer,
        incidents: h.incidents,
        executor: h.executor,
        approvals: h.approvals,
        audit: h.audit,
        heartbeat: h.heartbeat,
        clock: h.clock,
        config: { slaWarnRatio: 0.75, environment: 'staging' },
      }),
    };
  }

  test('tickets are classified by deterministic rules', () => {
    assert.equal(classifyTicket(ticket()), 'incident_report');
    assert.equal(classifyTicket(ticket({ subject: 'Invoice question', body: 'About my payment' })), 'billing');
    assert.equal(classifyTicket(ticket({ subject: 'Locked out', body: 'I forgot my password' })), 'access');
    assert.equal(classifyTicket(ticket({ subject: 'Question', body: 'How do I add a domain?' })), 'how_to');
    assert.equal(classifyTicket(ticket({ subject: 'Hello', body: 'Just saying hi' })), 'other');
  });

  test('assessment computes SLA remaining and stops the clock on first response', async () => {
    const { agent: a, clock } = agent([]);
    clock.advance(1 * HOUR);
    const open = await a.assess(ticket());
    assert.equal(open.slaBreached, false);
    assert.equal(open.slaRemainingMs, 3 * HOUR);

    const answered = await a.assess(ticket({ firstResponseAt: T0 + 30 * MIN }));
    assert.equal(answered.slaRemainingMs, null, 'an answered ticket is not accruing breach');
  });

  test('a breached SLA raises urgency to HIGH', async () => {
    const { agent: a, clock } = agent([]);
    clock.advance(5 * HOUR);
    const assessment = await a.assess(ticket());
    assert.equal(assessment.slaBreached, true);
    assert.equal(assessment.urgency, 'HIGH');
  });

  test('a related open incident raises an incident report to HIGH', async () => {
    const { agent: a, incidents } = agent([]);
    incidents.detect({
      dedupeKey: 'workload:w1:unhealthy',
      tenantId: 'tenant-a',
      category: 'availability',
      title: 'worker down',
      owner: 'cloud_ops',
      correlationId: 'c',
      evidence: [],
      facts: {
        environment: 'production',
        affectedTenants: 1,
        serviceCritical: true,
        durationMs: 0,
        dataAtRisk: false,
        securityRisk: false,
        slaBreached: false,
      },
    });
    const assessment = await a.assess(ticket());
    assert.equal(assessment.relatedIncidentIds.length, 1);
    assert.equal(assessment.urgency, 'HIGH');
  });

  test('another tenant incident is never visible to this ticket', async () => {
    const { agent: a, incidents } = agent([]);
    incidents.detect({
      dedupeKey: 'workload:other:unhealthy',
      tenantId: 'tenant-b',
      category: 'availability',
      title: 'other tenant worker down',
      owner: 'cloud_ops',
      correlationId: 'c',
      evidence: [],
      facts: {
        environment: 'production',
        affectedTenants: 1,
        serviceCritical: true,
        durationMs: 0,
        dataAtRisk: false,
        securityRisk: false,
        slaBreached: false,
      },
    });
    const assessment = await a.assess(ticket());
    assert.deepEqual(assessment.relatedIncidentIds, [], 'section 7 - no cross-tenant leakage');
  });

  test('the draft mentions an active incident when one exists, and does not invent one otherwise', async () => {
    const { agent: a, incidents } = agent([]);
    const withoutIncident = a.draftReply(ticket(), await a.assess(ticket()));
    assert.match(withoutIncident, /have not detected an incident/);

    incidents.detect({
      dedupeKey: 'k',
      tenantId: 'tenant-a',
      category: 'availability',
      title: 'down',
      owner: 'cloud_ops',
      correlationId: 'c',
      evidence: [],
      facts: {
        environment: 'production',
        affectedTenants: 1,
        serviceCritical: true,
        durationMs: 0,
        dataAtRisk: false,
        securityRisk: false,
        slaBreached: false,
      },
    });
    const withIncident = a.draftReply(ticket(), await a.assess(ticket()));
    assert.match(withIncident, /active incident/);
  });

  test('a sweep writes an internal note and an unsent draft, and sends nothing', async () => {
    const { agent: a, notes, drafts, audit } = agent([ticket()]);
    const run = await a.sweep();
    assert.equal(run.ticketsAssessed, 1);
    assert.equal(run.notesCreated, 1);
    assert.equal(run.draftsPrepared, 1);
    assert.equal(notes.length, 1);
    assert.equal(drafts.length, 1);
    assert.equal(
      audit.query({ action: 'customer_ops.send_customer_message' }).length,
      0,
      'nothing was sent',
    );
  });

  test('sending requires a scoped approval and is never executed by the sweep', async () => {
    const { agent: a, approvals } = agent([ticket()]);
    await a.sweep();
    const assessment = await a.assess(ticket());
    const req = a.requestSendApproval(ticket(), assessment, 'body');
    assert.equal(req.status, 'pending');
    assert.equal(approvals.pending().length, 1);
    assert.equal(req.rollback, 'none - a sent message cannot be recalled');
  });

  test('a read-only deployment assesses but writes nothing', async () => {
    const { agent: a, notes, drafts } = agent([ticket()], { readOnly: true });
    const run = await a.sweep();
    assert.equal(run.ticketsAssessed, 1);
    assert.equal(notes.length, 0);
    assert.equal(drafts.length, 0);
  });

  test('an unreachable helpdesk fails loudly', async () => {
    const { agent: a, audit, heartbeat } = agent([], { throwOn: true });
    const run = await a.sweep();
    assert.equal(run.status, 'failed');
    assert.equal(audit.query({ action: 'customer_ops.sweep', result: 'failed' }).length, 1);
    assert.equal(heartbeat.report('customer_ops').consecutiveErrors, 1);
  });
});

// ===========================================================================
describe('Section 31 - Sales agent', () => {
  const lead = (o: Partial<Lead> = {}): Lead => ({
    id: 'l-1',
    company: 'Acme Co',
    contactName: 'Sara',
    source: 'inbound',
    industry: 'retail',
    companySize: 250,
    statedNeeds: ['we need kubernetes hosting and backup'],
    stage: 'new',
    createdAt: T0,
    lastActivityAt: T0,
    ownerId: null,
    ...o,
  });

  function agent(leads: Lead[], throwOn = false) {
    const h = base();
    const saved: unknown[] = [];
    const reader = {
      name: 'fake-crm',
      async listLeads() {
        if (throwOn) throw new Error('crm unreachable');
        return leads;
      },
    };
    const writer = {
      async saveQualification(leadId: string, q: unknown) {
        saved.push({ leadId, q });
        return { qualificationId: `q-${saved.length}` };
      },
      async getQualification(id: string) {
        return { id, leadId: 'l-1' };
      },
    };
    h.heartbeat.expect('sales');
    return {
      ...h,
      saved,
      agent: new SalesAgent({
        reader,
        writer,
        audit: h.audit,
        heartbeat: h.heartbeat,
        clock: h.clock,
      }),
    };
  }

  test('a complete lead qualifies and maps needs to real services', () => {
    const { agent: a } = agent([]);
    const q = a.qualify(lead());
    assert.ok(q.score >= 60, `score ${q.score} should qualify`);
    assert.equal(q.stage, 'contact_ready');
    assert.deepEqual(q.recommendedServices.sort(), ['Backup and Recovery', 'Managed Kubernetes']);
    assert.deepEqual(q.missingInformation, []);
  });

  test('missing facts are reported, never guessed', () => {
    const { agent: a } = agent([]);
    const q = a.qualify(
      lead({ contactName: null, industry: null, companySize: null, statedNeeds: [] }),
    );
    assert.deepEqual(
      q.missingInformation.sort(),
      ['company size', 'contact name', 'industry', 'stated needs'],
    );
    assert.equal(q.stage, 'researching');
    assert.equal(q.reason, 'warm source: inbound');
  });

  test('only catalogue services are ever recommended', () => {
    const { agent: a } = agent([]);
    // No term here maps to anything Mahsumah sells, so nothing is proposed
    // rather than something adjacent being invented.
    const q = a.qualify(lead({ statedNeeds: ['we want quantum blockchain mining rigs'] }));
    assert.deepEqual(q.recommendedServices, []);
  });

  test('a generic term does not shadow a specific one', () => {
    const { agent: a } = agent([]);
    // "kubernetes hosting" is a request for Kubernetes, not shared hosting.
    const specific = a.qualify(lead({ statedNeeds: ['kubernetes hosting'] }));
    assert.deepEqual(specific.recommendedServices, ['Managed Kubernetes']);
    // But a bare hosting request still maps to hosting.
    const generic = a.qualify(lead({ statedNeeds: ['we need website hosting'] }));
    assert.deepEqual(generic.recommendedServices, ['Managed Hosting']);
  });

  test('the draft is marked unsent and invents no pricing', () => {
    const { agent: a } = agent([]);
    const l = lead();
    const draft = a.draftOutreach(l, a.qualify(l));
    assert.match(draft, /DRAFT - not sent/);
    assert.doesNotMatch(draft, /\b(discount|SAR|USD|\$|price|%)\b/i);
    assert.match(draft, /Sara/);
  });

  test('there is no send capability in the catalogue at all', () => {
    const { registry } = base();
    const sendActions = registry
      .all()
      .filter((x) => x.owner === 'sales' && /send|email/i.test(x.name));
    assert.deepEqual(sendActions, [], 'section 32 - sending must not exist as a capability');
  });

  test('stale leads are flagged', async () => {
    const { agent: a, clock } = agent([lead()]);
    clock.advance(20 * DAY);
    const run = await a.sweep();
    assert.equal(run.staleFlagged, 1);
  });

  test('an unreachable CRM fails loudly', async () => {
    const { agent: a, audit } = agent([], true);
    const run = await a.sweep();
    assert.equal(run.status, 'failed');
    assert.equal(audit.query({ action: 'sales.sweep', result: 'failed' }).length, 1);
  });
});

// ===========================================================================
describe('Section 34 - Marketing agent', () => {
  const brief = (o: Partial<CampaignBrief> = {}): CampaignBrief => ({
    id: 'c-1',
    objective: 'Generate qualified leads for managed hosting',
    audience: 'Saudi SaaS founders',
    service: 'Managed Hosting',
    valueProposition: 'Run your platform on Saudi infrastructure without hiring an ops team.',
    callToAction: 'Book a 20-minute call.',
    channel: 'linkedin',
    scheduledFor: T0 + DAY,
    ...o,
  });

  function agent(briefs: CampaignBrief[], channels: Channel[]) {
    const h = base();
    const drafts: Array<{ id: string; body: string }> = [];
    const reader = {
      name: 'fake-marketing',
      async listChannels() {
        return channels;
      },
      async listBriefs() {
        return briefs;
      },
    };
    const writer = {
      async saveDraft(_c: string, _ch: string, body: string) {
        const id = `i-${drafts.length + 1}`;
        drafts.push({ id, body });
        return { itemId: id };
      },
      async getItem() {
        return null;
      },
    };
    h.heartbeat.expect('marketing');
    return {
      ...h,
      drafts,
      agent: new MarketingAgent({
        reader,
        writer,
        approvals: h.approvals,
        audit: h.audit,
        heartbeat: h.heartbeat,
        clock: h.clock,
      }),
    };
  }

  const connected: Channel[] = [
    { name: 'linkedin', connected: true },
    { name: 'x', connected: true },
    { name: 'instagram', connected: false },
  ];

  test('an incomplete brief is rejected, not completed by the agent', async () => {
    const { agent: a, drafts, audit } = agent([brief({ callToAction: '  ' })], connected);
    const run = await a.sweep();
    assert.equal(run.rejected, 1);
    assert.equal(run.draftsPrepared, 0);
    assert.equal(drafts.length, 0);
    const [entry] = audit.query({ action: 'marketing.brief_rejected' });
    assert.match(entry!.reason, /callToAction/);
  });

  test('a disconnected channel is skipped rather than queued', async () => {
    const { agent: a, drafts, audit } = agent([brief({ channel: 'instagram' })], connected);
    const run = await a.sweep();
    assert.equal(run.skippedDisconnected, 1);
    assert.equal(drafts.length, 0);
    assert.equal(audit.query({ action: 'marketing.channel_unavailable' }).length, 1);
  });

  test('a complete brief on a connected channel drafts and requests approval', async () => {
    const { agent: a, drafts, approvals } = agent([brief()], connected);
    const run = await a.sweep();
    assert.equal(run.draftsPrepared, 1);
    assert.equal(run.approvalsRequested, 1);
    assert.equal(approvals.pending().length, 1);
    assert.match(drafts[0]!.body, /Saudi infrastructure/);
    assert.match(drafts[0]!.body, /Book a 20-minute call/);
  });

  test('content is fitted to the channel limit at a word boundary', async () => {
    const { agent: a, drafts } = agent([brief({ channel: 'x' })], connected);
    await a.sweep();
    const body = drafts[0]!.body;
    assert.ok(body.length <= 280, `length ${body.length}`);
    assert.doesNotMatch(body, /\s$/, 'no trailing whitespace from truncation');
  });

  test('publishing never happens during a sweep', async () => {
    const { agent: a, audit } = agent([brief()], connected);
    await a.sweep();
    assert.equal(audit.query({ action: 'marketing.publish_approved_content' }).length, 0);
  });
});

// ===========================================================================
describe('Section 37 - Finance agent', () => {
  const invoice = (o: Partial<Invoice> = {}): Invoice => ({
    id: 'inv-1',
    tenantId: 'tenant-a',
    amount: 150000,
    currency: 'SAR',
    dueAt: T0 - 10 * DAY,
    paidAt: null,
    ...o,
  });

  const sub = (o: Partial<Subscription> = {}): Subscription => ({
    id: 'sub-1',
    tenantId: 'tenant-a',
    serviceName: 'Managed Hosting',
    renewsAt: T0 + 10 * DAY,
    amount: 500000,
    currency: 'SAR',
    autoRenew: true,
    ...o,
  });

  function agent(invoices: Invoice[], subs: Subscription[], throwOn = false) {
    const h = base({
      enabledLevels: new Set([PermissionLevel.P0_READ, PermissionLevel.P2_SAFE_AUTONOMOUS]),
      enabledP2Actions: new Set(['finance.generate_renewal_reminder']),
    });
    const reminders: string[] = [];
    const reader = {
      name: 'fake-billing',
      async listInvoices() {
        if (throwOn) throw new Error('billing unreachable');
        return invoices;
      },
      async listSubscriptions() {
        if (throwOn) throw new Error('billing unreachable');
        return subs;
      },
    };
    const writer = {
      async createReminder(r: { subscriptionId: string }) {
        reminders.push(r.subscriptionId);
        return { reminderId: `r-${reminders.length}` };
      },
      async getReminder(id: string) {
        return { id, state: 'pending' as const };
      },
    };
    h.executor.registerHandler('finance.generate_renewal_reminder', {
      async execute(req) {
        return writer.createReminder({ subscriptionId: req.target.resourceId });
      },
      async verify(_req, res) {
        const r = await writer.getReminder((res as { reminderId: string }).reminderId);
        return r?.state === 'pending';
      },
    });
    h.heartbeat.expect('finance');
    return {
      ...h,
      reminders,
      agent: new FinanceAgent({
        reader,
        writer,
        executor: h.executor,
        audit: h.audit,
        heartbeat: h.heartbeat,
        clock: h.clock,
      }),
    };
  }

  test('money is summed in integer minor units', () => {
    const sum = sumSameCurrency([
      { amount: 10, currency: 'SAR' },
      { amount: 20, currency: 'SAR' },
    ]);
    assert.deepEqual(sum, { total: 30, currency: 'SAR' });
  });

  test('mixed currencies return null rather than a wrong total', () => {
    assert.equal(
      sumSameCurrency([
        { amount: 10, currency: 'SAR' },
        { amount: 20, currency: 'USD' },
      ]),
      null,
    );
  });

  test('overdue invoices escalate by age', () => {
    const { agent: a } = agent([], []);
    const rows = a.overdue([
      invoice({ id: 'a', dueAt: T0 - 2 * DAY }),
      invoice({ id: 'b', dueAt: T0 - 10 * DAY }),
      invoice({ id: 'c', dueAt: T0 - 40 * DAY }),
      invoice({ id: 'd', dueAt: T0 + DAY }),
      invoice({ id: 'e', dueAt: T0 - 99 * DAY, paidAt: T0 }),
    ]);
    assert.deepEqual(
      rows.map((r) => [r.invoice.id, r.escalation]),
      [['c', 'escalate'], ['b', 'follow_up'], ['a', 'reminder']],
    );
  });

  test('renewals inside the horizon are found, outside are not', () => {
    const { agent: a } = agent([], []);
    const rows = a.upcomingRenewals([
      sub({ id: 'near', renewsAt: T0 + 5 * DAY }),
      sub({ id: 'far', renewsAt: T0 + 90 * DAY }),
      sub({ id: 'past', renewsAt: T0 - DAY }),
    ]);
    assert.deepEqual(rows.map((r) => r.subscription.id), ['near']);
  });

  test('metrics are tenant scoped', () => {
    const { agent: a } = agent([], []);
    const invoices = [
      invoice({ id: 'a', tenantId: 'tenant-a', amount: 100 }),
      invoice({ id: 'b', tenantId: 'tenant-b', amount: 999 }),
    ];
    const forA = a.metrics(invoices, TenantScope.forTenant('tenant-a'));
    assert.equal(forA.outstanding, 100, 'tenant B invoice must not be counted');
    const internal = a.metrics(invoices, TenantScope.internalScope());
    assert.equal(internal.outstanding, 1099);
  });

  test('a sweep creates verified reminder records and no charge', async () => {
    const { agent: a, reminders, audit } = agent([invoice()], [sub()]);
    const run = await a.sweep();
    assert.equal(run.overdueFound, 1);
    assert.equal(run.renewalsUpcoming, 1);
    assert.equal(run.remindersCreated, 1);
    assert.deepEqual(reminders, ['sub-1']);
    assert.equal(audit.query({ action: 'finance.initiate_transfer' }).length, 0);
  });

  test('transfers are structurally impossible', async () => {
    const { executor, registry } = base();
    assert.equal(
      registry.get('finance.initiate_transfer')!.level,
      PermissionLevel.P4_MANUAL_CRITICAL,
    );
    assert.throws(
      () =>
        executor.registerHandler('finance.initiate_transfer', {
          async execute() {
            return null;
          },
          async verify() {
            return true;
          },
        }),
      /must not have an executable handler/,
    );
  });

  test('there is no suspend capability', () => {
    const { registry } = base();
    assert.deepEqual(
      registry.all().filter((x) => /suspend|terminate/i.test(x.name)),
      [],
      'section 38 - no automatic suspension',
    );
  });
});

// ===========================================================================
describe('Section 39 - CEO Command agent', () => {
  function agent() {
    const h = base();
    for (const a of ['cloud_ops', 'security'] as const) h.heartbeat.expect(a);
    return {
      ...h,
      agent: new CeoCommandAgent({
        incidents: h.incidents,
        approvals: h.approvals,
        heartbeat: h.heartbeat,
        killSwitches: h.kill,
        audit: h.audit,
        expectedAgents: ['cloud_ops', 'security'],
        clock: h.clock,
      }),
    };
  }

  test('sections with no data source say UNAVAILABLE with a reason', () => {
    const { agent: a } = agent();
    const brief = a.compile();
    assert.ok(isUnavailable(brief.sales));
    assert.match((brief.sales as { unavailable: string }).unavailable, /CRM/);
    assert.ok(isUnavailable(brief.finance));
  });

  test('supplied inputs replace the unavailable marker', () => {
    const { agent: a } = agent();
    const brief = a.compile({ finance: { overdue: 3, renewals: 2 } });
    assert.equal(isUnavailable(brief.finance), false);
    assert.deepEqual(brief.finance, { overdue: 3, renewals: 2 });
  });

  test('a never-started agent becomes a decision item', () => {
    const { agent: a } = agent();
    const brief = a.compile();
    const health = brief.decisionsNeeded.filter((d) => d.kind === 'agent_health');
    assert.equal(health.length, 2);
    assert.match(health[0]!.ifIgnored, /unmonitored/);
  });

  test('pending approvals surface as decisions with an expiry consequence', () => {
    const { agent: a, approvals, heartbeat } = agent();
    heartbeat.beat('cloud_ops', 'ok');
    heartbeat.beat('security', 'ok');
    approvals.request({
      action: 'cloud_ops.restart_worker',
      target: { resourceType: 'worker', resourceId: 'w1', tenantId: 'tenant-a', environment: 'production' },
      agent: 'cloud_ops',
      requestedBy: 'agent:cloud_ops',
      reason: 'three failed health checks',
      evidence: [],
      risk: 'HIGH',
      predictedEffect: 'restart',
      rollback: 'stop again',
      correlationId: 'c',
      ttlMs: 30 * MIN,
    });
    const brief = a.compile();
    assert.equal(brief.decisionsNeeded.length, 1);
    assert.equal(brief.decisionsNeeded[0]!.kind, 'approval');
    assert.match(brief.decisionsNeeded[0]!.ifIgnored, /expires/);
  });

  test('decisions are ordered most urgent first', () => {
    const { agent: a, approvals, heartbeat } = agent();
    heartbeat.beat('cloud_ops', 'ok');
    heartbeat.beat('security', 'ok');
    for (const risk of ['LOW', 'CRITICAL', 'MEDIUM'] as const) {
      approvals.request({
        action: 'cloud_ops.restart_worker',
        target: { resourceType: 'worker', resourceId: `w-${risk}`, tenantId: 'tenant-a', environment: 'production' },
        agent: 'cloud_ops',
        requestedBy: 'agent:cloud_ops',
        reason: risk,
        evidence: [],
        risk,
        predictedEffect: 'restart',
        rollback: 'stop again',
        correlationId: 'c',
        ttlMs: 30 * MIN,
      });
    }
    const order = a.compile().decisionsNeeded.map((d) => d.urgency);
    assert.deepEqual(order, ['CRITICAL', 'MEDIUM', 'LOW']);
  });

  test('a healthy quiet platform needs no decisions', () => {
    const { agent: a, heartbeat } = agent();
    heartbeat.beat('cloud_ops', 'ok');
    heartbeat.beat('security', 'ok');
    const brief = a.compile();
    assert.deepEqual(brief.decisionsNeeded, []);
    assert.match(a.render(brief), /None\. Everything open is handled/);
  });

  test('an engaged kill switch is surfaced to management', () => {
    const { agent: a, kill, heartbeat } = agent();
    heartbeat.beat('cloud_ops', 'ok');
    heartbeat.beat('security', 'ok');
    kill.disableAutonomousActions('ahmed', 'drill');
    const brief = a.compile();
    assert.equal(brief.platform.autonomyFrozen, true);
    assert.ok(brief.decisionsNeeded.some((d) => d.kind === 'kill_switch'));
  });

  test('the rendered brief never prints an estimated number', () => {
    const { agent: a } = agent();
    const text = a.render(a.compile());
    assert.match(text, /SALES\s+UNAVAILABLE - no CRM/);
    assert.match(text, /MTTR:\s+UNAVAILABLE - no incident resolved yet/);
  });

  test('compiling is audited', () => {
    const { agent: a, audit } = agent();
    a.compile();
    assert.equal(audit.query({ action: 'ceo_command.compile_daily_brief' }).length, 1);
  });
});
