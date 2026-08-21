import type { Severity } from '../core/types.ts';

/**
 * Ports for the business-domain agents (security, customer ops, sales,
 * marketing, finance).
 *
 * As with integrations/ports.ts these are INTERFACES ONLY. No adapter is
 * implemented, because none of the backing systems is reachable from the build
 * environment (see docs/ai-workforce/00-current-state-audit.md).
 *
 * These signatures are a proposal for what an adapter must provide, derived
 * from what each agent genuinely needs to do its job - not a claim about the
 * real platform's schema, which is still unknown. When the platform repository
 * is available, expect these to be reshaped to match the real models. The agent
 * logic above them is written to survive that: it depends on the port, never on
 * a concrete store.
 */

// ---------------------------------------------------------------- Security

export type AuthEventKind =
  | 'login_success'
  | 'login_failure'
  | 'mfa_failure'
  | 'privilege_grant'
  | 'admin_action'
  | 'token_created';

export interface AuthEvent {
  readonly id: string;
  readonly kind: AuthEventKind;
  readonly actorId: string;
  readonly tenantId: string | null;
  readonly sourceIp: string;
  /** Coarse geo hint if the provider supplies one. Never inferred locally. */
  readonly country: string | null;
  readonly at: number;
  readonly userAgent: string | null;
}

export interface SecurityAlert {
  readonly id: string;
  readonly source: string;
  readonly title: string;
  readonly tenantId: string | null;
  readonly reportedSeverity: Severity | null;
  readonly at: number;
  readonly detail: string;
}

export interface SecuritySignalReader {
  readonly name: string;
  /** Auth events in the window [since, now). */
  listAuthEvents(since: number): Promise<readonly AuthEvent[]>;
  /** Alerts raised by scanners, WAF, dependency bots, etc. */
  listSecurityAlerts(since: number): Promise<readonly SecurityAlert[]>;
}

// ----------------------------------------------------------- Customer Ops

export type TicketStatus = 'new' | 'open' | 'pending_customer' | 'resolved' | 'closed';

export interface Ticket {
  readonly id: string;
  readonly tenantId: string;
  readonly subject: string;
  readonly body: string;
  readonly status: TicketStatus;
  readonly createdAt: number;
  readonly lastCustomerReplyAt: number | null;
  readonly firstResponseAt: number | null;
  /** Service or product the customer is asking about, when known. */
  readonly serviceId: string | null;
}

export interface CustomerService {
  readonly id: string;
  readonly tenantId: string;
  readonly name: string;
  readonly active: boolean;
  /** Response-time commitment in ms, or null when no SLA applies. */
  readonly slaResponseMs: number | null;
}

export interface TicketReader {
  readonly name: string;
  listOpenTickets(): Promise<readonly Ticket[]>;
  listServices(tenantId: string): Promise<readonly CustomerService[]>;
}

export interface TicketWriter {
  /** Adds an internal-only note. Never customer visible. */
  addInternalNote(ticketId: string, note: string): Promise<{ noteId: string }>;
  /** Stores a reply in unsent state, pending approval. */
  saveDraftReply(ticketId: string, body: string): Promise<{ draftId: string }>;
  /** Reads back a note or draft, so verification can confirm it landed. */
  getNote(noteId: string): Promise<{ id: string; internal: boolean } | null>;
  getDraft(draftId: string): Promise<{ id: string; sent: boolean } | null>;
}

// -------------------------------------------------------------------- Sales

export type LeadStage =
  | 'new'
  | 'researching'
  | 'qualified'
  | 'contact_ready'
  | 'contacted'
  | 'engaged'
  | 'discovery'
  | 'proposal'
  | 'negotiation'
  | 'won'
  | 'lost'
  | 'nurture';

export interface Lead {
  readonly id: string;
  readonly company: string;
  readonly contactName: string | null;
  readonly source: string;
  readonly industry: string | null;
  readonly companySize: number | null;
  /** Needs as stated by the lead. Never invented - section 32. */
  readonly statedNeeds: readonly string[];
  readonly stage: LeadStage;
  readonly createdAt: number;
  readonly lastActivityAt: number;
  readonly ownerId: string | null;
}

export interface LeadReader {
  readonly name: string;
  listLeads(): Promise<readonly Lead[]>;
}

export interface LeadWriter {
  /** Persists a qualification result in proposed state for human review. */
  saveQualification(
    leadId: string,
    q: { score: number; reason: string; recommendedServices: readonly string[]; stage: LeadStage },
  ): Promise<{ qualificationId: string }>;
  getQualification(qualificationId: string): Promise<{ id: string; leadId: string } | null>;
}

// ---------------------------------------------------------------- Marketing

export type ChannelName = 'linkedin' | 'x' | 'instagram' | 'snapchat' | 'email' | 'blog';

export interface Channel {
  readonly name: ChannelName;
  /** True only when a working, authenticated integration exists. Section 34
   *  forbids presenting a channel as connected when it is not. */
  readonly connected: boolean;
}

export interface CampaignBrief {
  readonly id: string;
  readonly objective: string;
  readonly audience: string;
  readonly service: string;
  readonly valueProposition: string;
  readonly callToAction: string;
  readonly channel: ChannelName;
  readonly scheduledFor: number;
}

export interface ContentItem {
  readonly id: string;
  readonly campaignId: string;
  readonly channel: ChannelName;
  readonly body: string;
  readonly status: 'draft' | 'approved' | 'published';
}

export interface MarketingReader {
  readonly name: string;
  listChannels(): Promise<readonly Channel[]>;
  listBriefs(): Promise<readonly CampaignBrief[]>;
}

export interface MarketingWriter {
  saveDraft(campaignId: string, channel: ChannelName, body: string): Promise<{ itemId: string }>;
  getItem(itemId: string): Promise<ContentItem | null>;
}

// ------------------------------------------------------------------ Finance

export interface Invoice {
  readonly id: string;
  readonly tenantId: string;
  readonly amount: number;
  readonly currency: string;
  readonly dueAt: number;
  readonly paidAt: number | null;
}

export interface Subscription {
  readonly id: string;
  readonly tenantId: string;
  readonly serviceName: string;
  readonly renewsAt: number;
  readonly amount: number;
  readonly currency: string;
  readonly autoRenew: boolean;
}

export interface BillingReader {
  readonly name: string;
  listInvoices(): Promise<readonly Invoice[]>;
  listSubscriptions(): Promise<readonly Subscription[]>;
}

export interface BillingWriter {
  /** Creates an internal reminder record. No customer contact, no charge. */
  createReminder(
    r: { tenantId: string; subscriptionId: string; dueAt: number; note: string },
  ): Promise<{ reminderId: string }>;
  getReminder(reminderId: string): Promise<{ id: string; state: 'pending' | 'sent' } | null>;
}
