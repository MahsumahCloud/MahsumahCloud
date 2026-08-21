import type { ActionDescriptor } from '../core/types.ts';
import { PermissionLevel } from '../core/types.ts';
import { ActionRegistry } from '../core/policy.ts';

/**
 * Section 79 - Autonomy rollout catalogue.
 *
 * Every capability an agent may ever invoke is declared here with its level,
 * environments, blast radius, verification and rollback. Nothing outside this
 * catalogue is executable (PolicyEngine denies unknown actions).
 *
 * IMPORTANT: declaring an action does NOT enable it. Section 15 launches with
 * P2 disabled entirely; P2 entries below become live only when an operator adds
 * them to AutonomyConfig.enabledP2Actions one at a time.
 *
 * P4 entries are declared deliberately so the boundary is explicit and
 * testable. ActionExecutor.registerHandler refuses to attach a handler to any
 * of them, so they have no executable path.
 */

const ALL_ENVS = ['local', 'development', 'staging', 'production'] as const;
const NON_PROD = ['local', 'development', 'staging'] as const;

export const ACTION_CATALOGUE: readonly ActionDescriptor[] = [
  // ---------------------------------------------------------------- Cloud Ops
  {
    name: 'cloud_ops.read_workload_health',
    owner: 'cloud_ops',
    level: PermissionLevel.P0_READ,
    resourceType: 'workload',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'none - read only',
    verification: 'health payload returned for the requested workload',
    rollback: 'not applicable - no mutation',
    mutates: false,
  },
  {
    name: 'cloud_ops.read_ssl_status',
    owner: 'cloud_ops',
    level: PermissionLevel.P0_READ,
    resourceType: 'certificate',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'none - read only',
    verification: 'certificate metadata returned',
    rollback: 'not applicable - no mutation',
    mutates: false,
  },
  {
    name: 'cloud_ops.recommend_remediation',
    owner: 'cloud_ops',
    level: PermissionLevel.P1_RECOMMEND,
    resourceType: 'incident',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'none - produces a recommendation record only',
    verification: 'recommendation persisted against the incident',
    rollback: 'not applicable - no mutation',
    mutates: false,
  },
  {
    name: 'cloud_ops.retry_health_check',
    owner: 'cloud_ops',
    level: PermissionLevel.P2_SAFE_AUTONOMOUS,
    resourceType: 'monitoring_check',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'single monitoring check on a single workload',
    verification: 'a new health-check result row exists with a later timestamp',
    rollback: 'none required - re-running a check has no persistent effect',
    mutates: true,
    rateLimitPerHour: 12,
  },
  {
    name: 'cloud_ops.restart_worker',
    owner: 'cloud_ops',
    level: PermissionLevel.P3_APPROVAL_REQUIRED,
    resourceType: 'worker',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'single worker process on a single host',
    verification: 'worker reports healthy on two consecutive checks after restart',
    rollback: 'worker can be stopped again; prior state was already unhealthy',
    mutates: true,
    rateLimitPerHour: 4,
  },
  {
    name: 'cloud_ops.rollback_deployment',
    owner: 'cloud_ops',
    level: PermissionLevel.P3_APPROVAL_REQUIRED,
    resourceType: 'deployment',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'one environment of one project',
    verification: 'active release equals the requested previous release and health is green',
    rollback: 're-deploy the superseded release',
    mutates: true,
    rateLimitPerHour: 2,
  },
  {
    name: 'cloud_ops.delete_server',
    owner: 'cloud_ops',
    level: PermissionLevel.P4_MANUAL_CRITICAL,
    resourceType: 'server',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'irreversible destruction of a host and its workloads',
    verification: 'not applicable - never executed by an agent',
    rollback: 'none - irreversible',
    mutates: true,
  },
  {
    name: 'cloud_ops.delete_backup',
    owner: 'cloud_ops',
    level: PermissionLevel.P4_MANUAL_CRITICAL,
    resourceType: 'backup',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'irreversible loss of a recovery point',
    verification: 'not applicable - never executed by an agent',
    rollback: 'none - irreversible',
    mutates: true,
  },
  {
    name: 'cloud_ops.modify_dns_nameservers',
    owner: 'cloud_ops',
    level: PermissionLevel.P4_MANUAL_CRITICAL,
    resourceType: 'domain',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'can take every service on a domain offline globally',
    verification: 'not applicable - never executed by an agent',
    rollback: 'restore prior records, subject to propagation delay',
    mutates: true,
  },

  // ----------------------------------------------------------------- Security
  {
    name: 'security.read_auth_anomalies',
    owner: 'security',
    level: PermissionLevel.P0_READ,
    resourceType: 'auth_event',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'none - read only',
    verification: 'anomaly set returned for the requested window',
    rollback: 'not applicable - no mutation',
    mutates: false,
  },
  {
    name: 'security.recommend_containment',
    owner: 'security',
    level: PermissionLevel.P1_RECOMMEND,
    resourceType: 'security_incident',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'none - produces a containment proposal only',
    verification: 'proposal persisted against the security incident',
    rollback: 'not applicable - no mutation',
    mutates: false,
  },
  {
    name: 'security.modify_firewall_rules',
    owner: 'security',
    level: PermissionLevel.P4_MANUAL_CRITICAL,
    resourceType: 'security_group',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'can sever connectivity for every workload behind the group',
    verification: 'not applicable - never executed by an agent',
    rollback: 'restore prior rule set',
    mutates: true,
  },
  {
    name: 'security.rotate_root_credentials',
    owner: 'security',
    level: PermissionLevel.P4_MANUAL_CRITICAL,
    resourceType: 'credential',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'can lock the platform out of its own infrastructure',
    verification: 'not applicable - never executed by an agent',
    rollback: 'none once the prior secret is destroyed',
    mutates: true,
  },

  // ------------------------------------------------------------ Customer Ops
  {
    name: 'customer_ops.read_ticket_context',
    owner: 'customer_ops',
    level: PermissionLevel.P0_READ,
    resourceType: 'ticket',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'none - read only, tenant scoped',
    verification: 'ticket and service context returned for the owning tenant',
    rollback: 'not applicable - no mutation',
    mutates: false,
  },
  {
    name: 'customer_ops.draft_response',
    owner: 'customer_ops',
    level: PermissionLevel.P1_RECOMMEND,
    resourceType: 'ticket',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'none - draft is not sent',
    verification: 'draft persisted against the ticket in unsent state',
    rollback: 'discard the draft',
    mutates: false,
  },
  {
    name: 'customer_ops.create_internal_note',
    owner: 'customer_ops',
    level: PermissionLevel.P2_SAFE_AUTONOMOUS,
    resourceType: 'ticket',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'one internal note on one ticket; never customer visible',
    verification: 'note exists on the ticket and is flagged internal',
    rollback: 'delete the note',
    mutates: true,
    rateLimitPerHour: 60,
  },
  {
    name: 'customer_ops.send_customer_message',
    owner: 'customer_ops',
    level: PermissionLevel.P3_APPROVAL_REQUIRED,
    resourceType: 'ticket',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'one outbound message to one customer contact',
    verification: 'message recorded as sent with a provider message id',
    rollback: 'none - a sent message cannot be recalled',
    mutates: true,
    rateLimitPerHour: 20,
  },
  {
    name: 'customer_ops.delete_customer_account',
    owner: 'customer_ops',
    level: PermissionLevel.P4_MANUAL_CRITICAL,
    resourceType: 'tenant',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'irreversible destruction of a customer and all their data',
    verification: 'not applicable - never executed by an agent',
    rollback: 'none - irreversible',
    mutates: true,
  },

  // ------------------------------------------------------------------- Sales
  {
    name: 'sales.enrich_lead',
    owner: 'sales',
    level: PermissionLevel.P1_RECOMMEND,
    resourceType: 'lead',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'none - produces enrichment proposals for review',
    verification: 'enrichment attached to the lead in proposed state',
    rollback: 'discard the enrichment',
    mutates: false,
  },
  {
    name: 'sales.draft_outreach',
    owner: 'sales',
    level: PermissionLevel.P1_RECOMMEND,
    resourceType: 'lead',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'none - section 32 forbids autonomous sending',
    verification: 'draft persisted in unsent state',
    rollback: 'discard the draft',
    mutates: false,
  },

  // --------------------------------------------------------------- Marketing
  {
    name: 'marketing.draft_content',
    owner: 'marketing',
    level: PermissionLevel.P1_RECOMMEND,
    resourceType: 'campaign_item',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'none - draft only',
    verification: 'content item persisted in draft state',
    rollback: 'discard the draft',
    mutates: false,
  },
  {
    name: 'marketing.publish_approved_content',
    owner: 'marketing',
    level: PermissionLevel.P3_APPROVAL_REQUIRED,
    resourceType: 'campaign_item',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'one public post on one channel',
    verification: 'channel returns a live post id and the item is marked published',
    rollback: 'unpublish or delete the post',
    mutates: true,
    rateLimitPerHour: 5,
  },

  // ----------------------------------------------------------------- Finance
  {
    name: 'finance.read_overdue_invoices',
    owner: 'finance',
    level: PermissionLevel.P0_READ,
    resourceType: 'invoice',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'none - read only',
    verification: 'invoice set returned',
    rollback: 'not applicable - no mutation',
    mutates: false,
  },
  {
    name: 'finance.generate_renewal_reminder',
    owner: 'finance',
    level: PermissionLevel.P2_SAFE_AUTONOMOUS,
    resourceType: 'subscription',
    allowedEnvironments: NON_PROD,
    blastRadius: 'one internal reminder record; no customer contact, no charge',
    verification: 'reminder record exists in pending state',
    rollback: 'delete the reminder record',
    mutates: true,
    rateLimitPerHour: 100,
  },
  {
    name: 'finance.initiate_transfer',
    owner: 'finance',
    level: PermissionLevel.P4_MANUAL_CRITICAL,
    resourceType: 'payment',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'moves real money',
    verification: 'not applicable - never executed by an agent',
    rollback: 'none - section 37 forbids autonomous financial transfers',
    mutates: true,
  },

  // ------------------------------------------------------------- CEO Command
  {
    name: 'ceo_command.compile_daily_brief',
    owner: 'ceo_command',
    level: PermissionLevel.P0_READ,
    resourceType: 'brief',
    allowedEnvironments: ALL_ENVS,
    blastRadius: 'none - reads verified outputs of other agents',
    verification: 'brief document produced with all sections populated',
    rollback: 'not applicable - no mutation',
    mutates: false,
  },
];

/** Builds a registry populated with the full catalogue. */
export function buildActionRegistry(): ActionRegistry {
  const registry = new ActionRegistry();
  for (const descriptor of ACTION_CATALOGUE) registry.register(descriptor);
  return registry;
}
