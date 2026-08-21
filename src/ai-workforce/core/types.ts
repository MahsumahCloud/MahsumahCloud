/**
 * Mahsumah AI Workforce — shared core domain types.
 *
 * Directive references are cited inline so each construct is traceable to the
 * requirement it implements.
 */

/**
 * §14 — Autonomy classes. Numeric ordering is significant: higher = more dangerous.
 * Declared as a const object rather than an `enum` so the module runs under
 * Node's type-stripping loader with no build step.
 */
export const PermissionLevel = {
  /** Inspect / monitor / analyse. No mutation. */
  P0_READ: 0,
  /** Propose an action. No mutation. */
  P1_RECOMMEND: 1,
  /** Allowlisted, reversible, low-risk mutation. */
  P2_SAFE_AUTONOMOUS: 2,
  /** Mutation permitted only with a valid scoped human approval. */
  P3_APPROVAL_REQUIRED: 3,
  /** Never autonomous under any configuration. */
  P4_MANUAL_CRITICAL: 4,
} as const;

export type PermissionLevel = (typeof PermissionLevel)[keyof typeof PermissionLevel];

export const PERMISSION_LEVEL_NAMES: Record<PermissionLevel, string> = {
  [PermissionLevel.P0_READ]: 'P0_READ',
  [PermissionLevel.P1_RECOMMEND]: 'P1_RECOMMEND',
  [PermissionLevel.P2_SAFE_AUTONOMOUS]: 'P2_SAFE_AUTONOMOUS',
  [PermissionLevel.P3_APPROVAL_REQUIRED]: 'P3_APPROVAL_REQUIRED',
  [PermissionLevel.P4_MANUAL_CRITICAL]: 'P4_MANUAL_CRITICAL',
};

/** §65 — Environment separation. */
export type Environment = 'local' | 'development' | 'staging' | 'production';

export type AgentId =
  | 'cloud_ops'
  | 'security'
  | 'customer_ops'
  | 'sales'
  | 'marketing'
  | 'finance'
  | 'ceo_command';

/** §10 — Agent execution statuses. */
export type RunStatus =
  | 'queued'
  | 'running'
  | 'waiting_approval'
  | 'completed'
  | 'partially_completed'
  | 'failed'
  | 'cancelled'
  | 'blocked';

/** §26 — Severity levels. */
export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/** §53 — Data classification. */
export type DataClassification = 'public' | 'internal' | 'confidential' | 'secret';

/**
 * The exact thing an action operates on. §16 requires approvals to be bound to
 * an exact target, so this must be fully value-comparable.
 */
export interface ActionTarget {
  /** e.g. 'ecs_instance', 'cpanel_account', 'worker', 'ticket'. */
  readonly resourceType: string;
  /** Stable provider-side identifier. */
  readonly resourceId: string;
  /** Owning tenant, or null for platform-internal resources. */
  readonly tenantId: string | null;
  readonly environment: Environment;
}

/**
 * §79 — Every autonomous capability must be declared before it can run.
 * An action that is not in the registry cannot be executed at all.
 */
export interface ActionDescriptor {
  readonly name: string;
  readonly owner: AgentId;
  readonly level: PermissionLevel;
  readonly resourceType: string;
  /** Environments in which this action may run at all. */
  readonly allowedEnvironments: readonly Environment[];
  /** Human-readable description of the maximum scope of effect. */
  readonly blastRadius: string;
  /** How success is confirmed. §58 — a 200 response is not success. */
  readonly verification: string;
  /** What undoes it, or why it needs none. */
  readonly rollback: string;
  /** True when the action mutates state. P0/P1 must be false. */
  readonly mutates: boolean;
  /** Optional cap on executions per tenant per hour. */
  readonly rateLimitPerHour?: number;
}

export interface ActionRequest {
  readonly action: string;
  readonly target: ActionTarget;
  readonly agent: AgentId;
  readonly runId: string;
  readonly correlationId: string;
  /** §19 — concise operational justification, never chain-of-thought. */
  readonly reason: string;
  readonly evidence: readonly string[];
  /** Present only for P3. */
  readonly approvalId?: string;
}

/** §14/§15 — runtime autonomy configuration. */
export interface AutonomyConfig {
  /** Levels currently enabled. P4 is never enableable. */
  readonly enabledLevels: ReadonlySet<PermissionLevel>;
  /** §15 — P2 rolls out action-by-action, not wholesale. */
  readonly enabledP2Actions: ReadonlySet<string>;
}

/** §15 default launch policy. */
export function defaultLaunchAutonomy(): AutonomyConfig {
  return {
    enabledLevels: new Set([
      PermissionLevel.P0_READ,
      PermissionLevel.P1_RECOMMEND,
      PermissionLevel.P3_APPROVAL_REQUIRED,
    ]),
    enabledP2Actions: new Set<string>(),
  };
}
