/** Typed failures for the AI Workforce core. Each maps to a directive control. */

export class WorkforceError extends Error {
  readonly code: string;
  readonly details: Record<string, unknown>;
  constructor(code: string, message: string, details: Record<string, unknown> = {}) {
    super(message);
    this.name = new.target.name;
    this.code = code;
    this.details = details;
  }
}

/** §7 — cross-tenant access attempt. Release-blocking control. */
export class TenantIsolationError extends WorkforceError {
  constructor(message: string, details: Record<string, unknown> = {}) {
    super('TENANT_ISOLATION_VIOLATION', message, details);
  }
}

/** §14/§50 — policy refused the action. */
export class PolicyDeniedError extends WorkforceError {
  constructor(message: string, details: Record<string, unknown> = {}) {
    super('POLICY_DENIED', message, details);
  }
}

/** §16 — approval missing, expired, out of scope, consumed, or unauthorised. */
export class ApprovalError extends WorkforceError {
  constructor(message: string, details: Record<string, unknown> = {}) {
    super('APPROVAL_INVALID', message, details);
  }
}

/** §17 — a kill switch is engaged. */
export class KillSwitchError extends WorkforceError {
  constructor(message: string, details: Record<string, unknown> = {}) {
    super('KILL_SWITCH_ENGAGED', message, details);
  }
}

/** §58 — the action ran but the target state could not be confirmed. */
export class VerificationFailedError extends WorkforceError {
  constructor(message: string, details: Record<string, unknown> = {}) {
    super('VERIFICATION_FAILED', message, details);
  }
}
