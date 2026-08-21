import type { ActionRequest } from './types.ts';
import { PermissionLevel } from './types.ts';
import type { PolicyEngine } from './policy.ts';
import type { ActionRegistry } from './policy.ts';
import type { ApprovalEngine } from './approval.ts';
import type { AuditLog } from './audit.ts';
import type { TenantScope } from './tenant.ts';
import { PolicyDeniedError, VerificationFailedError } from './errors.ts';

/**
 * Section 58 - Transaction / action verification.
 *
 * An action is not successful because a call returned 200. It is successful
 * only when the target's observed state afterwards matches what was intended.
 * Every handler must therefore supply BOTH an execute step and an independent
 * verify step; there is no way to register one without the other.
 */
export interface ActionHandler {
  /** Performs the mutation (or the read, for P0). */
  execute(request: ActionRequest): Promise<unknown>;
  /**
   * Independently observes the target and returns true only if it reached the
   * intended state. Must re-read the target rather than trusting execute().
   */
  verify(request: ActionRequest, executeResult: unknown): Promise<boolean>;
  /** Optional compensation, invoked when verification fails. Section 11. */
  rollback?(request: ActionRequest, executeResult: unknown): Promise<void>;
}

export type ExecutionStatus =
  | 'succeeded'
  | 'denied'
  | 'awaiting_approval'
  | 'failed'
  | 'verification_failed';

export interface ExecutionResult {
  readonly status: ExecutionStatus;
  readonly action: string;
  readonly reason: string;
  readonly policy: string;
  readonly correlationId: string;
  readonly value?: unknown;
  readonly error?: string;
  readonly rolledBack?: boolean;
}

/**
 * Idempotency (section 57): a request is keyed by run + action + target so a
 * duplicated event cannot execute the same mutation twice.
 */
function idempotencyKey(r: ActionRequest): string {
  return [r.runId, r.action, r.target.resourceType, r.target.resourceId].join('|');
}

export class ActionExecutor {
  #registry: ActionRegistry;
  #policy: PolicyEngine;
  #approvals: ApprovalEngine;
  #audit: AuditLog;
  #handlers = new Map<string, ActionHandler>();
  #completed = new Map<string, ExecutionResult>();

  constructor(
    registry: ActionRegistry,
    policy: PolicyEngine,
    approvals: ApprovalEngine,
    audit: AuditLog,
  ) {
    this.#registry = registry;
    this.#policy = policy;
    this.#approvals = approvals;
    this.#audit = audit;
  }

  registerHandler(actionName: string, handler: ActionHandler): void {
    const descriptor = this.#registry.get(actionName);
    if (!descriptor) {
      throw new Error(`cannot register a handler for unregistered action '${actionName}'`);
    }
    // Section 14 - a P4 action must have no executable path at all.
    if (descriptor.level === PermissionLevel.P4_MANUAL_CRITICAL) {
      throw new Error(
        `P4_MANUAL_CRITICAL action '${actionName}' must not have an executable handler`,
      );
    }
    this.#handlers.set(actionName, handler);
  }

  #record(
    request: ActionRequest,
    result: ExecutionResult['status'],
    reason: string,
    policy: string,
    extra: Record<string, unknown> = {},
  ): void {
    const auditResult =
      result === 'succeeded'
        ? 'succeeded'
        : result === 'denied'
          ? 'denied'
          : result === 'awaiting_approval'
            ? 'blocked'
            : 'failed';
    this.#audit.append({
      actorType: 'agent',
      actorId: request.agent,
      tenantId: request.target.tenantId,
      action: request.action,
      target: `${request.target.resourceType}:${request.target.resourceId}`,
      result: auditResult,
      reason,
      correlationId: request.correlationId,
      policy,
      approvalId: request.approvalId,
      metadata: { runId: request.runId, evidence: request.evidence, ...extra },
    });
  }

  /**
   * The single path through which any agent action reaches the outside world.
   * Order: policy -> approval -> idempotency -> execute -> verify -> audit.
   */
  async run(request: ActionRequest, scope: TenantScope): Promise<ExecutionResult> {
    const decision = this.#policy.evaluate(request, scope);

    if (decision.outcome === 'deny') {
      this.#record(request, 'denied', decision.reason, decision.policy);
      return {
        status: 'denied',
        action: request.action,
        reason: decision.reason,
        policy: decision.policy,
        correlationId: request.correlationId,
      };
    }

    if (decision.outcome === 'require_approval') {
      // A P3 action may proceed only by presenting a valid, in-scope approval.
      if (!request.approvalId) {
        this.#record(request, 'awaiting_approval', decision.reason, decision.policy);
        return {
          status: 'awaiting_approval',
          action: request.action,
          reason: decision.reason,
          policy: decision.policy,
          correlationId: request.correlationId,
        };
      }
      try {
        this.#approvals.consume(request);
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        this.#record(request, 'denied', reason, 'approval.invalid');
        return {
          status: 'denied',
          action: request.action,
          reason,
          policy: 'approval.invalid',
          correlationId: request.correlationId,
        };
      }
    }

    // Section 57 - deduplicate replayed events.
    const key = idempotencyKey(request);
    const prior = this.#completed.get(key);
    if (prior) {
      this.#record(request, prior.status, 'deduplicated: already executed', 'idempotency.replay');
      return prior;
    }

    const handler = this.#handlers.get(request.action);
    if (!handler) {
      const reason = `no handler registered for action '${request.action}'`;
      this.#record(request, 'failed', reason, 'executor.missing_handler');
      return {
        status: 'failed',
        action: request.action,
        reason,
        policy: 'executor.missing_handler',
        correlationId: request.correlationId,
        error: reason,
      };
    }

    let executeResult: unknown;
    try {
      executeResult = await handler.execute(request);
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      this.#record(request, 'failed', `execution threw: ${reason}`, 'executor.execute_failed');
      return {
        status: 'failed',
        action: request.action,
        reason,
        policy: 'executor.execute_failed',
        correlationId: request.correlationId,
        error: reason,
      };
    }

    // Section 58 - success requires independent confirmation of target state.
    let verified = false;
    try {
      verified = await handler.verify(request, executeResult);
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      this.#record(request, 'verification_failed', `verify threw: ${reason}`, 'executor.verify_failed');
      return {
        status: 'verification_failed',
        action: request.action,
        reason,
        policy: 'executor.verify_failed',
        correlationId: request.correlationId,
        error: reason,
      };
    }

    if (!verified) {
      let rolledBack = false;
      if (handler.rollback) {
        try {
          await handler.rollback(request, executeResult);
          rolledBack = true;
        } catch {
          rolledBack = false;
        }
      }
      const reason = 'target state did not reach the intended state after execution';
      this.#record(request, 'verification_failed', reason, 'verification.failed', { rolledBack });
      // Deliberately NOT cached: an unverified action must be retryable.
      return {
        status: 'verification_failed',
        action: request.action,
        reason,
        policy: 'verification.failed',
        correlationId: request.correlationId,
        rolledBack,
      };
    }

    const result: ExecutionResult = {
      status: 'succeeded',
      action: request.action,
      reason: 'executed and verified',
      policy: decision.policy,
      correlationId: request.correlationId,
      value: executeResult,
    };
    this.#completed.set(key, result);
    this.#record(request, 'succeeded', 'executed and verified', decision.policy);
    return result;
  }
}
