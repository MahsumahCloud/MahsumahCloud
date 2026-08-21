import { createHash, randomUUID } from 'node:crypto';
import type { Clock } from './clock.ts';
import { systemClock } from './clock.ts';
import type { ActionRequest, ActionTarget, AgentId, Severity } from './types.ts';
import { ApprovalError } from './errors.ts';
import type { AuditLog } from './audit.ts';

/**
 * Section 16 - Scoped approval system.
 *
 * An approval authorises ONE exact action against ONE exact target, for a
 * bounded time, once. There are no blanket approvals: the scope is reduced to a
 * fingerprint at request time, and re-derived at execution time. If any element
 * of the scope changed in between, the fingerprints differ and the approval is
 * refused (section 67 "Scope Change" test).
 */
export interface ApprovalRequest {
  readonly id: string;
  readonly action: string;
  readonly target: ActionTarget;
  readonly agent: AgentId;
  readonly requestedBy: string;
  readonly reason: string;
  readonly evidence: readonly string[];
  readonly risk: Severity;
  readonly predictedEffect: string;
  readonly rollback: string;
  readonly correlationId: string;
  readonly incidentId?: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  /** Binds the approval to the exact scope. */
  readonly scopeFingerprint: string;
  status: 'pending' | 'approved' | 'rejected' | 'expired' | 'consumed';
  decidedBy?: string;
  decidedAt?: number;
  decisionNote?: string;
}

/** Canonical scope fingerprint - every field that defines "which exact action". */
export function scopeFingerprint(action: string, target: ActionTarget): string {
  const canonical = [
    action,
    target.resourceType,
    target.resourceId,
    target.tenantId ?? '__internal__',
    target.environment,
  ].join(' ');
  return createHash('sha256').update(canonical).digest('hex');
}

/** Who may approve what. Sections 51/67 - unauthorised approval must be denied. */
export interface ApproverDirectory {
  canApprove(userId: string, action: string, target: ActionTarget): boolean;
}

export class ApprovalEngine {
  #byId = new Map<string, ApprovalRequest>();
  #clock: Clock;
  #audit: AuditLog;
  #approvers: ApproverDirectory;

  constructor(audit: AuditLog, approvers: ApproverDirectory, clock: Clock = systemClock) {
    this.#audit = audit;
    this.#approvers = approvers;
    this.#clock = clock;
  }

  /** Section 16 - create an approval request carrying full context. */
  request(input: {
    action: string;
    target: ActionTarget;
    agent: AgentId;
    requestedBy: string;
    reason: string;
    evidence: readonly string[];
    risk: Severity;
    predictedEffect: string;
    rollback: string;
    correlationId: string;
    incidentId?: string;
    ttlMs: number;
  }): ApprovalRequest {
    const now = this.#clock.now();
    const req: ApprovalRequest = {
      id: randomUUID(),
      action: input.action,
      target: input.target,
      agent: input.agent,
      requestedBy: input.requestedBy,
      reason: input.reason,
      evidence: input.evidence,
      risk: input.risk,
      predictedEffect: input.predictedEffect,
      rollback: input.rollback,
      correlationId: input.correlationId,
      incidentId: input.incidentId,
      createdAt: now,
      expiresAt: now + input.ttlMs,
      scopeFingerprint: scopeFingerprint(input.action, input.target),
      status: 'pending',
    };
    this.#byId.set(req.id, req);
    this.#audit.append({
      actorType: 'agent',
      actorId: input.agent,
      tenantId: input.target.tenantId,
      action: 'approval.requested',
      target: `${input.action}:${input.target.resourceId}`,
      result: 'allowed',
      reason: input.reason,
      correlationId: input.correlationId,
      approvalId: req.id,
      metadata: { risk: input.risk, expiresAt: req.expiresAt },
    });
    return req;
  }

  get(id: string): ApprovalRequest | undefined {
    return this.#byId.get(id);
  }

  /**
   * expiresAt bounds the whole authorisation window, not merely the window in
   * which a decision may be made. An already-approved request that is not used
   * before its deadline must expire too - otherwise a granted approval would
   * remain redeemable indefinitely, which is the exact risk section 16 guards
   * against. Terminal states (rejected / consumed / expired) are left alone.
   */
  #expireIfDue(req: ApprovalRequest): void {
    const live = req.status === 'pending' || req.status === 'approved';
    if (live && this.#clock.now() > req.expiresAt) {
      req.status = 'expired';
    }
  }

  approve(id: string, approverId: string, note = ''): ApprovalRequest {
    const req = this.#byId.get(id);
    if (!req) throw new ApprovalError('approval not found', { approvalId: id });
    this.#expireIfDue(req);

    const deny = (why: string): never => {
      this.#audit.append({
        actorType: 'user',
        actorId: approverId,
        tenantId: req.target.tenantId,
        action: 'approval.decision',
        target: `${req.action}:${req.target.resourceId}`,
        result: 'denied',
        reason: why,
        correlationId: req.correlationId,
        approvalId: req.id,
        metadata: {},
      });
      throw new ApprovalError(why, { approvalId: id, approverId });
    };

    if (req.status !== 'pending') deny(`approval is ${req.status}, not pending`);
    // Section 67 - the requester must not approve their own request.
    if (approverId === req.requestedBy) deny('requester may not approve their own request');
    if (!this.#approvers.canApprove(approverId, req.action, req.target)) {
      deny('approver is not authorised for this action or target');
    }

    req.status = 'approved';
    req.decidedBy = approverId;
    req.decidedAt = this.#clock.now();
    req.decisionNote = note;
    this.#audit.append({
      actorType: 'user',
      actorId: approverId,
      tenantId: req.target.tenantId,
      action: 'approval.decision',
      target: `${req.action}:${req.target.resourceId}`,
      result: 'allowed',
      reason: note || 'approved',
      correlationId: req.correlationId,
      approvalId: req.id,
      metadata: {},
    });
    return req;
  }

  reject(id: string, approverId: string, note = ''): ApprovalRequest {
    const req = this.#byId.get(id);
    if (!req) throw new ApprovalError('approval not found', { approvalId: id });
    this.#expireIfDue(req);
    if (req.status !== 'pending') {
      throw new ApprovalError(`approval is ${req.status}, not pending`, { approvalId: id });
    }
    if (!this.#approvers.canApprove(approverId, req.action, req.target)) {
      throw new ApprovalError('approver is not authorised', { approvalId: id, approverId });
    }
    req.status = 'rejected';
    req.decidedBy = approverId;
    req.decidedAt = this.#clock.now();
    req.decisionNote = note;
    this.#audit.append({
      actorType: 'user',
      actorId: approverId,
      tenantId: req.target.tenantId,
      action: 'approval.decision',
      target: `${req.action}:${req.target.resourceId}`,
      result: 'denied',
      reason: note || 'rejected',
      correlationId: req.correlationId,
      approvalId: req.id,
      metadata: {},
    });
    return req;
  }

  /**
   * Validates and CONSUMES an approval for a specific execution. Throws unless
   * the approval is approved, unexpired, unconsumed, and bound to exactly this
   * action and target.
   */
  consume(request: ActionRequest): ApprovalRequest {
    const id = request.approvalId;
    if (!id) throw new ApprovalError('action requires an approval but none was supplied');
    const req = this.#byId.get(id);
    if (!req) throw new ApprovalError('approval not found', { approvalId: id });
    this.#expireIfDue(req);

    if (req.status === 'expired') {
      throw new ApprovalError('approval has expired', { approvalId: id, expiresAt: req.expiresAt });
    }
    if (req.status === 'consumed') {
      throw new ApprovalError('approval has already been used', { approvalId: id });
    }
    if (req.status !== 'approved') {
      throw new ApprovalError(`approval is ${req.status}`, { approvalId: id });
    }
    // Section 67 Scope Change - re-derive the fingerprint from what is executing now.
    const actual = scopeFingerprint(request.action, request.target);
    if (actual !== req.scopeFingerprint) {
      throw new ApprovalError('approval scope does not match the requested action', {
        approvalId: id,
        approvedScope: req.scopeFingerprint,
        requestedScope: actual,
      });
    }
    req.status = 'consumed';
    return req;
  }

  pending(): ApprovalRequest[] {
    for (const r of this.#byId.values()) this.#expireIfDue(r);
    return [...this.#byId.values()].filter((r) => r.status === 'pending');
  }
}
