import type {
  ActionDescriptor,
  ActionRequest,
  AutonomyConfig,
  Environment,
  PermissionLevel as PermissionLevelType,
} from './types.ts';
import { PermissionLevel, PERMISSION_LEVEL_NAMES } from './types.ts';
import type { TenantScope } from './tenant.ts';
import type { KillSwitchRegistry } from './killswitch.ts';
import type { AuditLog } from './audit.ts';
import type { Clock } from './clock.ts';
import { systemClock } from './clock.ts';

/**
 * Section 50 - Policy as code.
 *
 * The decision to permit an action is made here by deterministic rules, never
 * by a model. Section 12 is explicit that the LLM must not be the only security
 * boundary; nothing in this module consults an AI provider.
 */
export type PolicyOutcome = 'allow' | 'require_approval' | 'deny';

export interface PolicyDecision {
  readonly outcome: PolicyOutcome;
  readonly reason: string;
  readonly policy: string;
  readonly level: PermissionLevelType;
}

/** Section 79 - the declared catalogue of every capability an agent may invoke. */
export class ActionRegistry {
  #byName = new Map<string, ActionDescriptor>();

  register(descriptor: ActionDescriptor): void {
    if (this.#byName.has(descriptor.name)) {
      throw new Error(`action already registered: ${descriptor.name}`);
    }
    // A read-only level that claims to mutate is a declaration bug; reject it
    // at registration rather than discovering it at execution time.
    if (
      descriptor.mutates &&
      (descriptor.level === PermissionLevel.P0_READ ||
        descriptor.level === PermissionLevel.P1_RECOMMEND)
    ) {
      throw new Error(
        `action ${descriptor.name} is declared ${PERMISSION_LEVEL_NAMES[descriptor.level]} but mutates state`,
      );
    }
    this.#byName.set(descriptor.name, descriptor);
  }

  get(name: string): ActionDescriptor | undefined {
    return this.#byName.get(name);
  }

  all(): readonly ActionDescriptor[] {
    return [...this.#byName.values()];
  }

  byLevel(level: PermissionLevelType): ActionDescriptor[] {
    return this.all().filter((a) => a.level === level);
  }
}

/** Simple sliding-window rate limiter backing ActionDescriptor.rateLimitPerHour. */
class RateLimiter {
  #hits = new Map<string, number[]>();
  #clock: Clock;
  constructor(clock: Clock) {
    this.#clock = clock;
  }
  /** Returns true when the call is within budget, and records it. */
  tryConsume(key: string, limitPerHour: number): boolean {
    const now = this.#clock.now();
    const cutoff = now - 3_600_000;
    const arr = (this.#hits.get(key) ?? []).filter((t) => t > cutoff);
    if (arr.length >= limitPerHour) {
      this.#hits.set(key, arr);
      return false;
    }
    arr.push(now);
    this.#hits.set(key, arr);
    return true;
  }
}

export class PolicyEngine {
  #registry: ActionRegistry;
  #killSwitches: KillSwitchRegistry;
  #audit: AuditLog;
  #autonomy: AutonomyConfig;
  #rateLimiter: RateLimiter;

  constructor(
    registry: ActionRegistry,
    killSwitches: KillSwitchRegistry,
    audit: AuditLog,
    autonomy: AutonomyConfig,
    clock: Clock = systemClock,
  ) {
    this.#registry = registry;
    this.#killSwitches = killSwitches;
    this.#audit = audit;
    this.#autonomy = autonomy;
    this.#rateLimiter = new RateLimiter(clock);
  }

  get autonomy(): AutonomyConfig {
    return this.#autonomy;
  }

  /**
   * Section 15 - autonomy is rolled out level by level, and P2 action by action.
   * P4 can never be enabled: the setter refuses it outright.
   */
  setAutonomy(next: AutonomyConfig, by: string): void {
    if (next.enabledLevels.has(PermissionLevel.P4_MANUAL_CRITICAL)) {
      throw new Error('P4_MANUAL_CRITICAL can never be enabled for autonomous execution');
    }
    this.#autonomy = next;
    this.#audit.append({
      actorType: 'user',
      actorId: by,
      tenantId: null,
      action: 'autonomy.configure',
      target: 'policy_engine',
      result: 'succeeded',
      reason: 'autonomy configuration changed',
      correlationId: 'autonomy-config',
      metadata: {
        enabledLevels: [...next.enabledLevels].map((l) => PERMISSION_LEVEL_NAMES[l]),
        enabledP2Actions: [...next.enabledP2Actions],
      },
    });
  }

  /**
   * The single decision point for whether an agent may proceed.
   * Evaluation order matters: cheaper, more absolute refusals come first.
   */
  evaluate(request: ActionRequest, scope: TenantScope): PolicyDecision {
    const descriptor = this.#registry.get(request.action);

    // 1. Undeclared actions do not exist. Section 79.
    if (!descriptor) {
      return {
        outcome: 'deny',
        reason: `action '${request.action}' is not in the action registry`,
        policy: 'registry.unknown_action',
        level: PermissionLevel.P4_MANUAL_CRITICAL,
      };
    }

    // 2. Section 14 - P4 is never autonomous, under any configuration.
    if (descriptor.level === PermissionLevel.P4_MANUAL_CRITICAL) {
      return {
        outcome: 'deny',
        reason: 'P4_MANUAL_CRITICAL actions are never available to agents',
        policy: 'autonomy.p4_blocked',
        level: descriptor.level,
      };
    }

    // 3. Section 7 - tenant isolation. The agent's scope must own the target.
    if (!scope.canAccess(request.target.tenantId)) {
      return {
        outcome: 'deny',
        reason: 'target belongs to a different tenant',
        policy: 'tenant.isolation',
        level: descriptor.level,
      };
    }

    // 4. Section 17 - kill switches.
    const blocked = this.#killSwitches.blockingReason(
      request.agent,
      descriptor.level,
      descriptor.mutates,
    );
    if (blocked) {
      return { outcome: 'deny', reason: blocked, policy: 'killswitch', level: descriptor.level };
    }

    // 5. The action must belong to the agent that is invoking it.
    if (descriptor.owner !== request.agent) {
      return {
        outcome: 'deny',
        reason: `action '${descriptor.name}' belongs to ${descriptor.owner}, not ${request.agent}`,
        policy: 'registry.wrong_owner',
        level: descriptor.level,
      };
    }

    // 6. Section 65 - environment restrictions.
    if (!descriptor.allowedEnvironments.includes(request.target.environment)) {
      return {
        outcome: 'deny',
        reason: `action is not permitted in environment '${request.target.environment}'`,
        policy: 'environment.not_allowed',
        level: descriptor.level,
      };
    }

    // 7. Section 15 - the level itself must be enabled.
    if (!this.#autonomy.enabledLevels.has(descriptor.level)) {
      return {
        outcome: 'deny',
        reason: `${PERMISSION_LEVEL_NAMES[descriptor.level]} is not currently enabled`,
        policy: 'autonomy.level_disabled',
        level: descriptor.level,
      };
    }

    // 8. Level-specific handling.
    if (descriptor.level === PermissionLevel.P3_APPROVAL_REQUIRED) {
      return {
        outcome: 'require_approval',
        reason: 'action requires a scoped human approval',
        policy: 'autonomy.p3_approval',
        level: descriptor.level,
      };
    }

    if (descriptor.level === PermissionLevel.P2_SAFE_AUTONOMOUS) {
      // Section 15 - P2 is allowlisted per action, never wholesale.
      if (!this.#autonomy.enabledP2Actions.has(descriptor.name)) {
        return {
          outcome: 'deny',
          reason: `P2 action '${descriptor.name}' is not on the autonomous allowlist`,
          policy: 'autonomy.p2_not_allowlisted',
          level: descriptor.level,
        };
      }
    }

    // 9. Section 79 - blast-radius rate limiting.
    if (descriptor.rateLimitPerHour !== undefined) {
      const key = `${descriptor.name}:${request.target.tenantId ?? '__internal__'}`;
      if (!this.#rateLimiter.tryConsume(key, descriptor.rateLimitPerHour)) {
        return {
          outcome: 'deny',
          reason: `rate limit of ${descriptor.rateLimitPerHour}/hour exceeded`,
          policy: 'ratelimit.exceeded',
          level: descriptor.level,
        };
      }
    }

    return {
      outcome: 'allow',
      reason: 'permitted by policy',
      policy: `autonomy.${PERMISSION_LEVEL_NAMES[descriptor.level].toLowerCase()}`,
      level: descriptor.level,
    };
  }
}
