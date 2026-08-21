import type { AgentId, PermissionLevel } from './types.ts';
import type { AuditLog } from './audit.ts';

/**
 * §17 — Kill switches. Mandatory, and every use is audit logged.
 *
 * Four independent scopes:
 *   global      — disable all autonomous execution
 *   agent       — disable one agent
 *   integration — disable one integration (Huawei / WHM / GitHub / ...)
 *   autonomy    — disable P2 execution while leaving monitoring alive
 */
export type SwitchScope = 'global' | 'agent' | 'integration' | 'autonomy';

export interface SwitchState {
  readonly engaged: boolean;
  readonly reason: string;
  readonly by: string;
  readonly at: number;
}

export class KillSwitchRegistry {
  #global = false;
  #agents = new Set<AgentId>();
  #integrations = new Set<string>();
  #autonomyDisabled = false;
  #audit: AuditLog;

  constructor(audit: AuditLog) {
    this.#audit = audit;
  }

  #record(action: string, target: string, by: string, reason: string): void {
    this.#audit.append({
      actorType: 'user',
      actorId: by,
      tenantId: null,
      action,
      target,
      result: 'succeeded',
      reason,
      correlationId: `killswitch-${target}`,
      metadata: {},
    });
  }

  engageGlobal(by: string, reason: string): void {
    this.#global = true;
    this.#record('killswitch.engage', 'global', by, reason);
  }

  releaseGlobal(by: string, reason: string): void {
    this.#global = false;
    this.#record('killswitch.release', 'global', by, reason);
  }

  engageAgent(agent: AgentId, by: string, reason: string): void {
    this.#agents.add(agent);
    this.#record('killswitch.engage', `agent:${agent}`, by, reason);
  }

  releaseAgent(agent: AgentId, by: string, reason: string): void {
    this.#agents.delete(agent);
    this.#record('killswitch.release', `agent:${agent}`, by, reason);
  }

  engageIntegration(name: string, by: string, reason: string): void {
    this.#integrations.add(name);
    this.#record('killswitch.engage', `integration:${name}`, by, reason);
  }

  releaseIntegration(name: string, by: string, reason: string): void {
    this.#integrations.delete(name);
    this.#record('killswitch.release', `integration:${name}`, by, reason);
  }

  /** §17 — stop autonomous actions but keep monitoring running. */
  disableAutonomousActions(by: string, reason: string): void {
    this.#autonomyDisabled = true;
    this.#record('killswitch.engage', 'autonomy:P2', by, reason);
  }

  enableAutonomousActions(by: string, reason: string): void {
    this.#autonomyDisabled = false;
    this.#record('killswitch.release', 'autonomy:P2', by, reason);
  }

  get globalEngaged(): boolean {
    return this.#global;
  }
  isAgentDisabled(agent: AgentId): boolean {
    return this.#global || this.#agents.has(agent);
  }
  isIntegrationDisabled(name: string): boolean {
    return this.#global || this.#integrations.has(name);
  }
  get autonomousActionsDisabled(): boolean {
    return this.#global || this.#autonomyDisabled;
  }

  /**
   * Returns a blocking reason for a mutating action, or null if permitted.
   * Read-only work (P0/P1) survives the autonomy switch by design.
   */
  blockingReason(agent: AgentId, level: PermissionLevel, mutates: boolean): string | null {
    if (this.#global) return 'global kill switch engaged';
    if (this.#agents.has(agent)) return `agent kill switch engaged for ${agent}`;
    if (mutates && this.#autonomyDisabled) return 'autonomous actions disabled';
    return null;
  }
}
