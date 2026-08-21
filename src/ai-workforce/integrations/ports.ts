import type { Environment } from '../core/types.ts';

/**
 * Section 20 - Integration layer, expressed as PORTS ONLY.
 *
 * These are interfaces, not implementations. There is deliberately no
 * HuaweiAdapter, CPanelWhmAdapter or GitHubAdapter in this directory:
 * section 21 forbids implementing connectors for systems that are not
 * actually reachable, and sections 64/85 forbid shipping a connector that
 * returns invented data.
 *
 * What this file buys us is that the agents above it are real and testable
 * TODAY. An agent depends on the port, not on a vendor. When credentials and
 * egress exist (blockers 2 and 3 in 00-current-state-audit.md), the adapters
 * are written against these signatures and the agents do not change.
 *
 * Every method may reject. Section 57 requires callers to treat integration
 * failure as normal, not exceptional.
 */

export type WorkloadState = 'running' | 'stopped' | 'unhealthy' | 'restarting' | 'unknown';

export interface Workload {
  readonly id: string;
  readonly name: string;
  readonly tenantId: string | null;
  readonly environment: Environment;
  /** True when customers depend on it directly. Drives severity, section 26. */
  readonly critical: boolean;
  /** Provider-side host or node identifier, for evidence. */
  readonly host: string;
}

export interface WorkloadHealth {
  readonly workloadId: string;
  readonly state: WorkloadState;
  /** Consecutive failed health checks as observed by the provider. */
  readonly consecutiveFailures: number;
  /** Milliseconds the workload has been in its current state. */
  readonly inStateMs: number;
  readonly cpuPercent: number | null;
  readonly memoryPercent: number | null;
  readonly checkedAt: number;
}

/**
 * Read/inventory surface. A P0 agent needs only this much.
 * An adapter that can implement ONLY this is still useful: it satisfies
 * deployment gate 1 (read-only inventory) without any write scope.
 */
export interface InfrastructureReader {
  readonly name: string;
  listWorkloads(): Promise<readonly Workload[]>;
  getHealth(workloadId: string): Promise<WorkloadHealth>;
}

/**
 * Mutating surface, kept separate so credentials can be scoped read-only.
 * Section 15 launches with no P2 enabled, so a deployment may legitimately
 * provide a reader and no writer at all.
 */
export interface InfrastructureWriter {
  /** Requests a restart. Returns the provider's operation id. */
  restartWorkload(workloadId: string): Promise<{ operationId: string }>;
  /** Forces a fresh health probe, bypassing any cached result. */
  probeHealth(workloadId: string): Promise<WorkloadHealth>;
}

export interface Certificate {
  readonly domain: string;
  readonly tenantId: string | null;
  readonly issuer: string;
  readonly notAfter: number;
  readonly hostnameMatches: boolean;
  readonly chainValid: boolean;
}

export interface CertificateReader {
  readonly name: string;
  listCertificates(): Promise<readonly Certificate[]>;
}

/**
 * Section 75 - integration health. An adapter reports its own reachability so
 * a failure surfaces as "degraded integration", never as "everything healthy".
 */
export interface IntegrationHealth {
  readonly name: string;
  readonly reachable: boolean;
  readonly checkedAt: number;
  readonly detail: string;
}

export interface HealthCheckable {
  checkIntegrationHealth(): Promise<IntegrationHealth>;
}
