import { TenantIsolationError } from './errors.ts';

/**
 * §7 — Tenant isolation.
 *
 * The guard is deliberately explicit rather than implicit: callers must state
 * which tenant a piece of data belongs to, and the guard refuses any access
 * that does not match the active scope. Platform-internal records carry a null
 * tenant and are readable only by an internal scope.
 */
export class TenantScope {
  /** null == platform-internal (staff) scope. */
  readonly tenantId: string | null;
  readonly internal: boolean;

  private constructor(tenantId: string | null, internal: boolean) {
    this.tenantId = tenantId;
    this.internal = internal;
  }

  /** A customer-facing scope, pinned to exactly one tenant. */
  static forTenant(tenantId: string): TenantScope {
    if (!tenantId) throw new TenantIsolationError('tenantId is required for a tenant scope');
    return new TenantScope(tenantId, false);
  }

  /** Platform staff scope. May read internal records and any tenant. */
  static internalScope(): TenantScope {
    return new TenantScope(null, true);
  }

  /** True when this scope may access data owned by `ownerTenantId`. */
  canAccess(ownerTenantId: string | null): boolean {
    if (this.internal) return true;
    if (ownerTenantId === null) return false; // customers never read internal records
    return ownerTenantId === this.tenantId;
  }

  /** Throws unless this scope may access the owner. */
  assertCanAccess(ownerTenantId: string | null, what: string): void {
    if (!this.canAccess(ownerTenantId)) {
      throw new TenantIsolationError(`scope may not access ${what}`, {
        scopeTenantId: this.tenantId,
        ownerTenantId,
        what,
      });
    }
  }

  /**
   * Filters a collection down to what this scope may see. Used at the read
   * boundary so a missed check cannot leak rows.
   */
  filter<T>(rows: readonly T[], ownerOf: (row: T) => string | null): T[] {
    return rows.filter((r) => this.canAccess(ownerOf(r)));
  }
}
