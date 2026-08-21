# 01 — Architecture (Implemented Subset)

**Status:** Phase 2 (shared core) and Phase 3 (security / policy / audit) implemented and tested.
Phases 4–16 blocked — see `00-current-state-audit.md`.

This document describes **only what exists in `src/ai-workforce/`**. It is not a plan. Anything
not built is named as not built, per §87 ("documentation must match actual implementation").

---

## 1. Why this layer was built first

Phase 0 established that the Mahsumah Cloud platform is not reachable from this environment
(no application source, no Huawei/WHM credentials, no egress). Integration work (Phases 4–12)
is therefore blocked.

The shared safety core, however, depends on **none of those things**. Policy evaluation,
approval scoping, audit integrity, tenant isolation and action verification are pure decision
logic. They can be built and — more importantly — **proven by execution** with no external
dependency at all. That is what this layer is.

This ordering also matches §84: build a complete, reliable vertical slice rather than a broad
shallow one. The slice chosen is the one every other phase must pass through.

---

## 2. The single execution path

Every action any agent will ever take passes through one funnel. There is no side door:
handlers are not callable directly, because only `ActionExecutor` holds the handler map.

```text
ActionRequest + TenantScope
        │
        ▼
  PolicyEngine.evaluate()          deterministic, no LLM involved
        │
        ├── unknown action ──────────────────► DENY   registry.unknown_action
        ├── level is P4 ────────────────────► DENY   autonomy.p4_blocked
        ├── target owned by another tenant ─► DENY   tenant.isolation
        ├── kill switch engaged ────────────► DENY   killswitch
        ├── action not owned by this agent ─► DENY   registry.wrong_owner
        ├── environment not allowed ────────► DENY   environment.not_allowed
        ├── level not enabled ──────────────► DENY   autonomy.level_disabled
        ├── P2 not allowlisted ─────────────► DENY   autonomy.p2_not_allowlisted
        ├── rate limit exceeded ────────────► DENY   ratelimit.exceeded
        ├── level is P3 ────────────────────► REQUIRE_APPROVAL
        └── otherwise ──────────────────────► ALLOW
        │
        ▼
  ApprovalEngine.consume()         P3 only — scope-bound, single-use, expiring
        │
        ▼
  Idempotency check                runId|action|resourceType|resourceId
        │
        ▼
  handler.execute()
        │
        ▼
  handler.verify()                 §58 — re-observes the target
        │
        ├── false ──► rollback() if provided ──► VERIFICATION_FAILED (not cached)
        └── true  ──► SUCCEEDED (cached against replay)
        │
        ▼
  AuditLog.append()                hash-chained, secrets redacted
```

Ordering is deliberate: the cheapest and most absolute refusals run first, so a P4 request is
rejected before any tenant lookup, rate-limit bookkeeping or handler resolution occurs.

---

## 3. Modules

| File | Lines | Responsibility | Directive |
|---|---|---|---|
| `core/types.ts` | 133 | Permission levels, statuses, action descriptors, launch policy | §10, §14, §15 |
| `core/errors.ts` | 47 | Typed failures, one per control | §7, §14, §16, §17, §58 |
| `core/clock.ts` | 23 | Injectable time, so expiry is deterministic under test | §16 |
| `core/tenant.ts` | 57 | `TenantScope` — access checks and read filtering | §7 |
| `core/audit.ts` | 141 | Hash-chained append-only log, secret redaction, query | §18, §93 |
| `core/killswitch.ts` | 111 | Four switch scopes, all audited | §17 |
| `core/policy.ts` | 257 | `ActionRegistry` + `PolicyEngine` + rate limiter | §50, §79 |
| `core/approval.ts` | 251 | Scoped, expiring, single-use approvals | §16 |
| `core/executor.ts` | 255 | The funnel: policy → approval → execute → verify → audit | §57, §58 |
| `actions/registry.ts` | 338 | The declared action catalogue | §79 |
| `test/security.test.ts` | 685 | 38 tests across 8 suites | §67 |

Total: 2,298 lines. Zero runtime dependencies.

---

## 4. Design decisions and their rationale

### 4.1 The LLM is not in this path

§12 requires that AI must not be the only security boundary. No module in `core/` imports or
calls an AI provider. Policy outcomes are produced by comparison and set membership. An AI
provider can *propose* an `ActionRequest`; it cannot influence whether that request is allowed.

### 4.2 P4 is structurally unreachable, not merely disallowed

Three independent mechanisms, so no single mistake can open the path:

1. `PolicyEngine.evaluate()` denies P4 as its second check, before anything else.
2. `PolicyEngine.setAutonomy()` **throws** if P4 appears in `enabledLevels` — the state where
   P4 is enabled cannot be constructed.
3. `ActionExecutor.registerHandler()` **throws** for a P4 action — there is no code to run.

Even with every enableable level on and the action added to the P2 allowlist, P4 stays denied
(test: *P4 remains blocked even with every level an operator can enable*).

### 4.3 Approvals bind to a fingerprint, not to an intent

`scopeFingerprint()` is a SHA-256 over `action | resourceType | resourceId | tenantId |
environment`. It is computed when the approval is requested and **re-computed from the request
actually being executed**. Any drift — a different worker, a different environment, a different
tenant — produces a different digest and the approval is refused. This implements §16's "no
blanket approvals" as a data property rather than a review convention.

### 4.4 Verification is mandatory by type

`ActionHandler` requires both `execute` and `verify`. A handler that only knows how to call an
API does not satisfy the interface, so §58 cannot be skipped by omission. `verify` must
re-observe the target rather than trust `execute`'s return value.

A failed verification is **deliberately not cached**, so the action remains retryable; a
success is cached, so a duplicate event cannot re-run it.

### 4.5 Audit integrity is provable, not asserted

Each entry commits to its predecessor's hash. `verifyChain()` re-walks the log and returns the
index of the first entry that does not reconcile. §93 requires proving controls rather than
claiming them; the test tampers with entry 2 of 5 and asserts the chain reports exactly 2.

Redaction runs at **write** time over the metadata tree, so a careless caller cannot persist a
credential even by accident.

### 4.6 Kill switches distinguish "stop acting" from "stop looking"

§17 requires disabling autonomous action while keeping monitoring alive. `blockingReason()`
consults the autonomy switch **only when `mutates` is true**, so P0 reads continue during an
autonomy freeze. The global switch, by contrast, stops everything including reads.

---

## 5. What is NOT built

Stated plainly so this document cannot be mistaken for a completion claim:

- **No agents.** None of the seven agents exists. The catalogue declares the actions they would
  own; no agent loop, scheduler, or workflow engine has been written.
- **No integrations.** No Huawei, cPanel/WHM, GitHub, DNS, SSL, backup, email or CRM adapter.
  Writing them against unreachable APIs would produce unverifiable connectors (§64, §85).
- **No persistence.** `AuditLog` and `ApprovalEngine` hold state in memory. No database was
  chosen because the platform's database engine is unknown (Blocker 1).
- **No runtime.** No worker, scheduler, queue or heartbeat. §95 Q1/Q2 ("agents keep running
  when Claude is closed") is therefore **not satisfied** — there is nothing deployed to run.
- **No UI, no API, no incident engine, no AI provider gateway.**

The core is the boundary those pieces must be built behind — not a substitute for them.

---

## 6. Integration contract for the real platform

When Blocker 1 clears, this layer attaches to the real platform at exactly three seams, so the
discovered schema drives the integration rather than the reverse:

1. **`TenantScope`** — construct from the platform's authenticated principal. The rest of the
   core is already tenant-aware.
2. **`ActionHandler`** — implement `execute`/`verify` per action against the real adapters.
   The catalogue's `verification` field already states what each `verify` must observe.
3. **`AuditLog`** — replace the in-memory store with the platform's persistence, preserving
   `prevHash` chaining. `verifyChain()` should then run as a scheduled integrity check.

`ApproverDirectory` is an interface for the same reason: it binds to the platform's real RBAC
rather than assuming one.
