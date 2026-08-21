# 13 — Testing Report

**Run date:** 2026-08-21
**Command:** `node --test 'src/ai-workforce/test/*.test.ts'`
**Runtime:** Node v22.22.2, native TypeScript type-stripping, zero dependencies, no network.

```
# tests 38
# suites 8
# pass 38
# fail 0
# duration_ms 261
```

Every test below was executed. Nothing is aspirational; nothing is skipped or marked todo.

---

## 1. Results by suite

### §67 — Tenant isolation (4/4 pass)

| Test | Control |
|---|---|
| customer A cannot access customer B resources | Cross-tenant read denied |
| customer scope cannot read platform-internal records | Internal records invisible to tenants |
| list reads are filtered, so a missed check cannot leak rows | Isolation at the collection boundary |
| policy denies an action targeting another tenant | Isolation enforced in the execution path |

### §67 — P4 critical operations blocked (5/5 pass)

| Test | Control |
|---|---|
| every declared P4 action is denied by policy | All 7 P4 actions denied |
| P4 remains blocked even with every level an operator can enable | No configuration opens P4 |
| P4 cannot be enabled in autonomy configuration at all | `setAutonomy` throws |
| a P4 action cannot even have an executable handler attached | `registerHandler` throws |
| an action absent from the registry is denied | Undeclared capability is unreachable |

The seven P4 actions asserted: `cloud_ops.delete_server`, `cloud_ops.delete_backup`,
`cloud_ops.modify_dns_nameservers`, `security.modify_firewall_rules`,
`security.rotate_root_credentials`, `customer_ops.delete_customer_account`,
`finance.initiate_transfer`.

### §67 — Approval controls (8/8 pass)

| Test | Control |
|---|---|
| an unauthorised user cannot approve | Approver authorisation |
| the requester cannot approve their own request | Separation of duties |
| an expired approval is refused at execution time | Expiry — **see §2, bug found here** |
| changing the target after approval invalidates it | Scope binding (resource) |
| changing the environment after approval invalidates it | Scope binding (environment) |
| an approval is single-use | Replay of a granted approval |
| a P3 action with no approval waits rather than executing | Handler proven not to run |
| a rejected approval cannot be consumed | Rejected state is terminal |

### §15 — Default launch policy (4/4 pass)

| Test | Control |
|---|---|
| P2 is disabled at launch | Launch posture |
| enabling P2 wholesale still requires per-action allowlisting | Action-by-action rollout |
| an allowlisted P2 action runs and is verified | Positive path |
| P0 reads are enabled at launch | Launch posture |

### §17 — Kill switches (4/4 pass)

| Test | Control |
|---|---|
| the global switch stops everything, including reads | Global |
| the autonomy switch stops P2 but keeps monitoring alive | Autonomy vs monitoring |
| the per-agent switch isolates one agent | Per-agent, and release restores |
| every kill-switch operation is audited | §17 audit requirement |

### §58 — Action verification (4/4 pass)

| Test | Control |
|---|---|
| a 200 response is not success: unverified actions fail | Core §58 rule |
| rollback runs when verification fails | Compensation |
| an execution failure is reported, never silently swallowed | §57 no silent failures |
| a replayed event does not execute twice | Idempotency |

### §18/§93 — Audit integrity and secret handling (4/4 pass)

| Test | Control |
|---|---|
| credentials never reach the audit log | Redaction, including nested |
| tampering with history is detectable | Hash chain locates the edited entry |
| every denied action is attributable at a point in time | §95 Q6 |
| an approved action records who approved it | §95 Q7 |

### §79 — Catalogue integrity (5/5 pass)

| Test | Control |
|---|---|
| no P0 or P1 action is declared as mutating | Declaration consistency |
| every action declares blast radius, verification and rollback | §79 completeness |
| an action cannot be invoked by an agent that does not own it | Ownership |
| environment restrictions are enforced | §65 |
| rate limits cap blast radius | §79 |

---

## 2. Defect found and fixed during this run

One real defect was caught by the suite, not by review.

**Symptom.** *an expired approval is refused at execution time* failed: the executor returned
`succeeded` where `denied` was expected.

**Root cause.** `ApprovalEngine.#expireIfDue()` expired only requests in `pending` state:

```ts
if (req.status === 'pending' && this.#clock.now() > req.expiresAt) { ... }
```

An approval that had been **granted** and then sat past its deadline therefore never expired.
`consume()` saw `status === 'approved'` and allowed execution.

**Impact.** §16's expiry control was defeated in exactly its most dangerous case. A P3 approval
for, say, a production worker restart would have remained redeemable indefinitely after being
granted — the window an operator believed they were bounding did not exist.

**Fix.** `expiresAt` now bounds the whole authorisation window, not just the decision window.
Both `pending` and `approved` expire; terminal states are untouched.

```ts
const live = req.status === 'pending' || req.status === 'approved';
if (live && this.#clock.now() > req.expiresAt) { req.status = 'expired'; }
```

The failing test now passes and stands as the regression guard.

---

## 3. Test categories NOT run

Reported honestly per §91. These are blocked by the external dependencies in
`00-current-state-audit.md`, not by omission.

| Category | Status | Reason |
|---|---|---|
| Integration tests | **NOT RUN** | No integrations exist (Blocker 2: no credentials) |
| E2E tests (§68–§72) | **NOT RUN** | Requires agents, runtime and a platform — none exist |
| Browser QA (§76) | **NOT RUN** | Egress to `cloud.mahsumaah.sa` denied (Blocker 3) |
| Regression (§77) | **NOT APPLICABLE** | No pre-existing platform functionality to regress |
| Agent failure test (§73) | **NOT RUN** | No agent runtime or heartbeat implemented |
| AI provider outage test (§74) | **NOT RUN** | No AI provider gateway implemented |
| Integration failure test (§75) | **NOT RUN** | No adapters implemented |

**IDOR testing (§56)** is partially covered: cross-tenant object access is tested at the policy
and scope layers, but there is no HTTP API, so endpoint-level IDOR remains untested.

---

## 4. Reproducing

```bash
node --test 'src/ai-workforce/test/*.test.ts'
```

No install step. No network. No environment variables. No fixtures.
