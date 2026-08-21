# 14 — Deployment

**Who runs this:** Ahmed, on his own machine and server.
**Why not Claude:** the build session runs in an isolated Linux container with no access to
`/Users/ahmedasaud`, no Chrome on the Mac, and no network route to `cloud.mahsumaah.sa` or
`80.238.198.115` (egress gateway answers 403 to CONNECT). Every command below was written to be
run by a human with those accesses. Nothing here has been executed by Claude, and nothing below
is reported as verified.

---

## 0. Prerequisites check

```bash
node --version
```

- **Node 22.18+** strips TypeScript types by default; everything just works.
- **Node 22.6-22.17** needs `--experimental-strip-types`. `npm test` already carries it, so use
  that rather than a bare `node --test`, which fails with `ERR_UNKNOWN_FILE_EXTENSION`.
- **Below 22.6** the core cannot run without adding a build step.

There are no dependencies, so there is nothing to `npm install`.

---

## 1. Recover the commits

The two commits could not be pushed from the build session — the Claude GitHub App lacks
`contents: write` on `MahsumahCloud/MahsumahCloud`. They were delivered as a git bundle instead.

The earlier restore attempt failed with `fatal: not a git repository`, because
`~/Mahsumah Cloud` is a working directory, not a clone. Clone the repo first:

```bash
cd ~
git clone https://github.com/MahsumahCloud/MahsumahCloud.git mahsumah-workforce
cd mahsumah-workforce

# point at wherever the bundle was saved (usually ~/Downloads)
git fetch ~/Downloads/mahsumah-ai-workforce.bundle \
  'refs/heads/*:refs/heads/*'

git checkout claude/mahsumah-autonomous-ops-cnpqrf
git log --oneline -3
```

Expected commits:

```
2c4ee6d  Implement AI Workforce safety core with security test suite
3a7032c  Add Phase 0 current-state audit for AI Workforce program
880b890  Revise README for improved platform description
```

> A later commit adds the runtime (scheduler, heartbeat, incident engine). Confirm the tip hash
> against whatever the session last reported rather than assuming `2c4ee6d` is the tip.

---

## 2. Verify before pushing

```bash
npm test
```

Expected: **74 passing, 0 failing**, no install step and no network access required.

If this reports `tests 0`, the files are not where the glob is looking - the working directory
is wrong — the earlier attempt hit exactly this
because the files were not present. Confirm with `ls src/ai-workforce/core/` first.

---

## 3. Push

Once `contents: write` is granted to the Claude GitHub App (or simply push under your own
credentials, which already have access):

```bash
git push -u origin claude/mahsumah-autonomous-ops-cnpqrf
```

Then verify from GitHub itself, not only the terminal:

```
https://github.com/MahsumahCloud/MahsumahCloud/commits/claude/mahsumah-autonomous-ops-cnpqrf
```

Confirm the commit hashes on that page match `git log --oneline -3` locally.

---

## 4. What is safe to deploy today, and what is not

**Deployable now:** nothing that touches customers. The core is a library — it has no HTTP
server, no database, no integrations and no customer-facing surface. It cannot serve traffic.

**Not deployable:** the seven agents, every integration, the UI and the API. They do not exist.
See `FINAL-COMPLETION-MATRIX.md`.

Per §78, **no autonomous action may be enabled**: gates 1, 3, 5 and 8 are blocked.
`defaultLaunchAutonomy()` ships with `enabledP2Actions` empty, so even loading the library grants
no agent the ability to change anything.

### The honest deployment position

The correct next step is **not** to deploy this to production. It is to attach the core to the
real platform (Blocker 1), because the schema, tenancy model and RBAC it must bind to are still
unknown to the build session. Deploying a policy engine that does not yet know your real tenant
model would be theatre.

---

## 5. Answering §95 Q1/Q2 — running without Claude

The scheduler is deliberately host-agnostic: it owns *what is due*, the host owns *when to ask*.
That makes 24/7 operation a deployment decision. Given the existing architecture (Docker
container `mahsumaah-cloud`, cron on the host), the shape that fits is a long-lived process:

```js
// worker.mjs — illustrative; not yet wired to real agents
import { Scheduler } from './src/ai-workforce/runtime/scheduler.ts';
import { HeartbeatMonitor } from './src/ai-workforce/runtime/heartbeat.ts';
import { AuditLog } from './src/ai-workforce/core/audit.ts';

const audit = new AuditLog();
const scheduler = new Scheduler(audit);
const heartbeat = new HeartbeatMonitor(audit);

heartbeat.expect('cloud_ops');
scheduler.register({
  name: 'watchdog',
  intervalMs: 60_000,
  singleFlight: true,
  run: async () => {
    for (const bad of heartbeat.sweep()) console.error('UNHEALTHY', bad.agent, bad.detail);
  },
});

scheduler.start();
setInterval(() => scheduler.tick().catch((e) => console.error('tick failed', e)), 10_000);
```

**Do not deploy this yet.** It runs, but it supervises nothing: no agent emits heartbeats
because no agent exists. It is included to show the integration shape, and because §85 forbids
claiming a runtime exists when only its skeleton does.

A cron-driven variant is the wrong choice here: cron cannot express single-flight, and a
5-minute cron that overruns will overlap itself. The in-process scheduler prevents that
(`singleFlight`, tested).

---

## 6. Rollback

Nothing is deployed, so nothing needs rolling back. Should the branch itself need reverting:

```bash
git revert --no-commit 2c4ee6d 3a7032c
git commit -m "Revert AI Workforce core"
```

Do **not** force-push; the branch may be shared.

---

## 7. Live verification — blocked

§76 (Browser QA) and §90 (live status) require reaching `cloud.mahsumaah.sa`. That is not
possible from the build session (egress 403). When it is performed, it must be performed by
someone with browser access to the portal, and the results recorded in `13-testing.md` under a
new "Browser QA" section — replacing the current `BLOCKED` row rather than sitting alongside it.

Until then, every live-status value in `FINAL-COMPLETION-MATRIX.md` §10 stays `UNAVAILABLE` with
its stated reason. No value there may be filled in from assumption (§90).
