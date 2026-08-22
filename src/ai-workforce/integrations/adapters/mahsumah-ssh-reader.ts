import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type {
  InfrastructureReader,
  Workload,
  WorkloadHealth,
  WorkloadState,
} from '../ports.ts';

const run = promisify(execFile);

/**
 * First REAL adapter for the Cloud Operations agent (deployment gate 1:
 * read-only inventory, no writer). It implements InfrastructureReader ONLY —
 * there is deliberately no restart/mutate path here, so the credentials this
 * uses (an SSH key) can never be turned into a production write by the agent.
 *
 * Source of truth: `docker` on the Mahsumah nodes over SSH. State comes from
 * `docker inspect`, live CPU/memory from `docker stats`. If a host is
 * unreachable the refresh THROWS (section 75): the agent then records an
 * "integration unreachable" incident instead of silently reading "all healthy".
 */

export interface HostSpec {
  readonly ip: string;
  /** Human label used as the Workload.host evidence field. */
  readonly label: string;
}

export interface MahsumahSshReaderOptions {
  readonly sshKey: string;
  readonly hosts: readonly HostSpec[];
  /** Names matching this are flagged critical (drives incident severity). */
  readonly isCritical?: (name: string) => boolean;
  readonly connectTimeoutSec?: number;
  readonly now?: () => number;
}

const INSPECT_FMT =
  '{{.Name}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}|{{.State.Health.FailingStreak}}{{else}}none|0{{end}}|{{.State.StartedAt}}';

function mapState(dockerStatus: string, health: string): WorkloadState {
  const s = dockerStatus.trim().toLowerCase();
  if (s === 'running') return health.trim().toLowerCase() === 'unhealthy' ? 'unhealthy' : 'running';
  if (s === 'restarting') return 'restarting';
  if (s === 'exited' || s === 'dead' || s === 'created' || s === 'paused' || s === 'removing') {
    return 'stopped';
  }
  return 'unknown';
}

function pct(raw: string | undefined): number | null {
  if (!raw) return null;
  const n = Number.parseFloat(raw.replace('%', '').trim());
  return Number.isFinite(n) ? n : null;
}

export class MahsumahSshReader implements InfrastructureReader {
  readonly name = 'mahsumah-ssh-docker';

  readonly #opts: Required<Omit<MahsumahSshReaderOptions, 'now' | 'isCritical'>> &
    Pick<MahsumahSshReaderOptions, 'now' | 'isCritical'>;
  #cache = new Map<string, { workload: Workload; health: WorkloadHealth }>();

  constructor(opts: MahsumahSshReaderOptions) {
    this.#opts = {
      sshKey: opts.sshKey,
      hosts: opts.hosts,
      connectTimeoutSec: opts.connectTimeoutSec ?? 12,
      now: opts.now,
      isCritical: opts.isCritical,
    };
  }

  #now(): number {
    return this.#opts.now ? this.#opts.now() : Date.now();
  }

  async #ssh(ip: string, remoteCmd: string): Promise<string> {
    const { stdout } = await run(
      'ssh',
      [
        '-i',
        this.#opts.sshKey,
        '-o',
        'StrictHostKeyChecking=no',
        '-o',
        'BatchMode=yes',
        '-o',
        `ConnectTimeout=${this.#opts.connectTimeoutSec}`,
        `root@${ip}`,
        remoteCmd,
      ],
      { timeout: (this.#opts.connectTimeoutSec + 20) * 1000, maxBuffer: 4 * 1024 * 1024 },
    );
    return stdout;
  }

  /** Re-observe every host once and rebuild the cache. Throws if a host fails. */
  async #refresh(): Promise<void> {
    const next = new Map<string, { workload: Workload; health: WorkloadHealth }>();
    const now = this.#now();

    for (const host of this.#opts.hosts) {
      // Two cheap calls per host: inspect (state) + stats (live cpu/mem).
      const stateOut = await this.#ssh(
        host.ip,
        `docker inspect --format '${INSPECT_FMT}' $(docker ps -aq) 2>/dev/null | sed 's|^/||'`,
      );
      let statsOut = '';
      try {
        statsOut = await this.#ssh(
          host.ip,
          `docker stats --no-stream --format '{{.Name}}|{{.CPUPerc}}|{{.MemPerc}}' 2>/dev/null`,
        );
      } catch {
        // stats is best-effort; absence just means cpu/mem report as unavailable.
      }

      const usage = new Map<string, { cpu: number | null; mem: number | null }>();
      for (const line of statsOut.split('\n')) {
        const [name, cpu, mem] = line.split('|');
        if (name?.trim()) usage.set(name.trim(), { cpu: pct(cpu), mem: pct(mem) });
      }

      for (const line of stateOut.split('\n')) {
        if (!line.trim()) continue;
        const [name, status, health, failing, startedAt] = line.split('|');
        const id = (name ?? '').trim();
        if (!id) continue;

        const critical = this.#opts.isCritical ? this.#opts.isCritical(id) : true;
        const startedMs = Date.parse((startedAt ?? '').trim());
        const inStateMs = Number.isFinite(startedMs) ? Math.max(0, now - startedMs) : 0;
        const u = usage.get(id) ?? { cpu: null, mem: null };

        const workload: Workload = {
          id,
          name: id,
          tenantId: null,
          environment: 'production',
          critical,
          host: host.label,
        };
        const wh: WorkloadHealth = {
          workloadId: id,
          state: mapState(status ?? '', health ?? 'none'),
          consecutiveFailures: Number.parseInt((failing ?? '0').trim(), 10) || 0,
          inStateMs,
          cpuPercent: u.cpu,
          memoryPercent: u.mem,
          checkedAt: now,
        };
        next.set(id, { workload, health: wh });
      }
    }

    this.#cache = next;
  }

  async listWorkloads(): Promise<readonly Workload[]> {
    await this.#refresh();
    return [...this.#cache.values()].map((e) => e.workload);
  }

  async getHealth(workloadId: string): Promise<WorkloadHealth> {
    const hit = this.#cache.get(workloadId);
    if (!hit) throw new Error(`unknown workload ${workloadId}`);
    return hit.health;
  }
}
