/**
 * New pages for Ziro panel v4.7+ UI.
 *
 * LiveTrafficMonitor  — WebSocket stream of proxy requests.
 * DashboardV2         — dense one-shot overview using /api/dashboard/summary.
 * EngagementStateView — hosts/services/credentials/findings from /api/engagement-state.
 * ApprovalsQueue      — pending operator approval requests.
 * TimelinePage        — Gantt-ish timeline of agent activity.
 * CostBreakdown       — per-agent LLM cost.
 * CheckpointsPage     — scan checkpoint manager.
 * LlmDebugPage        — inspect agent messages for debugging.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Check,
  ChevronDown,
  ChevronRight,
  Cpu,
  Database,
  DollarSign,
  Download,
  Eye,
  HardDrive,
  History,
  Pause,
  Play,
  Radio,
  Server,
  Shield,
  Trash2,
  Upload,
  X,
  Zap,
} from 'lucide-react';
import { api } from './api';
import { cn } from './lib/utils';

// --- Shared helpers ---

const SEV_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/30',
  HIGH: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
  MEDIUM: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
  LOW: 'text-green-400 bg-green-500/10 border-green-500/30',
  INFO: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
};

const SEV_BG: Record<string, string> = {
  CRITICAL: 'bg-red-500',
  HIGH: 'bg-orange-500',
  MEDIUM: 'bg-yellow-500',
  LOW: 'bg-green-500',
  INFO: 'bg-blue-500',
};

function useInterval<T>(
  fetcher: () => Promise<T | null>,
  ms = 3000,
  enabled = true,
): { data: T | null; loading: boolean; refresh: () => void } {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetcher();
      if (r !== null) setData(r);
    } finally {
      setLoading(false);
    }
  }, [fetcher]);

  useEffect(() => {
    if (!enabled) return;
    load();
    const id = setInterval(load, ms);
    return () => clearInterval(id);
  }, [load, ms, enabled]);

  return { data, loading, refresh: load };
}

function StatCard({
  label,
  value,
  sub,
  icon: Icon,
  color = 'text-[#a855f7]',
}: {
  label: string;
  value: string | number;
  sub?: string;
  icon?: React.ComponentType<{ className?: string }>;
  color?: string;
}) {
  return (
    <div className="bg-[#111] border border-[#222] rounded-xl p-4 flex flex-col gap-1">
      <div className="flex items-center justify-between">
        <div className="text-xs text-[#666] uppercase tracking-wider">{label}</div>
        {Icon && <Icon className={cn('w-4 h-4', color)} />}
      </div>
      <div className={cn('text-2xl font-bold', color)}>{value}</div>
      {sub && <div className="text-xs text-[#8c8c8c]">{sub}</div>}
    </div>
  );
}

function Panel({
  title,
  children,
  right,
}: {
  title: string;
  children: React.ReactNode;
  right?: React.ReactNode;
}) {
  return (
    <div className="bg-[#111] border border-[#222] rounded-xl">
      <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e1e1e]">
        <h3 className="text-sm font-semibold text-[#e0e0e0]">{title}</h3>
        {right}
      </div>
      <div className="p-4">{children}</div>
    </div>
  );
}

// ================================================================
// 1. Live Traffic Monitor (WebSocket stream)
// ================================================================

interface TrafficRequest {
  id: number;
  method: string;
  url: string;
  status: number;
  duration_ms: number;
  timestamp: string;
  size_bytes: number;
  preview: string;
}

export function LiveTrafficMonitor() {
  const [requests, setRequests] = useState<TrafficRequest[]>([]);
  const [filter, setFilter] = useState('');
  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  useEffect(() => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${window.location.host}/ws/traffic`);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onerror = () => setConnected(false);
    ws.onmessage = (e) => {
      if (pausedRef.current) return;
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === 'request') {
          setRequests((prev) => {
            const next = [msg, ...prev];
            return next.slice(0, 500);
          });
        }
      } catch {
        /* ignore */
      }
    };
    return () => ws.close();
  }, []);

  const filtered = useMemo(() => {
    if (!filter) return requests;
    const f = filter.toLowerCase();
    return requests.filter(
      (r) =>
        r.url.toLowerCase().includes(f) ||
        r.method.toLowerCase().includes(f) ||
        String(r.status).includes(f),
    );
  }, [requests, filter]);

  return (
    <div className="flex flex-col h-full gap-4">
      <div className="flex items-center gap-3">
        <div
          className={cn(
            'flex items-center gap-2 text-xs px-2 py-1 rounded',
            connected
              ? 'bg-green-500/10 text-green-400 border border-green-500/30'
              : 'bg-red-500/10 text-red-400 border border-red-500/30',
          )}
        >
          <Radio className="w-3 h-3" />
          {connected ? 'Streaming' : 'Disconnected'}
        </div>
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter by URL / method / status…"
          className="flex-1 px-3 py-1.5 bg-[#0e0e0e] border border-[#222] rounded-md text-sm text-[#e0e0e0] placeholder:text-[#555] focus:border-[#a855f7] focus:outline-none"
        />
        <button
          onClick={() => setPaused((p) => !p)}
          className="px-3 py-1.5 bg-[#111] hover:bg-[#1a1a1a] border border-[#222] text-sm text-[#e0e0e0] rounded-md flex items-center gap-2 transition"
        >
          {paused ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
          {paused ? 'Resume' : 'Pause'}
        </button>
        <button
          onClick={() => setRequests([])}
          className="px-3 py-1.5 bg-[#111] hover:bg-[#1a1a1a] border border-[#222] text-sm text-[#e0e0e0] rounded-md flex items-center gap-2 transition"
        >
          <Trash2 className="w-3 h-3" /> Clear
        </button>
        <div className="text-xs text-[#666] ml-auto">
          {filtered.length} / {requests.length}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto custom-scrollbar bg-[#0e0e0e] border border-[#222] rounded-xl">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-[#161616] border-b border-[#222]">
            <tr className="text-left text-[#666] uppercase">
              <th className="px-3 py-2 font-semibold">#</th>
              <th className="px-3 py-2 font-semibold">Method</th>
              <th className="px-3 py-2 font-semibold">URL</th>
              <th className="px-3 py-2 font-semibold">Status</th>
              <th className="px-3 py-2 font-semibold">Size</th>
              <th className="px-3 py-2 font-semibold">Time</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((r) => (
              <tr
                key={r.id}
                className="border-b border-[#1a1a1a] hover:bg-[#151515] transition"
              >
                <td className="px-3 py-1.5 text-[#666]">{r.id}</td>
                <td className="px-3 py-1.5 font-mono text-[#a855f7]">{r.method}</td>
                <td className="px-3 py-1.5 font-mono text-[#d4d4d4] truncate max-w-xl">
                  {r.url}
                </td>
                <td
                  className={cn(
                    'px-3 py-1.5 font-mono',
                    r.status >= 500
                      ? 'text-red-400'
                      : r.status >= 400
                        ? 'text-orange-400'
                        : r.status >= 300
                          ? 'text-yellow-400'
                          : 'text-green-400',
                  )}
                >
                  {r.status || '—'}
                </td>
                <td className="px-3 py-1.5 text-[#8c8c8c]">
                  {r.size_bytes ? `${(r.size_bytes / 1024).toFixed(1)}k` : '—'}
                </td>
                <td className="px-3 py-1.5 text-[#8c8c8c]">
                  {r.duration_ms ? `${r.duration_ms}ms` : '—'}
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td
                  colSpan={6}
                  className="px-3 py-12 text-center text-[#555] italic"
                >
                  {connected
                    ? 'Waiting for requests… browser actions and HTTP tests will show up here in real time.'
                    : 'Not connected to traffic stream.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ================================================================
// 2. Dashboard V2 — dense one-shot overview
// ================================================================

export function DashboardV2() {
  const summaryFetcher = useCallback(() => api.getDashboardSummary(), []);
  const trendFetcher = useCallback(() => api.getSeverityTrend(), []);
  const trafficFetcher = useCallback(() => api.getTrafficStats(), []);
  const { data: summary } = useInterval(summaryFetcher, 3000);
  const { data: trend } = useInterval(trendFetcher, 5000);
  const { data: traffic } = useInterval(trafficFetcher, 4000);

  const sev = summary?.findings?.by_severity || {};
  const critical = sev.CRITICAL || 0;
  const high = sev.HIGH || 0;
  const medium = sev.MEDIUM || 0;
  const low = sev.LOW || 0;

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        <StatCard
          label="Active Agents"
          value={summary?.agents?.running ?? '—'}
          sub={`${summary?.agents?.total ?? 0} total`}
          icon={Cpu}
          color="text-[#a855f7]"
        />
        <StatCard
          label="Findings"
          value={summary?.findings?.total ?? 0}
          sub={`${summary?.findings?.by_status?.confirmed ?? 0} confirmed`}
          icon={Shield}
        />
        <StatCard
          label="Critical"
          value={critical}
          sub={`${high} high · ${medium} med`}
          icon={AlertTriangle}
          color="text-red-400"
        />
        <StatCard
          label="Hosts"
          value={summary?.findings?.hosts_enumerated ?? 0}
          sub={`${summary?.findings?.services_enumerated ?? 0} services`}
          icon={Server}
          color="text-cyan-400"
        />
        <StatCard
          label="Cost"
          value={`$${(summary?.cost?.total_usd ?? 0).toFixed(3)}`}
          sub={`${((summary?.cost?.tokens_input ?? 0) / 1000).toFixed(1)}K in · ${(
            (summary?.cost?.tokens_output ?? 0) / 1000
          ).toFixed(1)}K out`}
          icon={DollarSign}
          color="text-yellow-400"
        />
        <StatCard
          label="Runtime"
          value={formatDuration(summary?.engagement?.runtime_seconds)}
          sub={summary?.engagement?.target?.substring(0, 30) || '—'}
          icon={Activity}
          color="text-green-400"
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Panel title="Severity Distribution">
          <div className="space-y-2">
            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const).map((s) => {
              const n = sev[s] || 0;
              const max = Math.max(
                sev.CRITICAL || 0,
                sev.HIGH || 0,
                sev.MEDIUM || 0,
                sev.LOW || 0,
                sev.INFO || 0,
                1,
              );
              return (
                <div key={s} className="flex items-center gap-3">
                  <div
                    className={cn(
                      'text-xs font-semibold w-20 px-2 py-0.5 rounded border text-center',
                      SEV_COLORS[s],
                    )}
                  >
                    {s}
                  </div>
                  <div className="flex-1 bg-[#0e0e0e] h-6 rounded overflow-hidden">
                    <div
                      className={cn('h-full transition-all', SEV_BG[s])}
                      style={{ width: `${(n / max) * 100}%` }}
                    />
                  </div>
                  <div className="text-sm font-mono text-[#e0e0e0] w-10 text-right">
                    {n}
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>

        <Panel title="Top Spending Agents">
          {summary?.cost?.top_agents?.length ? (
            <div className="space-y-2">
              {summary.cost.top_agents.map((a: any, i: number) => (
                <div
                  key={a.agent_id}
                  className="flex items-center justify-between text-sm"
                >
                  <div className="flex items-center gap-2 text-[#d4d4d4]">
                    <span className="text-xs text-[#666] w-5">#{i + 1}</span>
                    <span className="truncate">{a.name || a.agent_id}</span>
                  </div>
                  <div className="font-mono text-yellow-400">
                    ${a.cost.toFixed(4)}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-sm text-[#555] italic">No cost data yet.</div>
          )}
        </Panel>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Panel title="Recent Activity">
          <div className="space-y-1 max-h-64 overflow-y-auto custom-scrollbar">
            {summary?.recent_activity?.length ? (
              summary.recent_activity.map((a: any, i: number) => (
                <div
                  key={i}
                  className="flex items-center justify-between text-xs font-mono py-1 border-b border-[#1a1a1a]"
                >
                  <span className="text-[#a855f7]">{a.tool}</span>
                  <span
                    className={cn(
                      'px-1.5 rounded text-[10px]',
                      a.status === 'completed'
                        ? 'bg-green-500/10 text-green-400'
                        : a.status === 'error'
                          ? 'bg-red-500/10 text-red-400'
                          : 'bg-yellow-500/10 text-yellow-400',
                    )}
                  >
                    {a.status}
                  </span>
                  <span className="text-[#666]">
                    {a.duration_ms ? `${a.duration_ms}ms` : '—'}
                  </span>
                </div>
              ))
            ) : (
              <div className="text-sm text-[#555] italic">No activity yet.</div>
            )}
          </div>
        </Panel>

        <Panel title="Traffic Stats">
          {traffic ? (
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div className="flex justify-between">
                <span className="text-[#666]">Total</span>
                <span className="font-mono text-[#e0e0e0]">{traffic.total}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#666]">Avg latency</span>
                <span className="font-mono text-[#e0e0e0]">
                  {traffic.avg_latency_ms}ms
                </span>
              </div>
              <div className="col-span-2 pt-2 border-t border-[#222]">
                <div className="text-xs text-[#666] uppercase mb-1">By status</div>
                <div className="flex flex-wrap gap-1">
                  {Object.entries(traffic.by_status || {}).map(([k, v]) => {
                    const code = parseInt(k, 10);
                    return (
                      <span
                        key={k}
                        className={cn(
                          'text-[10px] px-1.5 py-0.5 rounded font-mono border',
                          code >= 500
                            ? 'border-red-500/30 text-red-400'
                            : code >= 400
                              ? 'border-orange-500/30 text-orange-400'
                              : code >= 300
                                ? 'border-yellow-500/30 text-yellow-400'
                                : 'border-green-500/30 text-green-400',
                        )}
                      >
                        {k} · {v as number}
                      </span>
                    );
                  })}
                </div>
              </div>
            </div>
          ) : (
            <div className="text-sm text-[#555] italic">No traffic captured.</div>
          )}
        </Panel>
      </div>

      <Panel title="Findings Over Time (last 24h)">
        {trend?.series?.length ? (
          <div className="flex items-end gap-[2px] h-24">
            {[...trend.series].reverse().map((b, i) => {
              const total = b.CRITICAL + b.HIGH + b.MEDIUM + b.LOW + b.INFO;
              const max = 10;
              return (
                <div
                  key={i}
                  className="flex-1 flex flex-col-reverse justify-start gap-[1px] rounded-sm overflow-hidden"
                  style={{ minHeight: 4 }}
                  title={`${b.hours_ago}h ago — C:${b.CRITICAL} H:${b.HIGH} M:${b.MEDIUM}`}
                >
                  {b.CRITICAL > 0 && (
                    <div
                      className="bg-red-500"
                      style={{ height: `${(b.CRITICAL / max) * 100}%`, minHeight: 1 }}
                    />
                  )}
                  {b.HIGH > 0 && (
                    <div
                      className="bg-orange-500"
                      style={{ height: `${(b.HIGH / max) * 100}%`, minHeight: 1 }}
                    />
                  )}
                  {b.MEDIUM > 0 && (
                    <div
                      className="bg-yellow-500"
                      style={{ height: `${(b.MEDIUM / max) * 100}%`, minHeight: 1 }}
                    />
                  )}
                  {b.LOW > 0 && (
                    <div
                      className="bg-green-500"
                      style={{ height: `${(b.LOW / max) * 100}%`, minHeight: 1 }}
                    />
                  )}
                  {total === 0 && (
                    <div className="bg-[#1a1a1a]" style={{ height: 2 }} />
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <div className="text-sm text-[#555] italic">No findings bucketed yet.</div>
        )}
      </Panel>
    </div>
  );
}

function formatDuration(sec?: number): string {
  if (!sec || sec < 0) return '—';
  if (sec < 60) return `${Math.round(sec)}s`;
  if (sec < 3600) return `${Math.round(sec / 60)}m`;
  return `${Math.floor(sec / 3600)}h ${Math.round((sec % 3600) / 60)}m`;
}

// ================================================================
// 3. Engagement state viewer
// ================================================================

export function EngagementStateView() {
  const fetcher = useCallback(() => api.getEngagementState(), []);
  const { data } = useInterval(fetcher, 3000);
  const [tab, setTab] = useState<'hosts' | 'services' | 'creds' | 'findings' | 'notes'>('findings');

  if (!data) {
    return (
      <div className="text-center py-16 text-[#555]">
        <Database className="w-12 h-12 mx-auto mb-3 text-[#333]" />
        No engagement state yet. Start a scan to populate hosts / services / credentials.
      </div>
    );
  }

  const hosts = Object.values(data.hosts || {}) as any[];
  const services = data.services || [];
  const creds = data.credentials || [];
  const findings = Object.values(data.findings || {}) as any[];
  const notes = data.notes || [];

  return (
    <div className="flex flex-col h-full gap-4">
      <div className="flex gap-2">
        {[
          ['findings', `Findings (${findings.length})`],
          ['hosts', `Hosts (${hosts.length})`],
          ['services', `Services (${services.length})`],
          ['creds', `Credentials (${creds.length})`],
          ['notes', `Notes (${notes.length})`],
        ].map(([key, label]) => (
          <button
            key={key}
            onClick={() => setTab(key as any)}
            className={cn(
              'px-3 py-1.5 rounded text-sm transition',
              tab === key
                ? 'bg-[#a855f7] text-white'
                : 'bg-[#111] text-[#8c8c8c] hover:bg-[#1a1a1a]',
            )}
          >
            {label}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto custom-scrollbar">
        {tab === 'findings' && <FindingsTable findings={findings} />}
        {tab === 'hosts' && <HostsList items={hosts} />}
        {tab === 'services' && <ServicesList items={services} />}
        {tab === 'creds' && <CredsList items={creds} />}
        {tab === 'notes' && (
          <div className="bg-[#111] border border-[#222] rounded-xl p-4 space-y-2">
            {notes.length === 0 ? (
              <div className="text-[#555] italic">No notes recorded.</div>
            ) : (
              notes.map((n: string, i: number) => (
                <div
                  key={i}
                  className="text-sm text-[#d4d4d4] border-b border-[#1a1a1a] pb-2 last:border-0"
                >
                  {n}
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function FindingsTable({ findings }: { findings: any[] }) {
  const [open, setOpen] = useState<string | null>(null);
  return (
    <div className="bg-[#111] border border-[#222] rounded-xl overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-[#161616] border-b border-[#222]">
          <tr className="text-left text-xs text-[#666] uppercase">
            <th className="px-3 py-2"></th>
            <th className="px-3 py-2">Severity</th>
            <th className="px-3 py-2">Title</th>
            <th className="px-3 py-2">Type</th>
            <th className="px-3 py-2">Endpoint</th>
            <th className="px-3 py-2">Status</th>
            <th className="px-3 py-2">Conf.</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => {
            const sev = (f.severity || 'UNKNOWN').toUpperCase();
            return (
              <>
                <tr
                  key={f.id}
                  className="border-b border-[#1a1a1a] hover:bg-[#151515] cursor-pointer"
                  onClick={() => setOpen(open === f.id ? null : f.id)}
                >
                  <td className="px-3 py-2">
                    {open === f.id ? (
                      <ChevronDown className="w-3 h-3 text-[#666]" />
                    ) : (
                      <ChevronRight className="w-3 h-3 text-[#666]" />
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <span
                      className={cn(
                        'text-[10px] px-2 py-0.5 rounded border',
                        SEV_COLORS[sev] || SEV_COLORS.INFO,
                      )}
                    >
                      {sev}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-[#e0e0e0]">{f.title}</td>
                  <td className="px-3 py-2 font-mono text-xs text-[#a855f7]">
                    {f.vuln_type || '—'}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs text-[#8c8c8c] truncate max-w-xs">
                    {f.endpoint || '—'}
                  </td>
                  <td className="px-3 py-2 text-xs">
                    <span
                      className={cn(
                        'px-1.5 py-0.5 rounded',
                        f.status === 'confirmed'
                          ? 'bg-green-500/10 text-green-400'
                          : f.status === 'false_positive'
                            ? 'bg-red-500/10 text-red-400'
                            : 'bg-yellow-500/10 text-yellow-400',
                      )}
                    >
                      {f.status}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-xs text-[#8c8c8c]">
                    {typeof f.confidence === 'number'
                      ? f.confidence.toFixed(2)
                      : '—'}
                  </td>
                </tr>
                {open === f.id && (
                  <tr className="bg-[#0d0d0d]">
                    <td colSpan={7} className="px-6 py-3">
                      <div className="text-xs space-y-2">
                        <div>
                          <span className="text-[#666]">ID:</span>{' '}
                          <span className="font-mono">{f.id}</span>
                        </div>
                        {f.description && (
                          <div>
                            <span className="text-[#666]">Description:</span>{' '}
                            <span className="text-[#d4d4d4]">
                              {f.description}
                            </span>
                          </div>
                        )}
                        {f.evidence && f.evidence.length > 0 && (
                          <div>
                            <span className="text-[#666]">Evidence:</span>
                            <pre className="mt-1 p-2 bg-black rounded text-[11px] text-green-300 overflow-x-auto custom-scrollbar">
                              {JSON.stringify(f.evidence, null, 2)}
                            </pre>
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </>
            );
          })}
          {findings.length === 0 && (
            <tr>
              <td colSpan={7} className="px-3 py-12 text-center text-[#555]">
                No findings yet.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function HostsList({ items }: { items: any[] }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
      {items.map((h, i) => (
        <div
          key={i}
          className="bg-[#111] border border-[#222] rounded-xl p-3 text-sm"
        >
          <div className="flex items-center justify-between">
            <span className="font-mono text-[#a855f7]">
              {h.ip || h.hostname || 'unknown'}
            </span>
            <span className="text-xs text-[#666]">{h.os || ''}</span>
          </div>
          {h.notes && (
            <div className="mt-2 text-xs text-[#8c8c8c]">{h.notes}</div>
          )}
        </div>
      ))}
      {items.length === 0 && (
        <div className="col-span-full text-center py-12 text-[#555]">
          No hosts enumerated.
        </div>
      )}
    </div>
  );
}

function ServicesList({ items }: { items: any[] }) {
  return (
    <div className="bg-[#111] border border-[#222] rounded-xl overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-[#161616] border-b border-[#222] text-xs text-[#666] uppercase">
          <tr className="text-left">
            <th className="px-3 py-2">Host</th>
            <th className="px-3 py-2">Port</th>
            <th className="px-3 py-2">Protocol</th>
            <th className="px-3 py-2">Service</th>
            <th className="px-3 py-2">Version</th>
          </tr>
        </thead>
        <tbody>
          {items.map((s, i) => (
            <tr
              key={i}
              className="border-b border-[#1a1a1a] hover:bg-[#151515]"
            >
              <td className="px-3 py-1.5 font-mono text-[#a855f7]">{s.host}</td>
              <td className="px-3 py-1.5 font-mono">{s.port}</td>
              <td className="px-3 py-1.5">{s.protocol || 'tcp'}</td>
              <td className="px-3 py-1.5">{s.service || '—'}</td>
              <td className="px-3 py-1.5 text-xs text-[#8c8c8c]">
                {s.version || '—'}
              </td>
            </tr>
          ))}
          {items.length === 0 && (
            <tr>
              <td colSpan={5} className="px-3 py-12 text-center text-[#555]">
                No services enumerated.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function CredsList({ items }: { items: any[] }) {
  return (
    <div className="bg-[#111] border border-[#222] rounded-xl overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-[#161616] border-b border-[#222] text-xs text-[#666] uppercase">
          <tr className="text-left">
            <th className="px-3 py-2">Type</th>
            <th className="px-3 py-2">Username</th>
            <th className="px-3 py-2">Secret</th>
            <th className="px-3 py-2">Source</th>
          </tr>
        </thead>
        <tbody>
          {items.map((c, i) => (
            <tr
              key={i}
              className="border-b border-[#1a1a1a] hover:bg-[#151515]"
            >
              <td className="px-3 py-1.5">{c.type || '—'}</td>
              <td className="px-3 py-1.5 font-mono text-[#a855f7]">
                {c.username || '—'}
              </td>
              <td className="px-3 py-1.5 font-mono text-xs text-[#8c8c8c] truncate max-w-md">
                {c.password ? '••••••••' : c.secret ? '•••••' : '—'}
              </td>
              <td className="px-3 py-1.5 text-xs text-[#8c8c8c]">
                {c.source || '—'}
              </td>
            </tr>
          ))}
          {items.length === 0 && (
            <tr>
              <td colSpan={4} className="px-3 py-12 text-center text-[#555]">
                No credentials captured.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

// ================================================================
// 4. Approvals queue
// ================================================================

export function ApprovalsQueue() {
  const fetcher = useCallback(() => api.getApprovals(), []);
  const { data, refresh } = useInterval(fetcher, 2000);

  const decide = async (id: string, approved: boolean) => {
    const reason = approved
      ? 'Approved by operator'
      : prompt('Reason for denial?') || 'Denied by operator';
    await api.decideApproval(id, approved, reason);
    refresh();
  };

  const pending = data?.pending || [];

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">
          Pending approvals{' '}
          <span className="text-sm text-[#666]">({pending.length})</span>
        </h2>
        <button
          onClick={refresh}
          className="text-xs px-2 py-1 bg-[#111] border border-[#222] hover:bg-[#1a1a1a] rounded text-[#8c8c8c]"
        >
          Refresh
        </button>
      </div>

      {pending.length === 0 ? (
        <div className="text-center py-16 text-[#555] bg-[#111] border border-[#222] rounded-xl">
          <Check className="w-12 h-12 mx-auto mb-3 text-[#333]" />
          No pending approval requests.
        </div>
      ) : (
        <div className="space-y-3">
          {pending.map((req: any) => (
            <div
              key={req.id}
              className="bg-[#111] border border-[#222] rounded-xl p-4 space-y-3"
            >
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span
                      className={cn(
                        'text-[10px] px-2 py-0.5 rounded border font-semibold',
                        req.risk_level === 'critical'
                          ? SEV_COLORS.CRITICAL
                          : req.risk_level === 'high'
                            ? SEV_COLORS.HIGH
                            : SEV_COLORS.MEDIUM,
                      )}
                    >
                      {req.risk_level?.toUpperCase() || 'MEDIUM'}
                    </span>
                    <span className="text-sm font-semibold text-[#e0e0e0]">
                      {req.action}
                    </span>
                    <span className="text-xs text-[#666]">{req.agent_id}</span>
                  </div>
                  <div className="mt-2 text-sm text-[#d4d4d4]">
                    {req.rationale}
                  </div>
                  {req.details && Object.keys(req.details).length > 0 && (
                    <pre className="mt-2 p-2 bg-black rounded text-[11px] text-green-300 overflow-x-auto">
                      {JSON.stringify(req.details, null, 2)}
                    </pre>
                  )}
                </div>
              </div>
              <div className="flex gap-2 justify-end border-t border-[#1a1a1a] pt-3">
                <button
                  onClick={() => decide(req.id, false)}
                  className="px-3 py-1.5 text-sm bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-400 rounded transition"
                >
                  <X className="w-3 h-3 inline mr-1" /> Deny
                </button>
                <button
                  onClick={() => decide(req.id, true)}
                  className="px-3 py-1.5 text-sm bg-green-500/10 hover:bg-green-500/20 border border-green-500/30 text-green-400 rounded transition"
                >
                  <Check className="w-3 h-3 inline mr-1" /> Approve
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ================================================================
// 5. Cost breakdown
// ================================================================

export function CostBreakdown() {
  const fetcher = useCallback(() => api.getCostBreakdown(), []);
  const { data } = useInterval(fetcher, 5000);

  const totals = data?.totals || {
    input_tokens: 0,
    output_tokens: 0,
    cached_tokens: 0,
    cost: 0,
  };
  const agents = data?.by_agent || [];

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-4 gap-3">
        <StatCard
          label="Total Cost"
          value={`$${(totals.cost || 0).toFixed(4)}`}
          icon={DollarSign}
          color="text-yellow-400"
        />
        <StatCard
          label="Input Tokens"
          value={formatBigNum(totals.input_tokens)}
          icon={Upload}
          color="text-blue-400"
        />
        <StatCard
          label="Output Tokens"
          value={formatBigNum(totals.output_tokens)}
          icon={Download}
          color="text-green-400"
        />
        <StatCard
          label="Cached"
          value={formatBigNum(totals.cached_tokens)}
          icon={HardDrive}
          color="text-cyan-400"
        />
      </div>

      <Panel title={`Per-agent breakdown (${agents.length})`}>
        {agents.length === 0 ? (
          <div className="text-sm text-[#555] italic py-4">
            No LLM calls recorded yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-xs text-[#666] uppercase">
                <tr className="text-left">
                  <th className="px-3 py-2">Agent</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2 text-right">Input</th>
                  <th className="px-3 py-2 text-right">Output</th>
                  <th className="px-3 py-2 text-right">Cached</th>
                  <th className="px-3 py-2 text-right">Cost</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((a: any) => (
                  <tr
                    key={a.agent_id}
                    className="border-t border-[#1a1a1a] hover:bg-[#151515]"
                  >
                    <td className="px-3 py-2 font-medium text-[#e0e0e0]">
                      {a.agent_name || a.agent_id}
                    </td>
                    <td className="px-3 py-2 text-xs">{a.status || '—'}</td>
                    <td className="px-3 py-2 text-right font-mono">
                      {formatBigNum(a.input_tokens)}
                    </td>
                    <td className="px-3 py-2 text-right font-mono">
                      {formatBigNum(a.output_tokens)}
                    </td>
                    <td className="px-3 py-2 text-right font-mono">
                      {formatBigNum(a.cached_tokens)}
                    </td>
                    <td className="px-3 py-2 text-right font-mono text-yellow-400">
                      ${(a.cost || 0).toFixed(4)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}

function formatBigNum(n?: number): string {
  if (!n) return '0';
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

// ================================================================
// 6. Checkpoints manager
// ================================================================

export function CheckpointsPage() {
  const fetcher = useCallback(() => api.getCheckpoints(), []);
  const { data, refresh } = useInterval(fetcher, 10000);

  const [busy, setBusy] = useState<string | null>(null);

  const save = async () => {
    const id = prompt('Session name to checkpoint:', 'default') || 'default';
    setBusy('save');
    try {
      await api.saveCheckpoint(id);
      refresh();
    } finally {
      setBusy(null);
    }
  };

  const restore = async (id: string) => {
    if (!confirm(`Restore session ${id}?`)) return;
    setBusy(id);
    try {
      const r = await api.restoreCheckpoint(id);
      alert(r?.success ? `Restored: ${JSON.stringify(r.restored || {})}` : `Failed: ${r?.error}`);
      refresh();
    } finally {
      setBusy(null);
    }
  };

  const sessions = data?.sessions || [];

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Scan checkpoints</h2>
        <button
          onClick={save}
          disabled={busy === 'save'}
          className="text-sm px-3 py-1.5 bg-[#a855f7] hover:bg-[#9333ea] text-white rounded flex items-center gap-2 disabled:opacity-50"
        >
          <Upload className="w-3 h-3" />
          Save checkpoint
        </button>
      </div>

      {sessions.length === 0 ? (
        <div className="text-center py-16 text-[#555] bg-[#111] border border-[#222] rounded-xl">
          <History className="w-12 h-12 mx-auto mb-3 text-[#333]" />
          No checkpoints recorded yet. They auto-save every 5 minutes during scans.
        </div>
      ) : (
        <div className="space-y-2">
          {sessions.map((s: any) => (
            <div
              key={s.session_id}
              className="bg-[#111] border border-[#222] rounded-xl p-3 flex items-center justify-between"
            >
              <div>
                <div className="font-semibold text-[#e0e0e0]">
                  {s.session_id}
                </div>
                <div className="text-xs text-[#666] mt-1">
                  {s.checkpoints} snapshots · latest {s.latest} ·{' '}
                  {(s.latest_size / 1024).toFixed(1)}KB
                </div>
              </div>
              <button
                onClick={() => restore(s.session_id)}
                disabled={busy === s.session_id}
                className="text-sm px-3 py-1.5 bg-[#1a1a1a] hover:bg-[#222] border border-[#333] text-[#e0e0e0] rounded flex items-center gap-2 disabled:opacity-50"
              >
                <Download className="w-3 h-3" />
                Restore
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ================================================================
// 7. LLM debug — inspect an agent's last 30 messages
// ================================================================

export function LlmDebugPage() {
  const agentsFetcher = useCallback(() => api.getAgents(), []);
  const { data: agentsData } = useInterval(agentsFetcher, 5000);
  const [selectedId, setSelectedId] = useState<string>('');

  const debugFetcher = useCallback(
    () => (selectedId ? api.getLlmDebug(selectedId) : Promise.resolve(null)),
    [selectedId],
  );
  const { data: debug } = useInterval(debugFetcher, 3000, !!selectedId);

  const agents = (agentsData as any)?.agents || [];

  return (
    <div className="flex flex-col gap-4 h-full">
      <div className="flex items-center gap-2">
        <select
          value={selectedId}
          onChange={(e) => setSelectedId(e.target.value)}
          className="bg-[#111] border border-[#222] text-[#e0e0e0] text-sm px-3 py-2 rounded"
        >
          <option value="">Select an agent…</option>
          {agents.map((a: any) => (
            <option key={a.agent_id || a.id} value={a.agent_id || a.id}>
              {a.name || a.agent_name || 'unnamed'} ({a.status})
            </option>
          ))}
        </select>
        {debug && (
          <div className="text-xs text-[#8c8c8c] ml-auto space-x-4">
            <span>iter: {debug.iteration}</span>
            <span>waiting: {debug.waiting ? 'yes' : 'no'}</span>
            <span>llm_failed: {debug.llm_failed ? 'yes' : 'no'}</span>
            <span>fail_streak: {debug.consecutive_llm_failures}</span>
          </div>
        )}
      </div>

      <div className="flex-1 overflow-y-auto custom-scrollbar bg-[#111] border border-[#222] rounded-xl p-3 space-y-2">
        {!selectedId ? (
          <div className="text-center py-16 text-[#555]">
            <Eye className="w-12 h-12 mx-auto mb-3 text-[#333]" />
            Select an agent to see its last 30 messages.
          </div>
        ) : debug?.messages_preview?.length ? (
          debug.messages_preview.map((m: any, i: number) => (
            <div
              key={i}
              className="bg-[#0d0d0d] border border-[#1a1a1a] rounded p-2 text-xs"
            >
              <div className="flex justify-between mb-1">
                <span
                  className={cn(
                    'font-semibold uppercase',
                    m.role === 'user'
                      ? 'text-cyan-400'
                      : m.role === 'assistant'
                        ? 'text-[#a855f7]'
                        : m.role === 'system'
                          ? 'text-yellow-400'
                          : 'text-[#666]',
                  )}
                >
                  {m.role}
                </span>
                {m.has_thinking && (
                  <span className="text-[10px] text-[#666]">[has thinking]</span>
                )}
              </div>
              <pre className="whitespace-pre-wrap text-[#d4d4d4] font-mono break-words">
                {m.content_preview}
              </pre>
            </div>
          ))
        ) : (
          <div className="text-[#555] italic p-3">No messages yet.</div>
        )}
      </div>
    </div>
  );
}

// ================================================================
// 8. Scan control (pause/resume)
// ================================================================

export function ScanControlBar() {
  const [status, setStatus] = useState<string>('idle');
  const pause = async () => {
    const r = await api.pauseScan();
    setStatus(r?.status || 'unknown');
  };
  const resume = async () => {
    const msg = prompt('Optional guidance to inject?') || '';
    const r = await api.resumeScan(undefined, msg);
    setStatus(r?.status || 'unknown');
  };

  return (
    <div className="flex items-center gap-2 bg-[#111] border border-[#222] rounded-xl px-4 py-2">
      <Zap className="w-4 h-4 text-[#a855f7]" />
      <span className="text-sm text-[#8c8c8c]">Scan control:</span>
      <button
        onClick={pause}
        className="px-2 py-1 text-xs bg-[#1a1a1a] hover:bg-[#222] border border-[#333] text-[#e0e0e0] rounded flex items-center gap-1"
      >
        <Pause className="w-3 h-3" /> Pause
      </button>
      <button
        onClick={resume}
        className="px-2 py-1 text-xs bg-[#a855f7] hover:bg-[#9333ea] text-white rounded flex items-center gap-1"
      >
        <Play className="w-3 h-3" /> Resume + inject message
      </button>
      {status !== 'idle' && (
        <span className="text-xs text-[#8c8c8c] ml-auto">Status: {status}</span>
      )}
    </div>
  );
}
