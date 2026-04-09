import React, { useState, useEffect, useCallback, useRef } from 'react';
import { api, type ScanStatus, type Vulnerability, type AgentInfo, type AgentEventsResponse, type ToolEvent, type ReconResults, type AttackGraphResponse, type TodosResponse, type TodoItem, type ScreenshotCard, type ScreenshotsResponse, type MitreHit, type MitreResponse, type HttpLogEntry, type HttpLogsResponse, type RoiScore, type RoiScoresResponse } from './api';
import { 
  LayoutDashboard, 
  ShieldAlert, 
  ListTodo, 
  FileCheck, 
  Database, 
  Settings, 
  Plus, 
  X, 
  Check, 
  ChevronRight, 
  ChevronDown,
  ChevronUp,
  Search,
  Bell,
  User,
  Target,
  Activity,
  AlertTriangle,
  Terminal,
  Crosshair,
  Key,
  ClipboardCheck,
  Info,
  FileText,
  Cpu,
  Zap,
  Eye,
  Server,
  ClipboardList,
  Map,
  TerminalSquare,
  Network,
  Globe,
  Code,
  AtSign,
  Globe2,
  Bug,
  Lock,
  Camera,
  Grid3X3,
  Layers,
  ArrowUpDown,
  ExternalLink,
  Wifi,
  WifiOff,
  Shield,
  BarChart3,
  Send,
  Hash,
  Clock
} from 'lucide-react';
import { ResponsiveContainer, Tooltip as RechartsTooltip } from 'recharts';
import ReactFlow, { Background, Controls, type Node, type Edge, Position, MarkerType } from 'reactflow';
import 'reactflow/dist/style.css';
import { cn } from './lib/utils';

// --- Types ---
type ScanMode = 'standard' | 'full' | 'infra' | 'smartcontract';

interface Credential {
  username: string;
  password?: string;
  description?: string;
}

interface RequestHeader {
  name: string;
  value: string;
}

interface TestFormData {
  taskName: string;
  testTarget: string;
  note: string;
  autoRiskFilter: boolean;
  scanMode: ScanMode;
  businessContext: string;
  testingScope: string;
  criticalAssets: string;
  knownIssues: string;
  complianceRequirements: string;
  credentials: Credential[];
  requestHeaders: RequestHeader[];
}

// --- Data polling hook ---
function useApiPolling<T>(fetcher: () => Promise<T | null>, intervalMs = 3000) {
  const [data, setData] = useState<T | null>(null);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    let active = true;
    const poll = async () => {
      const result = await fetcher();
      if (active) {
        setData(result);
        setConnected(result !== null);
      }
    };
    poll();
    const id = setInterval(poll, intervalMs);
    return () => { active = false; clearInterval(id); };
  }, [fetcher, intervalMs]);

  return { data, connected };
}

// --- Main App Component ---
export default function App() {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [activeTab, setActiveTab] = useState('Tests');

  const statusFetcher = useCallback(() => api.getStatus(), []);
  const vulnFetcher = useCallback(() => api.getVulnerabilities(), []);
  const agentsFetcher = useCallback(() => api.getAgents(), []);
  const llmStatsFetcher = useCallback(() => api.getLlmStats(), []);

  const { data: scanStatus, connected } = useApiPolling(statusFetcher);
  const { data: liveVulns } = useApiPolling(vulnFetcher);
  const { data: liveAgents } = useApiPolling(agentsFetcher);
  const { data: llmStats } = useApiPolling(llmStatsFetcher, 5000);

  return (
    <div className="flex h-screen w-full bg-[#0a0a0a] text-[#e0e0e0] font-sans overflow-hidden selection:bg-[#a855f7]/30">
      <Sidebar onNewTask={() => setIsModalOpen(true)} activeTab={activeTab} setActiveTab={setActiveTab} />

      <div className="flex-1 flex flex-col min-w-0">
        <Header scanStatus={scanStatus} connected={connected} llmStats={llmStats} />
        <main className="flex-1 overflow-y-auto p-6 lg:p-8 custom-scrollbar">
          {activeTab === 'Tests' ? <Dashboard liveAgents={liveAgents} liveVulns={liveVulns} /> : activeTab === 'Agent Terminal' ? <AgentTerminal /> : activeTab === 'Target Overview' ? <TargetOverview scanStatus={scanStatus} /> : activeTab === 'Vulnerabilities' ? <Vulnerabilities liveVulns={liveVulns} /> : activeTab === 'Attack Surface' ? <AttackSurface /> : activeTab === 'Screenshots' ? <ScreenshotsGallery /> : activeTab === 'MITRE ATT&CK' ? <MitreHeatmap /> : activeTab === 'HTTP Log' ? <HttpRequestLog /> : activeTab === 'AI Chat' ? <AiChat /> : activeTab === 'Compliance' ? <CompliancePage /> : activeTab === 'History' ? <HistoryPage /> : activeTab === 'Replay' ? <ReplayPage /> : activeTab === 'Settings' ? <SettingsPage /> : <div className="text-[#8c8c8c] flex items-center justify-center h-full">Section under development</div>}
        </main>
      </div>

      {isModalOpen && <CreateTestModal onClose={() => setIsModalOpen(false)} />}
    </div>
  );
}

// --- Sidebar Component ---
function Sidebar({ onNewTask, activeTab, setActiveTab }: { onNewTask: () => void, activeTab: string, setActiveTab: (t: string) => void }) {
  const navItems = [
    { icon: ClipboardList, label: 'Tests' },
    { icon: TerminalSquare, label: 'Agent Terminal' },
    { icon: Server, label: 'Target Overview' },
    { icon: Map, label: 'Attack Surface' },
    { icon: Bug, label: 'Vulnerabilities' },
    { icon: Camera, label: 'Screenshots' },
    { icon: Grid3X3, label: 'MITRE ATT&CK' },
    { icon: Layers, label: 'HTTP Log' },
    { icon: AtSign, label: 'AI Chat' },
    { icon: Clock, label: 'History' },
    { icon: Activity, label: 'Replay' },
    { icon: Settings, label: 'Settings' },
  ];

  return (
    <aside className="w-64 flex-shrink-0 bg-[#111111] border-r border-[#222] flex flex-col">
      <div className="h-16 flex items-center px-6 border-b border-[#222] flex-shrink-0">
        <div className="flex items-center gap-2 text-[#f2f2f2] font-bold text-xl tracking-wider">
          <Terminal className="w-6 h-6 text-[#a855f7]" />
          <span>ZIRO</span>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto custom-scrollbar flex flex-col">
        <nav className="px-3 py-4 space-y-1">
          {navItems.map((item, idx) => (
            <button
              key={idx}
              onClick={() => setActiveTab(item.label)}
              className={cn(
                "w-full flex items-center justify-between px-3 py-2.5 rounded-md text-sm font-medium transition-colors duration-200 text-left",
                activeTab === item.label 
                  ? "bg-[#1a1a1a] text-[#a855f7] border-l-2 border-[#a855f7]" 
                  : "text-[#8c8c8c] hover:bg-[#1a1a1a] hover:text-[#d4d4d4] border-l-2 border-transparent"
              )}
            >
              <div className="flex items-center gap-3 flex-1 min-w-0 pr-2">
                <item.icon className="w-4 h-4 flex-shrink-0" />
                <span className="leading-snug whitespace-normal">{item.label}</span>
              </div>
              {item.badge && (
                <span className={cn(
                  "text-[10px] px-1.5 py-0.5 rounded-full border flex-shrink-0",
                  activeTab === item.label
                    ? "border-[#a855f7]/30 bg-[#a855f7]/10 text-[#a855f7]"
                    : "border-[#333] bg-[#222] text-[#8c8c8c]"
                )}>
                  {item.badge}
                </span>
              )}
            </button>
          ))}
        </nav>

        <div className="px-3 pb-4 flex-1">
          <div className="text-xs font-semibold text-[#666] uppercase tracking-wider mb-3 px-3">Test History</div>
          <div className="space-y-2">
            <div className="text-center py-8 text-[#666] text-xs">No completed tests</div>
          </div>
        </div>
      </div>

      <div className="p-4 border-t border-[#222] flex flex-col gap-4 flex-shrink-0">
        <button 
          onClick={onNewTask}
          className="w-full flex items-center justify-center gap-2 bg-[#a855f7] hover:bg-[#c084fc] text-white py-2.5 px-4 rounded-md font-medium transition-all duration-200 shadow-[0_0_15px_rgba(168,85,247,0.2)] hover:shadow-[0_0_20px_rgba(168,85,247,0.4)]"
        >
          <span>New Test</span>
          <Plus className="w-4 h-4" />
        </button>

        <div className="flex items-center gap-3 px-2">
          <div className="w-8 h-8 rounded-full bg-[#222] flex items-center justify-center text-[#8c8c8c]">
            <User className="w-4 h-4" />
          </div>
          <div className="flex flex-col text-left">
            <span className="text-sm font-medium text-[#d4d4d4]">Ziro Agent</span>
            <span className="text-xs text-[#666]">v1.0.3</span>
          </div>
        </div>
      </div>
    </aside>
  );
}

// --- Header Component ---
function Header({ scanStatus, connected, llmStats }: { scanStatus?: ScanStatus | null, connected?: boolean, llmStats?: any }) {
  const target = scanStatus?.targets?.[0]?.original ?? '—';
  const sc = scanStatus?.severity_counts ?? {};

  const totalTokens = llmStats?.total_tokens ?? 0;
  const cost = llmStats?.total?.cost ?? 0;
  const requests = llmStats?.total?.requests ?? 0;

  const formatTokens = (n: number) => {
    if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
    if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
    return String(n);
  };

  return (
    <header className="h-16 flex-shrink-0 bg-[#111111] border-b border-[#222] flex items-center justify-between px-6">
      <div className="flex items-center gap-2 text-sm text-[#8c8c8c]">
        <Target className="w-4 h-4" />
        <span>Target:</span>
        <span className="text-[#a855f7] font-medium">{target}</span>
        {connected && <span className="w-2 h-2 rounded-full bg-green-500 ml-1" title="API connected"></span>}
        <span className="mx-2 text-[#444]">|</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500"></span> Critical: {sc.critical ?? 0}</span>
        <span className="flex items-center gap-1 ml-3"><span className="w-2 h-2 rounded-full bg-orange-500"></span> High: {sc.high ?? 0}</span>
        <span className="flex items-center gap-1 ml-3"><span className="w-2 h-2 rounded-full bg-yellow-500"></span> Medium: {sc.medium ?? 0}</span>
        <span className="flex items-center gap-1 ml-3"><span className="w-2 h-2 rounded-full bg-blue-500"></span> Low: {sc.low ?? 0}</span>
      </div>

      <div className="flex items-center gap-3">
        {/* Token/Cost counter */}
        {(totalTokens > 0 || cost > 0) && (
          <div className="flex items-center gap-3 text-xs text-[#8c8c8c] bg-[#0a0a0a] border border-[#222] rounded-lg px-3 py-1.5">
            <div className="flex items-center gap-1.5" title="Total tokens used">
              <Hash className="w-3 h-3 text-[#a855f7]" />
              <span className="text-[#d4d4d4] font-mono">{formatTokens(totalTokens)}</span>
              <span className="text-[#555]">tokens</span>
            </div>
            <span className="text-[#333]">|</span>
            <div className="flex items-center gap-1.5" title="Estimated cost">
              <span className="text-green-400 font-mono">${cost.toFixed(2)}</span>
            </div>
            <span className="text-[#333]">|</span>
            <div className="flex items-center gap-1.5" title="API requests">
              <Send className="w-3 h-3 text-blue-400" />
              <span className="font-mono">{requests}</span>
            </div>
          </div>
        )}

        <div className="relative group">
          <button className="flex items-center gap-2 bg-[#1a1a1a] hover:bg-[#222] border border-[#333] px-3 py-1.5 rounded text-sm text-[#d4d4d4] transition-colors">
            <FileText className="w-3.5 h-3.5" />
            Export
            <ChevronDown className="w-3 h-3" />
          </button>
          <div className="absolute right-0 top-full mt-1 bg-[#1a1a1a] border border-[#333] rounded-lg shadow-xl hidden group-hover:block z-50 w-44">
            <button onClick={() => window.open('/api/report?format=download', '_blank')} className="w-full text-left px-3 py-2 text-xs text-[#d4d4d4] hover:bg-[#222] flex items-center gap-2 rounded-t-lg">
              <FileText className="w-3 h-3" /> HTML Report
            </button>
            <button onClick={() => window.open('/api/report/markdown', '_blank')} className="w-full text-left px-3 py-2 text-xs text-[#d4d4d4] hover:bg-[#222] flex items-center gap-2">
              <Code className="w-3 h-3" /> Markdown
            </button>
            <button onClick={() => window.open('/api/report/json', '_blank')} className="w-full text-left px-3 py-2 text-xs text-[#d4d4d4] hover:bg-[#222] flex items-center gap-2">
              <Database className="w-3 h-3" /> JSON
            </button>
            <button onClick={() => window.open('/api/evidence/download', '_blank')} className="w-full text-left px-3 py-2 text-xs text-[#d4d4d4] hover:bg-[#222] flex items-center gap-2 border-t border-[#333]">
              <Shield className="w-3 h-3" /> Evidence ZIP
            </button>
            <button onClick={() => api.sendTelegram()} className="w-full text-left px-3 py-2 text-xs text-[#d4d4d4] hover:bg-[#222] flex items-center gap-2 rounded-b-lg border-t border-[#333]">
              <Send className="w-3 h-3" /> Send to Telegram
            </button>
          </div>
        </div>
      </div>
    </header>
  );
}

// --- Polar Area Chart Component ---
function PolarAreaChart({ data }: { data: { name: string, value: number, color: string }[] }) {
  const size = 300;
  const cx = size / 2;
  const cy = size / 2;
  const maxRadius = (size / 2) - 10;

  const maxValue = Math.max(...data.map(d => d.value), 1);
  const gridCircles = [0.25, 0.5, 0.75, 1];
  const gridLines = 8;

  return (
    <svg width="100%" height="100%" viewBox={`0 0 ${size} ${size}`} className="overflow-visible">
      {/* Slices (Drawn first so grid is on top) */}
      {data.map((d, i) => {
        if (d.value === 0) return null;
        const sliceAngle = 360 / data.length;
        const startAngle = i * sliceAngle - 90;
        const endAngle = (i + 1) * sliceAngle - 90;
        const radius = (d.value / maxValue) * maxRadius;

        const startRad = (startAngle * Math.PI) / 180;
        const endRad = (endAngle * Math.PI) / 180;

        const x1 = cx + radius * Math.cos(startRad);
        const y1 = cy + radius * Math.sin(startRad);
        const x2 = cx + radius * Math.cos(endRad);
        const y2 = cy + radius * Math.sin(endRad);

        const largeArcFlag = sliceAngle > 180 ? 1 : 0;

        const pathData = [
          `M ${cx} ${cy}`,
          `L ${x1} ${y1}`,
          `A ${radius} ${radius} 0 ${largeArcFlag} 1 ${x2} ${y2}`,
          'Z'
        ].join(' ');

        return (
          <g key={i} className="group cursor-pointer">
            <path
              d={pathData}
              fill={d.color}
              fillOpacity={0.25}
              stroke={d.color}
              strokeWidth={1.5}
              className="transition-all duration-300 group-hover:fill-opacity-40"
              style={{ filter: `drop-shadow(0 0 8px ${d.color}40)` }}
            />
            <title>{`${d.name}: ${d.value}`}</title>
          </g>
        );
      })}

      {/* Grid Circles (Drawn on top) */}
      {gridCircles.map(pct => (
        <circle key={pct} cx={cx} cy={cy} r={maxRadius * pct} fill="none" stroke="#ffffff" strokeOpacity={0.15} strokeWidth="1" className="pointer-events-none" />
      ))}
      {/* Grid Lines (Drawn on top) */}
      {Array.from({ length: gridLines }).map((_, i) => {
        const angle = (i * 360) / gridLines;
        const rad = (angle * Math.PI) / 180;
        const x = cx + maxRadius * Math.cos(rad);
        const y = cy + maxRadius * Math.sin(rad);
        return <line key={i} x1={cx} y1={cy} x2={x} y2={y} stroke="#ffffff" strokeOpacity={0.15} strokeWidth="1" className="pointer-events-none" />;
      })}
    </svg>
  );
}

// --- Agent Content Parser ---

interface ContentBlock {
  type: 'text' | 'tool_call' | 'tool_result' | 'thinking';
  content: string;
  toolName?: string;
  params?: [string, string][];
}

function parseAgentContent(raw: string): ContentBlock[] {
  if (!raw) return [];
  const blocks: ContentBlock[] = [];
  let remaining = raw;

  // Process iteratively — pull out structured blocks, leave plain text
  while (remaining.length > 0) {
    // Find the next XML-like structure
    const funcMatch = remaining.match(/<function=(\w+)>([\s\S]*?)(?:<\/function>|$)/);
    const toolResultMatch = remaining.match(/<tool_result>([\s\S]*?)(?:<\/tool_result>|$)/);
    const thinkMatch = remaining.match(/<function=think>\s*<parameter=thought>([\s\S]*?)(?:<\/parameter>[\s\S]*?<\/function>|$)/);

    // Find earliest match
    let earliest: { idx: number; len: number; block: ContentBlock } | null = null;

    if (thinkMatch && thinkMatch.index !== undefined) {
      const idx = remaining.indexOf(thinkMatch[0]);
      if (!earliest || idx < earliest.idx) {
        earliest = { idx, len: thinkMatch[0].length, block: { type: 'thinking', content: thinkMatch[1].trim() } };
      }
    }

    if (funcMatch && funcMatch.index !== undefined && (!thinkMatch || remaining.indexOf(funcMatch[0]) <= remaining.indexOf(thinkMatch[0]))) {
      const idx = remaining.indexOf(funcMatch[0]);
      if (funcMatch[1] === 'think') {
        // Already handled above or handle as thinking
        if (!earliest || idx < earliest.idx) {
          const thoughtContent = funcMatch[2].replace(/<parameter=thought>/g, '').replace(/<\/parameter>/g, '').trim();
          earliest = { idx, len: funcMatch[0].length, block: { type: 'thinking', content: thoughtContent } };
        }
      } else {
        if (!earliest || idx < earliest.idx) {
          // Parse parameters
          const params: [string, string][] = [];
          const paramRegex = /<parameter=(\w+)>([\s\S]*?)(?:<\/parameter>|$)/g;
          let pm;
          while ((pm = paramRegex.exec(funcMatch[2])) !== null) {
            params.push([pm[1], pm[2].trim()]);
          }
          earliest = { idx, len: funcMatch[0].length, block: { type: 'tool_call', content: '', toolName: funcMatch[1], params } };
        }
      }
    }

    if (toolResultMatch && toolResultMatch.index !== undefined) {
      const idx = remaining.indexOf(toolResultMatch[0]);
      if (!earliest || idx < earliest.idx) {
        // Try to extract tool name
        const tnMatch = toolResultMatch[1].match(/<tool_name>(\w+)<\/tool_name>/);
        const resultMatch = toolResultMatch[1].match(/<result>([\s\S]*?)<\/result>/);
        earliest = { idx, len: toolResultMatch[0].length, block: {
          type: 'tool_result',
          content: resultMatch ? resultMatch[1].trim() : toolResultMatch[1].replace(/<[^>]+>/g, '').trim(),
          toolName: tnMatch ? tnMatch[1] : '',
        }};
      }
    }

    if (!earliest) {
      // No more XML blocks — rest is plain text
      const cleaned = remaining.replace(/<\/?[a-z_]+>/g, '').trim();
      if (cleaned) blocks.push({ type: 'text', content: cleaned });
      break;
    }

    // Add text before this block
    if (earliest.idx > 0) {
      const before = remaining.slice(0, earliest.idx).replace(/<\/?[a-z_]+>/g, '').trim();
      if (before) blocks.push({ type: 'text', content: before });
    }

    blocks.push(earliest.block);
    remaining = remaining.slice(earliest.idx + earliest.len);
  }

  return blocks;
}

// --- Agent Terminal Component (Split: Chat left + Subagent tabs right) ---

function AgentChatFeed({ events, agentId, streaming }: { events: any[]; agentId: string; streaming?: any }) {
  const feedRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [collapsed, setCollapsed] = useState<Set<number>>(new Set());

  useEffect(() => {
    if (autoScroll && feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
  }, [events, autoScroll]);

  const handleScroll = () => {
    if (!feedRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = feedRef.current;
    setAutoScroll(scrollHeight - scrollTop - clientHeight < 60);
  };

  const toggleCollapse = (idx: number) => {
    setCollapsed(prev => { const n = new Set(prev); n.has(idx) ? n.delete(idx) : n.add(idx); return n; });
  };

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <div ref={feedRef} onScroll={handleScroll} className="flex-1 overflow-y-auto custom-scrollbar p-4 space-y-3">
        {/* Live streaming */}
        {streaming && (
          <div className="border border-[#333] rounded-lg bg-[#0d0d0d] overflow-hidden">
            <div className="px-3 py-1.5 bg-[#111] border-b border-[#333] flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse"></span>
              <span className="text-[10px] text-green-400 uppercase tracking-wider">Live</span>
            </div>
            <div className="p-3 max-h-[150px] overflow-y-auto custom-scrollbar">
              <span className="text-xs text-[#d4d4d4] whitespace-pre-wrap">{streaming.content?.slice(-600)}</span>
              <span className="text-[#a855f7] animate-pulse">▊</span>
            </div>
          </div>
        )}

        {events.length === 0 && !streaming && (
          <div className="flex flex-col items-center justify-center py-16 text-[#666]">
            <TerminalSquare className="w-10 h-10 mb-3 text-[#333]" />
            <p className="text-sm">Waiting for activity...</p>
          </div>
        )}

        {events.map((evt, i) => {
          const isAssistant = evt.role === 'assistant';
          const content = evt.content || '';

          // Skip noise
          if (content.includes('<inherited_context') || content.includes('<agent_delegation>')) {
            return <div key={i} className="text-[10px] text-[#444] italic py-0.5">context inherited</div>;
          }

          const parsed = parseAgentContent(content);
          const isCollapsed = collapsed.has(i);

          // Determine if this message has tool calls (make collapsible)
          const hasToolBlocks = parsed.some(b => b.type === 'tool_call' || b.type === 'tool_result');

          return (
            <div key={i} className="space-y-2">
              {parsed.map((block, bi) => {
                if (block.type === 'text' && block.content.trim()) {
                  return (
                    <div key={bi} className={cn(
                      "text-[13px] leading-relaxed whitespace-pre-wrap",
                      isAssistant ? "text-[#e0e0e0]" : "text-[#888]"
                    )}>
                      {block.content.length > 600 ? block.content.slice(0, 600) + '...' : block.content}
                    </div>
                  );
                }
                if (block.type === 'thinking') {
                  return (
                    <div key={bi} className="border border-[#2a2520] rounded-lg bg-[#141210] overflow-hidden">
                      <button
                        onClick={() => toggleCollapse(i * 100 + bi)}
                        className="w-full px-3 py-2 flex items-center gap-2 hover:bg-[#1a1815] transition-colors"
                      >
                        <Zap className="w-3.5 h-3.5 text-amber-500" />
                        <span className="text-xs font-medium text-amber-400">Reasoning</span>
                        <span className="text-[10px] text-[#666] ml-1">{block.content.length} chars</span>
                        <ChevronDown className={cn("w-3 h-3 text-[#666] ml-auto transition-transform", !collapsed.has(i * 100 + bi) && "rotate-180")} />
                      </button>
                      {!collapsed.has(i * 100 + bi) && (
                        <div className="px-3 pb-3 max-h-[300px] overflow-y-auto custom-scrollbar">
                          <p className="text-xs text-[#a09880] whitespace-pre-wrap leading-relaxed">
                            {block.content.length > 800 ? block.content.slice(0, 800) + '...' : block.content}
                          </p>
                        </div>
                      )}
                    </div>
                  );
                }
                if (block.type === 'tool_call') {
                  const isToolCollapsed = collapsed.has(i * 100 + bi);
                  return (
                    <div key={bi} className="border border-[#252525] rounded-lg bg-[#0e0e0e] overflow-hidden">
                      <button
                        onClick={() => toggleCollapse(i * 100 + bi)}
                        className="w-full px-3 py-2 flex items-center gap-2 hover:bg-[#141414] transition-colors"
                      >
                        <Cpu className="w-3.5 h-3.5 text-[#a855f7]" />
                        <span className="text-xs font-mono font-medium text-[#a855f7]">{block.toolName}</span>
                        {block.params && block.params.length > 0 && (
                          <span className="text-[10px] text-[#666] font-mono truncate max-w-[300px]">
                            {block.params.map(([k, v]) => `${k}=${v.length > 30 ? v.slice(0, 30) + '..' : v}`).join(', ')}
                          </span>
                        )}
                        <ChevronDown className={cn("w-3 h-3 text-[#666] ml-auto transition-transform", !isToolCollapsed && "rotate-180")} />
                      </button>
                      {!isToolCollapsed && block.params && block.params.length > 0 && (
                        <div className="px-3 pb-3 border-t border-[#1a1a1a] space-y-1 pt-2">
                          {block.params.map(([k, v], pi) => (
                            <div key={pi} className="text-[11px]">
                              <span className="text-[#666]">{k}: </span>
                              <span className="text-[#aaa] whitespace-pre-wrap break-all">{v.length > 400 ? v.slice(0, 400) + '...' : v}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                }
                if (block.type === 'tool_result') {
                  const isResCollapsed = collapsed.has(i * 100 + bi);
                  return (
                    <div key={bi} className="border border-[#1a2a1a] rounded-lg bg-[#0a110a] overflow-hidden">
                      <button
                        onClick={() => toggleCollapse(i * 100 + bi)}
                        className="w-full px-3 py-2 flex items-center gap-2 hover:bg-[#0d160d] transition-colors"
                      >
                        {block.toolName ? <Check className="w-3.5 h-3.5 text-green-600" /> : <ChevronRight className="w-3.5 h-3.5 text-green-600" />}
                        <span className="text-xs font-mono text-green-600">{block.toolName ? `OUTPUT ${block.toolName}` : 'OUTPUT'}</span>
                        <ChevronDown className={cn("w-3 h-3 text-[#666] ml-auto transition-transform", !isResCollapsed && "rotate-180")} />
                      </button>
                      {!isResCollapsed && (
                        <div className="px-3 pb-3 border-t border-[#1a2a1a] pt-2 max-h-[200px] overflow-y-auto custom-scrollbar">
                          <pre className="text-[11px] text-[#6a9a6a] whitespace-pre-wrap break-all">
                            {block.content.length > 500 ? block.content.slice(0, 500) + '...' : block.content}
                          </pre>
                        </div>
                      )}
                    </div>
                  );
                }
                return null;
              })}
            </div>
          );
        })}
      </div>

      {/* Scroll indicator */}
      {!autoScroll && (
        <button
          onClick={() => { setAutoScroll(true); if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight; }}
          className="mx-auto mb-2 px-3 py-1 bg-[#a855f7]/20 text-[#a855f7] rounded-full text-xs border border-[#a855f7]/30 hover:bg-[#a855f7]/30 transition-colors"
        >
          <ChevronDown className="w-3 h-3 inline mr-1" />scroll to latest
        </button>
      )}
    </div>
  );
}

function AgentTerminal() {
  const [events, setEvents] = useState<AgentEventsResponse | null>(null);
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [selectedSubagent, setSelectedSubagent] = useState<string | null>(null);
  const [chatInput, setChatInput] = useState('');
  const [sending, setSending] = useState(false);
  const [browserView, setBrowserView] = useState<Record<string, any>>({});
  const [showBrowser, setShowBrowser] = useState(false);

  const [assistRequests, setAssistRequests] = useState<any[]>([]);

  // Poll events + agents + browser view + assist requests
  useEffect(() => {
    let active = true;
    const poll = async () => {
      const [evRes, agRes, bvRes, arRes] = await Promise.all([
        api.getAgentEvents(0),
        api.getAgents(),
        api.getBrowserView(),
        api.getAssistRequests(),
      ]);
      if (active) {
        if (evRes) setEvents(evRes);
        if (agRes) setAgents(agRes.agents);
        if (bvRes) setBrowserView(bvRes.browsers);
        if (arRes) setAssistRequests(arRes.requests.filter((r: any) => r.status === 'pending'));
      }
    };
    poll();
    const id = setInterval(poll, 2000);
    return () => { active = false; clearInterval(id); };
  }, []);

  const handleSendMessage = async () => {
    if (!chatInput.trim() || sending) return;
    setSending(true);
    await api.sendAgentMessage(chatInput.trim());
    setChatInput('');
    setSending(false);
  };

  const allEvents = events?.events ?? [];
  const toolEvents = events?.tool_events ?? [];

  // Identify root agent (first agent or one without parent)
  const rootAgent = agents.find(a => !a.parent_id) || agents[0];
  const rootId = rootAgent?.id;
  const subAgents = agents.filter(a => a.id !== rootId);

  // Group events by agent
  const eventsByAgent: Record<string, any[]> = {};
  for (const evt of allEvents) {
    const aid = evt.agent_id || 'unknown';
    if (!eventsByAgent[aid]) eventsByAgent[aid] = [];
    eventsByAgent[aid].push(evt);
  }

  // Root events = root agent's events. If no root, show all
  const rootEvents = rootId ? (eventsByAgent[rootId] || []) : allEvents;

  // Selected subagent events
  const subagentEvents = selectedSubagent ? (eventsByAgent[selectedSubagent] || []) : [];

  // Streaming for root and selected subagent
  const rootStreaming = rootId && events?.streaming?.[rootId] ? events.streaming[rootId] : null;
  const subStreaming = selectedSubagent && events?.streaming?.[selectedSubagent] ? events.streaming[selectedSubagent] : null;

  // Active subagent or first one
  const activeSubagent = selectedSubagent || (subAgents.length > 0 ? subAgents[0].id : null);
  const activeSubEvents = activeSubagent ? (eventsByAgent[activeSubagent] || []) : [];
  const activeSubStreaming = activeSubagent && events?.streaming?.[activeSubagent] ? events.streaming[activeSubagent] : null;

  // Tool counts per agent
  const toolCountByAgent: Record<string, number> = {};
  for (const t of toolEvents) {
    toolCountByAgent[t.agent_id] = (toolCountByAgent[t.agent_id] || 0) + 1;
  }

  const hasSubagents = subAgents.length > 0;
  const runningCount = subAgents.filter(a => a.status === 'running').length;

  return (
    <div className="h-full flex flex-col animate-in fade-in duration-300 -m-6 lg:-m-8">
      {/* Top bar */}
      <div className="flex items-center justify-between px-5 py-2.5 bg-[#111111] border-b border-[#222] flex-shrink-0">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-full bg-[#ff5f57]"></span>
            <span className="w-3 h-3 rounded-full bg-[#febc2e]"></span>
            <span className="w-3 h-3 rounded-full bg-[#28c840]"></span>
          </div>
          <span className="text-sm font-mono text-[#8c8c8c]">agent-terminal</span>
          {events && Object.keys(events.streaming).length > 0 && (
            <span className="flex items-center gap-1.5 text-xs text-green-400">
              <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse"></span>streaming
            </span>
          )}
        </div>
        <div className="flex items-center gap-3 text-[10px] text-[#666] font-mono">
          <span>messages: {allEvents.length}</span>
          <span>tools: {toolEvents.length}</span>
          <span>agents: {agents.length}</span>
          {runningCount > 0 && <span className="text-green-400">{runningCount} active</span>}
        </div>
      </div>

      {/* Captcha / Human assist alerts */}
      {assistRequests.length > 0 && (
        <div className="flex-shrink-0 bg-red-500/10 border-b border-red-500/30">
          {assistRequests.map((ar: any) => (
            <div key={ar.id} className="flex items-center gap-3 px-5 py-2.5">
              <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 animate-pulse" />
              <div className="flex-1 min-w-0">
                <span className="text-xs font-medium text-red-300">
                  {ar.type === 'captcha' ? 'CAPTCHA Detected' : 'Human Assist Required'}
                </span>
                <span className="text-xs text-red-400/70 ml-2">{ar.agent_name} — {ar.url}</span>
              </div>
              <span className="text-[10px] text-red-400/60">{ar.message}</span>
              <button
                onClick={async () => { await api.resolveAssist(ar.id); setAssistRequests(prev => prev.filter(r => r.id !== ar.id)); }}
                className="px-3 py-1 bg-green-500/20 text-green-400 border border-green-500/30 rounded text-xs hover:bg-green-500/30 transition-colors flex-shrink-0"
              >
                Solved ✓
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Split panes */}
      <div className="flex-1 flex overflow-hidden">
        {/* LEFT: Main agent chat */}
        <div className={cn("flex flex-col bg-[#0a0a0a] overflow-hidden", hasSubagents ? "w-1/2 border-r border-[#222]" : "flex-1")}>
          <div className="px-4 py-2 bg-[#0d0d0d] border-b border-[#1a1a1a] flex items-center gap-2 flex-shrink-0">
            <Terminal className="w-3.5 h-3.5 text-[#a855f7]" />
            <span className="text-xs font-medium text-[#d4d4d4]">{rootAgent?.name || 'Main Agent'}</span>
            {rootAgent && (
              <span className={cn("text-[10px] px-1.5 py-0.5 rounded",
                rootAgent.status === 'running' ? "bg-green-500/10 text-green-400" :
                rootAgent.status === 'completed' || rootAgent.status === 'finished' ? "bg-blue-500/10 text-blue-400" :
                "bg-[#222] text-[#666]"
              )}>{rootAgent.status}</span>
            )}
            <span className="text-[10px] text-[#555] ml-auto">
              {rootEvents.length} msgs / {toolCountByAgent[rootId || ''] || 0} tools
            </span>
          </div>
          <AgentChatFeed events={rootEvents} agentId={rootId || ''} streaming={rootStreaming} />

          {/* Chat input */}
          <div className="flex-shrink-0 border-t border-[#222] bg-[#0d0d0d] p-3">
            <div className="flex items-center gap-2">
              <input
                value={chatInput}
                onChange={e => setChatInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && !e.shiftKey && handleSendMessage()}
                placeholder="Message the agent..."
                className="flex-1 bg-[#111] border border-[#333] rounded-lg px-3 py-2 text-sm text-[#d4d4d4] focus:outline-none focus:border-[#a855f7]/50 placeholder-[#555]"
                disabled={sending}
              />
              <button
                onClick={handleSendMessage}
                disabled={sending || !chatInput.trim()}
                className={cn(
                  "p-2 rounded-lg transition-colors",
                  chatInput.trim() ? "bg-[#a855f7] hover:bg-[#c084fc] text-white" : "bg-[#222] text-[#555]"
                )}
              >
                <Send className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>

        {/* RIGHT: Subagent tabs + feed */}
        {hasSubagents && (
          <div className="w-1/2 flex flex-col bg-[#0a0a0a] overflow-hidden">
            {/* Subagent tab bar */}
            <div className="flex items-center bg-[#0d0d0d] border-b border-[#1a1a1a] flex-shrink-0 overflow-x-auto custom-scrollbar">
              {subAgents.map(agent => {
                const isActive = (selectedSubagent || subAgents[0]?.id) === agent.id;
                const isRunning = agent.status === 'running';
                const isDone = agent.status === 'completed' || agent.status === 'finished';
                return (
                  <button
                    key={agent.id}
                    onClick={() => setSelectedSubagent(agent.id)}
                    className={cn(
                      "flex items-center gap-2 px-3 py-2 text-xs border-b-2 transition-colors whitespace-nowrap flex-shrink-0",
                      isActive ? "border-[#a855f7] text-[#d4d4d4] bg-[#111]" : "border-transparent text-[#666] hover:text-[#999] hover:bg-[#111]"
                    )}
                  >
                    <span className={cn("w-2 h-2 rounded-full flex-shrink-0",
                      isRunning ? "bg-green-500 animate-pulse" : isDone ? "bg-blue-500" : agent.status === 'error' ? "bg-red-500" : "bg-[#555]"
                    )}></span>
                    <span className="truncate max-w-[140px]">{agent.name}</span>
                    {(eventsByAgent[agent.id]?.length || 0) > 0 && (
                      <span className="text-[9px] bg-[#222] px-1 rounded text-[#888]">{eventsByAgent[agent.id]?.length}</span>
                    )}
                  </button>
                );
              })}
            </div>

            {/* Active subagent info bar */}
            {activeSubagent && (() => {
              const agent = subAgents.find(a => a.id === activeSubagent) || subAgents[0];
              if (!agent) return null;
              return (
                <div className="px-4 py-2 bg-[#0d0d0d] border-b border-[#1a1a1a] flex items-center gap-2 flex-shrink-0">
                  <span className="text-[10px] text-[#666]">Task:</span>
                  <span className="text-[11px] text-[#999] truncate">{agent.task || 'No task description'}</span>
                  {agent.progress !== undefined && agent.progress > 0 && (
                    <div className="ml-auto flex items-center gap-2 flex-shrink-0">
                      <div className="w-16 h-1 bg-[#222] rounded-full overflow-hidden">
                        <div className="h-full bg-[#a855f7] rounded-full transition-all" style={{ width: `${agent.progress}%` }}></div>
                      </div>
                      <span className="text-[10px] text-[#666]">{agent.progress}%</span>
                    </div>
                  )}
                </div>
              );
            })()}

            {/* Subagent feed */}
            <AgentChatFeed events={activeSubEvents} agentId={activeSubagent || ''} streaming={activeSubStreaming} />
          </div>
        )}
      </div>

      {/* Browser View — bottom center, full width */}
      {Object.keys(browserView).length > 0 && (
        <div className="flex-shrink-0 border-t border-[#222] bg-[#0a0a0a]">
          <button
            onClick={() => setShowBrowser(!showBrowser)}
            className="w-full px-5 py-2 flex items-center justify-center gap-2 text-xs text-[#8c8c8c] hover:text-[#d4d4d4] hover:bg-[#111] transition-colors"
          >
            <Eye className="w-3.5 h-3.5" />
            <span>{showBrowser ? 'Hide' : 'Show'} Browser View</span>
            <span className="text-[10px] text-green-400">{Object.keys(browserView).length} active</span>
          </button>
          {showBrowser && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 p-3 max-h-[500px] overflow-y-auto custom-scrollbar" style={{scrollbarWidth: 'none'}}>
              {Object.entries(browserView).map(([aid, bv]: [string, any]) => (
                <div key={aid} className="border border-[#222] rounded-lg overflow-hidden">
                  <div className="px-3 py-1.5 bg-[#111] border-b border-[#222] flex items-center gap-2">
                    <Globe className="w-3 h-3 text-[#a855f7]" />
                    <span className="text-xs text-[#d4d4d4]">{bv.agent_name}</span>
                    {bv.url && <span className="text-[10px] text-[#666] font-mono ml-auto truncate max-w-[250px]">{bv.url}</span>}
                  </div>
                  {bv.screenshot && (
                    <img
                      src={`data:${bv.media_type || 'image/png'};base64,${bv.screenshot}`}
                      alt={bv.title || 'Browser view'}
                      className="w-full"
                    />
                  )}
                  {bv.title && <div className="px-3 py-1 text-[10px] text-[#888] bg-[#0d0d0d] border-t border-[#1a1a1a]">{bv.title}</div>}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// --- Attack Surface Component ---

const NODE_TYPE_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  recon:         { bg: '#1e3a5f', border: '#3b82f6', text: '#93c5fd' },
  enumerate:     { bg: '#1e3a5f', border: '#60a5fa', text: '#93c5fd' },
  vulnerability: { bg: '#5f1e1e', border: '#ef4444', text: '#fca5a5' },
  exploit:       { bg: '#5f3b1e', border: '#f97316', text: '#fdba74' },
  credential:    { bg: '#5f5f1e', border: '#eab308', text: '#fde047' },
  access:        { bg: '#1e5f3b', border: '#22c55e', text: '#86efac' },
  pivot:         { bg: '#3b1e5f', border: '#a855f7', text: '#d8b4fe' },
  escalation:    { bg: '#5f1e4a', border: '#ec4899', text: '#f9a8d4' },
  exfiltration:  { bg: '#1e5f5f', border: '#14b8a6', text: '#5eead4' },
  persistence:   { bg: '#4a4a1e', border: '#a3a322', text: '#d4d48a' },
};

const STATUS_STYLES: Record<string, string> = {
  planned:     'opacity-50 border-dashed',
  in_progress: 'animate-pulse',
  success:     '',
  failed:      'opacity-60',
  blocked:     'opacity-40',
  skipped:     'opacity-30 line-through',
};

function layoutNodes(apiNodes: any[], apiEdges: [string, string, string][]): { nodes: Node[]; edges: Edge[] } {
  if (!apiNodes.length) return { nodes: [], edges: [] };

  // Build adjacency and compute depths via BFS
  const childMap: Record<string, string[]> = {};
  const parentSet = new Set<string>();
  for (const [from, to] of apiEdges) {
    if (!childMap[from]) childMap[from] = [];
    childMap[from].push(to);
    parentSet.add(to);
  }

  const roots = apiNodes.filter(n => !parentSet.has(n.id)).map(n => n.id);
  if (roots.length === 0 && apiNodes.length > 0) roots.push(apiNodes[0].id);

  const depths: Record<string, number> = {};
  const queue = [...roots];
  roots.forEach(id => { depths[id] = 0; });

  while (queue.length) {
    const current = queue.shift()!;
    for (const child of (childMap[current] || [])) {
      if (!(child in depths)) {
        depths[child] = (depths[current] || 0) + 1;
        queue.push(child);
      }
    }
  }

  // Assign depth to orphans
  for (const n of apiNodes) {
    if (!(n.id in depths)) depths[n.id] = 0;
  }

  // Group by depth
  const byDepth: Record<number, any[]> = {};
  for (const n of apiNodes) {
    const d = depths[n.id];
    if (!byDepth[d]) byDepth[d] = [];
    byDepth[d].push(n);
  }

  const X_GAP = 320;
  const Y_GAP = 120;
  const MAX_ROWS = 8; // Max nodes per column before wrapping
  const nodes: Node[] = [];

  for (const [depthStr, group] of Object.entries(byDepth)) {
    const depth = Number(depthStr);
    // Multi-column layout: wrap after MAX_ROWS nodes
    const cols = Math.ceil(group.length / MAX_ROWS);
    const rowsPerCol = Math.min(group.length, MAX_ROWS);
    const totalHeight = (rowsPerCol - 1) * Y_GAP;

    group.forEach((n: any, i: number) => {
      const col = Math.floor(i / MAX_ROWS);
      const row = i % MAX_ROWS;
      const colors = NODE_TYPE_COLORS[n.type] || NODE_TYPE_COLORS.recon;
      const statusCls = STATUS_STYLES[n.status] || '';
      nodes.push({
        id: n.id,
        position: {
          x: depth * X_GAP * cols + col * X_GAP + 50,
          y: row * Y_GAP - totalHeight / 2 + 300,
        },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
        data: { label: n.description || n.id, node: n },
        style: {
          background: colors.bg,
          border: `1.5px ${n.status === 'planned' ? 'dashed' : 'solid'} ${colors.border}`,
          color: colors.text,
          borderRadius: '8px',
          padding: '10px 14px',
          fontSize: '11px',
          fontFamily: 'monospace',
          maxWidth: '220px',
          boxShadow: `0 0 12px ${colors.border}30`,
        },
        className: statusCls,
      });
    });
  }

  const edges: Edge[] = apiEdges.map(([from, to, label], i) => ({
    id: `e-${i}`,
    source: from,
    target: to,
    label,
    labelStyle: { fill: '#666', fontSize: 9, fontFamily: 'monospace' },
    style: { stroke: '#444', strokeWidth: 1.5 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#555', width: 16, height: 16 },
    animated: true,
  }));

  return { nodes, edges };
}

function AttackSurface() {
  const [graphData, setGraphData] = useState<AttackGraphResponse | null>(null);
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [stableNodes, setStableNodes] = useState<Node[]>([]);
  const [stableEdges, setStableEdges] = useState<Edge[]>([]);
  const prevNodeCount = useRef(0);

  const fetcher = useCallback(() => api.getAttackGraph(), []);
  const vulnFetcher = useCallback(() => api.getVulnerabilities(), []);

  useEffect(() => {
    let active = true;
    const poll = async () => {
      const [gRes, vRes] = await Promise.all([fetcher(), vulnFetcher()]);
      if (active) {
        if (gRes) setGraphData(gRes);
        if (vRes) setVulns(vRes);
      }
    };
    poll();
    const id = setInterval(poll, 5000);
    return () => { active = false; clearInterval(id); };
  }, [fetcher, vulnFetcher]);

  const hasData = graphData && graphData.nodes && graphData.nodes.length > 0;

  // Only re-layout when node count changes (prevents flicker on polling)
  useEffect(() => {
    if (hasData) {
      const newCount = graphData.nodes.length;
      if (newCount !== prevNodeCount.current) {
        prevNodeCount.current = newCount;
        const { nodes: n, edges: e } = layoutNodes(graphData.nodes, graphData.edges);
        setStableNodes(n);
        setStableEdges(e);
      }
    }
  }, [graphData, hasData]);

  const nodes = stableNodes;
  const edges = stableEdges;

  // Count by type for legend
  const typeCounts: Record<string, number> = {};
  if (hasData) {
    for (const n of graphData.nodes) {
      typeCounts[n.type] = (typeCounts[n.type] || 0) + 1;
    }
  }

  // Build CVE chains from vulnerabilities
  const cveChains = vulns.filter(v => v.cve || v.cwe).map(v => ({
    vuln: v.title,
    cve: v.cve || '',
    cwe: v.cwe || '',
    severity: v.severity,
    hasPoc: !!v.poc_script_code,
    endpoint: v.endpoint || v.target || '',
  }));

  const onNodeClick = (_: any, node: Node) => {
    setSelectedNode(node.data?.node || null);
  };

  return (
    <div className="space-y-4 max-w-full mx-auto animate-in fade-in duration-500 h-full flex flex-col">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-medium text-[#f2f2f2]">Attack Surface</h2>
          <p className="text-[#8c8c8c] text-sm mt-1">Visualization of target structure and discovered attack vectors.</p>
        </div>
        <div className="flex items-center gap-2">
          {cveChains.length > 0 && (
            <span className="text-xs bg-red-500/10 text-red-400 px-2.5 py-1 rounded-full border border-red-500/20">
              {cveChains.length} CVE chains
            </span>
          )}
          {hasData && (
            <span className="text-xs bg-[#a855f7]/10 text-[#a855f7] px-2.5 py-1 rounded-full border border-[#a855f7]/20">
              {graphData.nodes.length} nodes
            </span>
          )}
        </div>
      </div>

      {/* Legend */}
      {hasData && (
        <div className="flex flex-wrap gap-3">
          {Object.entries(typeCounts).map(([type, count]) => {
            const colors = NODE_TYPE_COLORS[type] || NODE_TYPE_COLORS.recon;
            return (
              <div key={type} className="flex items-center gap-1.5 text-xs">
                <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: colors.border }}></span>
                <span className="text-[#8c8c8c]">{type}</span>
                <span className="text-[#555]">({count})</span>
              </div>
            );
          })}
        </div>
      )}

      <div className="flex-1 flex gap-4 min-h-[600px]">
        {/* Graph */}
        <div className={cn("bg-[#0a0a0a] border border-[#222] rounded-xl overflow-hidden relative", selectedNode || cveChains.length > 0 ? "flex-1" : "w-full")}>
          {!hasData ? (
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <Map className="w-16 h-16 text-[#333] mx-auto mb-4" />
                <h3 className="text-lg font-medium text-[#8c8c8c] mb-2">No Data</h3>
                <p className="text-sm text-[#666]">The attack surface graph will appear after scanning begins.</p>
              </div>
            </div>
          ) : (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodeClick={onNodeClick}
              fitView
              minZoom={0.3}
              maxZoom={2}
              defaultViewport={{ x: 0, y: 0, zoom: 0.8 }}
              proOptions={{ hideAttribution: true }}
            >
              <Background color="#222" gap={20} size={1} />
              <Controls
                showInteractive={false}
                style={{ background: '#1a1a1a', border: '1px solid #333', borderRadius: '6px' }}
              />
            </ReactFlow>
          )}
        </div>

        {/* Side panel: Node detail + CVE chains */}
        {(selectedNode || cveChains.length > 0) && (
          <div className="w-80 flex-shrink-0 space-y-3 overflow-y-auto custom-scrollbar">
            {/* Selected node detail */}
            {selectedNode && (
              <div className="bg-[#111] border border-[#222] rounded-lg overflow-hidden">
                <div className="px-4 py-3 bg-[#141414] border-b border-[#222] flex items-center justify-between">
                  <span className="text-sm font-medium text-[#f2f2f2]">Node Detail</span>
                  <button onClick={() => setSelectedNode(null)} className="text-[#666] hover:text-[#999]"><X className="w-3.5 h-3.5" /></button>
                </div>
                <div className="p-4 space-y-3 text-xs">
                  <div><span className="text-[#666]">Type:</span> <span className="text-[#d4d4d4] ml-1" style={{color: (NODE_TYPE_COLORS[selectedNode.type] || NODE_TYPE_COLORS.recon).text}}>{selectedNode.type}</span></div>
                  <div><span className="text-[#666]">Status:</span> <span className="text-[#d4d4d4] ml-1">{selectedNode.status}</span></div>
                  {selectedNode.description && <div><span className="text-[#666]">Description:</span><p className="text-[#aaa] mt-1">{selectedNode.description}</p></div>}
                  {selectedNode.technique && <div><span className="text-[#666]">Technique:</span> <span className="text-yellow-400 ml-1 font-mono">{selectedNode.technique}</span></div>}
                  {selectedNode.target && <div><span className="text-[#666]">Target:</span> <span className="text-[#a855f7] ml-1 font-mono">{selectedNode.target}</span></div>}
                  {selectedNode.evidence && <div><span className="text-[#666]">Evidence:</span><pre className="text-[#86efac] mt-1 p-2 bg-[#0a0a0a] rounded border border-[#222] whitespace-pre-wrap text-[10px]">{selectedNode.evidence.slice(0, 300)}</pre></div>}
                </div>
              </div>
            )}

            {/* CVE/Exploit Chains */}
            {cveChains.length > 0 && (
              <div className="bg-[#111] border border-[#222] rounded-lg overflow-hidden">
                <div className="px-4 py-3 bg-[#141414] border-b border-[#222]">
                  <span className="text-sm font-medium text-[#f2f2f2]">Exploit Chains</span>
                </div>
                <div className="divide-y divide-[#1a1a1a] max-h-[400px] overflow-y-auto custom-scrollbar">
                  {cveChains.map((c, i) => {
                    const sevColor = c.severity === 'critical' ? '#ef4444' : c.severity === 'high' ? '#f97316' : c.severity === 'medium' ? '#eab308' : '#3b82f6';
                    return (
                      <div key={i} className="p-3 space-y-1.5">
                        <div className="flex items-center gap-2">
                          <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{backgroundColor: sevColor}}></span>
                          <span className="text-xs text-[#d4d4d4] truncate">{c.vuln}</span>
                        </div>
                        <div className="flex items-center gap-1.5 text-[10px] font-mono pl-3">
                          {c.cve && <span className="text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded border border-red-500/20">{c.cve}</span>}
                          {c.cve && c.cwe && <span className="text-[#555]">&rarr;</span>}
                          {c.cwe && <span className="text-orange-400 bg-orange-500/10 px-1.5 py-0.5 rounded border border-orange-500/20">{c.cwe}</span>}
                          {c.hasPoc && <><span className="text-[#555]">&rarr;</span><span className="text-green-400 bg-green-500/10 px-1.5 py-0.5 rounded border border-green-500/20">PoC</span></>}
                        </div>
                        {c.endpoint && <div className="text-[10px] text-[#666] pl-3 font-mono truncate">{c.endpoint}</div>}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// --- Vulnerabilities Component ---
function Vulnerabilities({ liveVulns }: { liveVulns?: Vulnerability[] | null }) {
  const [activeFilter, setActiveFilter] = useState('All');
  const [expandedVuln, setExpandedVuln] = useState<number | null>(null);

  // Map API vulns to display format with full details
  const apiVulns = liveVulns?.map((v, i) => {
    const sevMap: Record<string, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'INFO' };
    return {
      id: i + 1,
      title: v.title,
      severity: sevMap[v.severity?.toLowerCase()] ?? v.severity,
      target: v.target ?? v.endpoint ?? '—',
      description: v.description ?? '',
      script: v.poc_script_code ?? '',
      impact: v.impact ?? '',
      remediation: v.remediation_steps ?? '',
      technical: v.technical_analysis ?? '',
      cvss: v.cvss,
      cve: v.cve ?? '',
      cwe: v.cwe ?? '',
      method: v.method ?? '',
      endpoint: v.endpoint ?? '',
      business_impact: v.business_impact,
    };
  });

  const mockVulns = apiVulns ?? [];

  const filters = [
    { label: 'All', count: mockVulns.length },
    { label: 'Critical', count: mockVulns.filter(v => v.severity === 'Critical').length },
    { label: 'High', count: mockVulns.filter(v => v.severity === 'High').length },
    { label: 'Medium', count: mockVulns.filter(v => v.severity === 'Medium').length },
    { label: 'Low', count: mockVulns.filter(v => v.severity === 'Low').length },
    { label: 'INFO', count: 0 },
    { label: 'Ignored', count: 0 },
  ];

  const filteredVulns = activeFilter === 'All' 
    ? mockVulns 
    : mockVulns.filter(v => v.severity === activeFilter);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'text-red-500 bg-red-500/10 border-red-500/20';
      case 'High': return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
      case 'Medium': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
      case 'Low': return 'text-blue-500 bg-blue-500/10 border-blue-500/20';
      default: return 'text-gray-500 bg-gray-500/10 border-gray-500/20';
    }
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto animate-in fade-in duration-500">
      
      {/* Filters */}
      <div className="flex flex-wrap gap-2 border-b border-[#222] pb-4">
        {filters.map((filter) => (
          <button
            key={filter.label}
            onClick={() => setActiveFilter(filter.label)}
            className={cn(
              "px-4 py-2 rounded-md text-sm font-medium transition-colors duration-200 flex items-center gap-2",
              activeFilter === filter.label
                ? "bg-blue-500/20 text-blue-400 border border-blue-500/30"
                : "text-[#8c8c8c] hover:text-[#d4d4d4] hover:bg-[#1a1a1a] border border-transparent"
            )}
          >
            {filter.label}
            <span className={cn(
              "text-[10px] px-1.5 py-0.5 rounded-full border",
              activeFilter === filter.label
                ? "border-blue-500/30 bg-blue-500/10 text-blue-400"
                : "border-[#333] bg-[#222] text-[#8c8c8c]"
            )}>
              {filter.count}
            </span>
          </button>
        ))}
      </div>

      {/* Vulnerabilities List */}
      <div className="space-y-4">
        {filteredVulns.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-[#8c8c8c]">
            <Check className="w-12 h-12 mb-4 text-[#333]" />
            <p>No vulnerabilities found</p>
          </div>
        ) : (
          filteredVulns.map((vuln) => (
            <div 
              key={vuln.id} 
              className={cn(
                "bg-[#111111] border rounded-lg overflow-hidden transition-all duration-200",
                expandedVuln === vuln.id ? "border-blue-500/50 shadow-[0_0_15px_rgba(59,130,246,0.1)]" : "border-[#222] hover:border-[#333]"
              )}
            >
              <div
                className="p-5 flex items-center justify-between cursor-pointer select-none"
                onClick={() => setExpandedVuln(expandedVuln === vuln.id ? null : vuln.id)}
              >
                <div className="flex items-center gap-4">
                  <div className={cn("px-3 py-1 rounded border text-xs font-medium uppercase tracking-wider", getSeverityColor(vuln.severity))}>
                    {vuln.severity}
                  </div>
                  <div>
                    <h3 className="text-[#f2f2f2] font-medium text-base">{vuln.title}</h3>
                    <div className="flex items-center gap-3 mt-1">
                      <span className="text-[#8c8c8c] text-sm">{vuln.target}</span>
                      {vuln.cvss && <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#222] border border-[#333] text-[#d4d4d4]">CVSS {vuln.cvss}</span>}
                      {vuln.cve && <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400">{vuln.cve}</span>}
                      {vuln.cwe && <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-orange-500/10 border border-orange-500/20 text-orange-400">{vuln.cwe}</span>}
                      {vuln.method && <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400">{vuln.method}</span>}
                    </div>
                  </div>
                </div>
                <div className="text-[#666]">
                  {expandedVuln === vuln.id ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
                </div>
              </div>

              {/* Expanded Content */}
              {expandedVuln === vuln.id && (
                <div className="border-t border-[#222] bg-[#0a0a0a] p-6 space-y-5 animate-in slide-in-from-top-2 duration-200">
                  {/* Meta badges */}
                  {(vuln.endpoint || vuln.cvss || vuln.cve || vuln.cwe) && (
                    <div className="flex flex-wrap gap-3 text-xs">
                      {vuln.endpoint && (
                        <div className="bg-[#111] border border-[#222] rounded px-3 py-1.5">
                          <span className="text-[#666]">Endpoint: </span>
                          <span className="text-[#a855f7] font-mono">{vuln.endpoint}</span>
                        </div>
                      )}
                      {vuln.cvss && (
                        <div className="bg-[#111] border border-[#222] rounded px-3 py-1.5">
                          <span className="text-[#666]">CVSS: </span>
                          <span className={cn("font-bold", vuln.cvss >= 9 ? "text-red-400" : vuln.cvss >= 7 ? "text-orange-400" : vuln.cvss >= 4 ? "text-yellow-400" : "text-blue-400")}>{vuln.cvss}</span>
                        </div>
                      )}
                      {vuln.business_impact && (
                        <div className="bg-[#111] border border-[#222] rounded px-3 py-1.5">
                          <span className="text-[#666]">Business Risk: </span>
                          <span className={cn("font-medium", vuln.business_impact.risk_level === 'critical' ? "text-red-400" : vuln.business_impact.risk_level === 'high' ? "text-orange-400" : "text-yellow-400")}>{vuln.business_impact.risk_level}</span>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Description */}
                  {vuln.description && (
                    <div>
                      <h4 className="text-sm font-medium text-[#e0e0e0] mb-2 flex items-center gap-2">
                        <Info className="w-4 h-4 text-blue-400" />
                        Description
                      </h4>
                      <p className="text-[#8c8c8c] text-sm leading-relaxed">{vuln.description}</p>
                    </div>
                  )}

                  {/* Impact */}
                  {vuln.impact && (
                    <div>
                      <h4 className="text-sm font-medium text-[#e0e0e0] mb-2 flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 text-orange-400" />
                        Impact
                      </h4>
                      <p className="text-[#8c8c8c] text-sm leading-relaxed">{vuln.impact}</p>
                    </div>
                  )}

                  {/* Technical Analysis */}
                  {vuln.technical && (
                    <div>
                      <h4 className="text-sm font-medium text-[#e0e0e0] mb-2 flex items-center gap-2">
                        <Eye className="w-4 h-4 text-blue-400" />
                        Technical Analysis
                      </h4>
                      <p className="text-[#8c8c8c] text-sm leading-relaxed">{vuln.technical}</p>
                    </div>
                  )}

                  {/* PoC */}
                  {vuln.script && (
                    <div>
                      <h4 className="text-sm font-medium text-[#e0e0e0] mb-2 flex items-center gap-2">
                        <Code className="w-4 h-4 text-green-400" />
                        Proof of Concept
                      </h4>
                      <pre className="bg-[#111111] border border-[#222] rounded-md p-4 overflow-x-auto text-sm font-mono text-green-400/90 leading-relaxed custom-scrollbar">
                        <code>{vuln.script}</code>
                      </pre>
                    </div>
                  )}

                  {/* Remediation */}
                  {vuln.remediation && (
                    <div>
                      <h4 className="text-sm font-medium text-[#e0e0e0] mb-2 flex items-center gap-2">
                        <Shield className="w-4 h-4 text-green-400" />
                        Remediation
                      </h4>
                      <p className="text-green-300/80 text-sm leading-relaxed bg-green-500/5 border border-green-500/10 rounded-md p-3">{vuln.remediation}</p>
                    </div>
                  )}

                  {/* Retest button */}
                  <button
                    onClick={async (e) => {
                      e.stopPropagation();
                      await api.sendAgentMessage(`Retest this specific vulnerability: "${vuln.title}" at ${vuln.target || vuln.endpoint || 'the target'}. Check if it is still exploitable. Use the same technique described in the PoC.`);
                    }}
                    className="flex items-center gap-2 px-4 py-2 bg-[#a855f7]/10 hover:bg-[#a855f7]/20 border border-[#a855f7]/30 rounded-lg text-sm text-[#a855f7] transition-colors"
                  >
                    <Crosshair className="w-3.5 h-3.5" />
                    Retest this vulnerability
                  </button>
                </div>
              )}
            </div>
          ))
        )}
      </div>

    </div>
  );
}

// --- Target Overview Component ---
function TargetOverview({ scanStatus }: { scanStatus?: ScanStatus | null }) {
  const target = scanStatus?.targets?.[0]?.original ?? '—';
  const targetType = scanStatus?.targets?.[0]?.type ?? '—';
  const targetDetails = scanStatus?.targets?.[0]?.details ?? {};
  const hasTarget = scanStatus && scanStatus.targets && scanStatus.targets.length > 0;

  const [recon, setRecon] = useState<ReconResults | null>(null);
  const [showRawNmap, setShowRawNmap] = useState(false);
  const [roiScores, setRoiScores] = useState<RoiScore[]>([]);

  useEffect(() => {
    if (!hasTarget) return;
    let active = true;
    const poll = async () => {
      const [reconRes, roiRes] = await Promise.all([api.getReconResults(), api.getRoiScores()]);
      if (active) {
        if (reconRes && Object.keys(reconRes).length > 0) setRecon(reconRes);
        if (roiRes) setRoiScores(roiRes.scores);
      }
    };
    poll();
    const id = setInterval(poll, 5000);
    return () => { active = false; clearInterval(id); };
  }, [hasTarget]);

  const httpx = recon?.httpx_info ?? {};

  if (!hasTarget) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-[#8c8c8c] animate-in fade-in duration-500">
        <Server className="w-16 h-16 text-[#333] mb-4" />
        <h3 className="text-lg font-medium mb-2">No Target Data</h3>
        <p className="text-sm text-[#666]">Start a penetration test to get target information.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-6xl mx-auto animate-in fade-in duration-500">

      {/* Section 1: Target Info */}
      <div className="bg-[#111111] border border-[#222] rounded-lg shadow-lg overflow-hidden">
        <div className="p-5 border-b border-[#222] flex items-center gap-2">
          <Target className="w-5 h-5 text-blue-400" />
          <h2 className="text-lg font-medium text-[#f2f2f2]">Target Information</h2>
        </div>
        <div className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div>
                <div className="text-xs text-[#8c8c8c] mb-2">Test Target</div>
                <span className="inline-block px-3 py-1.5 bg-[#1a1a1a] border border-[#333] rounded text-sm text-[#d4d4d4] font-mono">
                  {target}
                </span>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-xs text-[#8c8c8c] mb-1.5">Target Type</div>
                  <div className="text-sm text-[#e0e0e0] font-medium">{targetType}</div>
                </div>
                <div>
                  <div className="text-xs text-[#8c8c8c] mb-1.5">Status</div>
                  <div className="text-sm text-[#e0e0e0]">{scanStatus?.status ?? '—'}</div>
                </div>
              </div>
              {httpx.status_code && (
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <div className="text-xs text-[#8c8c8c] mb-1.5">HTTP Status</div>
                    <div className="text-sm text-[#e0e0e0]">
                      <span className={cn(
                        "px-2 py-0.5 rounded text-xs font-mono",
                        httpx.status_code < 400 ? "bg-green-500/10 text-green-400" : "bg-red-500/10 text-red-400"
                      )}>{httpx.status_code}</span>
                    </div>
                  </div>
                  {httpx.title && (
                    <div>
                      <div className="text-xs text-[#8c8c8c] mb-1.5">Page Title</div>
                      <div className="text-sm text-[#e0e0e0]">{httpx.title}</div>
                    </div>
                  )}
                </div>
              )}
              {httpx.server && (
                <div>
                  <div className="text-xs text-[#8c8c8c] mb-1.5">Server</div>
                  <div className="text-sm text-[#e0e0e0] font-mono">{httpx.server}</div>
                </div>
              )}
            </div>
            <div className="space-y-4">
              {/* Technologies / WAF */}
              {httpx.technologies && httpx.technologies.length > 0 && (
                <div>
                  <div className="text-xs text-[#8c8c8c] mb-2">Technologies / WAF</div>
                  <div className="flex flex-wrap gap-2">
                    {httpx.technologies.map((tech: string, i: number) => (
                      <span key={i} className="px-2.5 py-1 bg-[#1a1a1a] border border-[#333] rounded text-xs text-[#d4d4d4]">
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {/* Subdomains count */}
              {recon?.subdomains && recon.subdomains.length > 0 && (
                <div>
                  <div className="text-xs text-[#8c8c8c] mb-1.5">Subdomains Found</div>
                  <div className="text-sm text-[#a855f7] font-medium">{recon.subdomains.length}</div>
                </div>
              )}
              {/* Ports summary */}
              {recon?.ports && recon.ports.length > 0 && (
                <div>
                  <div className="text-xs text-[#8c8c8c] mb-1.5">Open Ports</div>
                  <div className="text-sm text-[#e0e0e0]">{recon.ports.map(p => p.port.split('/')[0]).join(', ')}</div>
                </div>
              )}
              {/* IP Intelligence */}
              {(recon as any)?.ip_info?.ip && (
                <div className="col-span-2 mt-2 bg-[#0a0a0a] border border-[#222] rounded-lg p-4">
                  <div className="text-xs text-[#8c8c8c] mb-3 flex items-center gap-2">
                    <Globe className="w-3 h-3" />
                    IP Intelligence
                  </div>
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div><span className="text-[#666]">IP:</span> <span className="text-[#d4d4d4] font-mono ml-1">{(recon as any).ip_info.ip}</span></div>
                    {(recon as any).ip_info.country && <div><span className="text-[#666]">Location:</span> <span className="text-[#d4d4d4] ml-1">{(recon as any).ip_info.city}, {(recon as any).ip_info.region}, {(recon as any).ip_info.country}</span></div>}
                    {(recon as any).ip_info.isp && <div><span className="text-[#666]">ISP:</span> <span className="text-[#d4d4d4] ml-1">{(recon as any).ip_info.isp}</span></div>}
                    {(recon as any).ip_info.org && <div><span className="text-[#666]">Organization:</span> <span className="text-[#d4d4d4] ml-1">{(recon as any).ip_info.org}</span></div>}
                    {(recon as any).ip_info.asn && <div><span className="text-[#666]">ASN:</span> <span className="text-[#a855f7] font-mono ml-1">{(recon as any).ip_info.asn}</span></div>}
                    {(recon as any).ip_info.hosting && <div><span className="text-orange-400 text-[10px] px-1.5 py-0.5 bg-orange-500/10 border border-orange-500/20 rounded">Hosting/Cloud</span></div>}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Section 2: Network Info */}
      <div className="bg-[#111111] border border-[#222] rounded-lg shadow-lg overflow-hidden">
        <div className="p-5 border-b border-[#222] flex items-center gap-2">
          <Network className="w-5 h-5 text-blue-400" />
          <h2 className="text-lg font-medium text-[#f2f2f2]">Network Information</h2>
          {recon?.ports && recon.ports.length > 0 && (
            <span className="text-xs bg-blue-500/10 text-blue-400 px-2 py-0.5 rounded-full border border-blue-500/20 ml-auto">
              {recon.ports.length} open ports
            </span>
          )}
        </div>
        <div className="p-6">
          {!recon ? (
            <div className="text-sm text-[#666] text-center py-8">Data will update during scanning</div>
          ) : (
            <div className="space-y-6">
              {/* Open Ports & Services */}
              {recon.ports && recon.ports.length > 0 && (
                <div>
                  <div className="text-xs text-[#8c8c8c] mb-3">Open Ports & Services</div>
                  <div className="space-y-2">
                    {recon.ports.map((p, i) => (
                      <div key={i} className="flex items-center gap-3 bg-[#0a0a0a] border border-[#222] rounded p-3">
                        <span className="font-mono text-[#a855f7] text-sm font-medium w-16">{p.port.split('/')[0]}</span>
                        <span className={cn(
                          "px-2 py-0.5 rounded text-[10px] font-medium",
                          p.state === 'open' ? "bg-green-500/10 text-green-400 border border-green-500/20" : "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20"
                        )}>{p.state}</span>
                        <span className="text-sm text-[#d4d4d4]">{p.service.toUpperCase()}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* WAF/CDN Detection */}
              {httpx.technologies && httpx.technologies.some((t: string) => /guard|cloud|waf|cdn|firewall/i.test(t)) && (
                <div>
                  <div className="text-xs text-[#8c8c8c] mb-3">WAF / CDN Detection</div>
                  <div className="flex flex-wrap gap-2">
                    {httpx.technologies.filter((t: string) => /guard|cloud|waf|cdn|firewall|hsts/i.test(t)).map((t: string, i: number) => (
                      <span key={i} className="px-3 py-1.5 bg-orange-500/10 border border-orange-500/20 rounded text-xs text-orange-400 font-medium">
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Raw nmap toggle */}
              {recon.nmap_output && (
                <div>
                  <button
                    onClick={() => setShowRawNmap(!showRawNmap)}
                    className="flex items-center gap-1 text-xs text-[#8c8c8c] hover:text-[#d4d4d4] transition-colors"
                  >
                    {showRawNmap ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                    Raw nmap output
                  </button>
                  {showRawNmap && (
                    <pre className="mt-2 p-3 bg-[#0a0a0a] border border-[#222] rounded text-xs text-[#888] font-mono overflow-x-auto max-h-[300px] overflow-y-auto custom-scrollbar whitespace-pre">
                      {recon.nmap_output}
                    </pre>
                  )}
                </div>
              )}

              {recon.ports.length === 0 && !recon.nmap_output && (
                <div className="text-sm text-[#666] text-center py-4">No network data collected</div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Section 3: Web App Info */}
      <div className="bg-[#111111] border border-[#222] rounded-lg shadow-lg overflow-hidden">
        <div className="p-5 border-b border-[#222] flex items-center gap-2">
          <Globe className="w-5 h-5 text-blue-400" />
          <h2 className="text-lg font-medium text-[#f2f2f2]">Web Application Info</h2>
        </div>
        <div className="p-6 space-y-6">
          {!recon ? (
            <div className="text-sm text-[#666] text-center py-8">Data will update during scanning</div>
          ) : (
            <>
              {/* Subdomains */}
              {recon.subdomains && recon.subdomains.length > 0 && (
                <div>
                  <div className="text-xs text-[#8c8c8c] mb-3 flex items-center gap-2">
                    <Globe2 className="w-3 h-3" />
                    Subdomains ({recon.subdomains.length})
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {recon.subdomains.map((sub, i) => (
                      <span key={i} className="px-2.5 py-1 bg-[#1a1a1a] border border-[#333] rounded text-xs text-[#d4d4d4] font-mono">
                        {sub}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* HTTP Probe */}
              {recon.httpx_output && (
                <div>
                  <div className="text-xs text-[#8c8c8c] mb-3 flex items-center gap-2">
                    <Activity className="w-3 h-3" />
                    HTTP Probe
                  </div>
                  <pre className="p-3 bg-[#0a0a0a] border border-[#222] rounded text-xs text-[#c0c0c0] font-mono overflow-x-auto max-h-[200px] overflow-y-auto custom-scrollbar whitespace-pre-wrap">
                    {recon.httpx_output}
                  </pre>
                </div>
              )}

              {/* Discovered Endpoints */}
              {(recon as any)?.endpoints?.length > 0 && (
                <div>
                  <div className="text-xs text-[#8c8c8c] mb-3 flex items-center gap-2">
                    <Layers className="w-3 h-3" />
                    Discovered Endpoints ({(recon as any).endpoints.length})
                    {(recon as any).api_endpoints?.length > 0 && <span className="bg-[#a855f7]/10 text-[#a855f7] px-1.5 py-0.5 rounded-full border border-[#a855f7]/20 text-[10px]">{(recon as any).api_endpoints.length} API</span>}
                    {(recon as any).auth_endpoints?.length > 0 && <span className="bg-blue-500/10 text-blue-400 px-1.5 py-0.5 rounded-full border border-blue-500/20 text-[10px]">{(recon as any).auth_endpoints.length} Auth</span>}
                  </div>
                  <div className="flex flex-wrap gap-1.5 max-h-[150px] overflow-y-auto custom-scrollbar" style={{scrollbarWidth:'none'}}>
                    {(recon as any).endpoints.map((ep: string, i: number) => {
                      const isApi = (recon as any).api_endpoints?.includes(ep);
                      const isAuth = (recon as any).auth_endpoints?.includes(ep);
                      return (
                        <span key={i} className={cn("px-2 py-0.5 rounded text-[10px] font-mono border",
                          isApi ? "bg-[#a855f7]/10 border-[#a855f7]/20 text-[#a855f7]" :
                          isAuth ? "bg-blue-500/10 border-blue-500/20 text-blue-400" :
                          "bg-[#1a1a1a] border-[#333] text-[#999]"
                        )}>
                          {ep.replace(/^https?:\/\/[^/]+/, '')}
                        </span>
                      );
                    })}
                  </div>
                  {(recon as any).graphql?.endpoint && (
                    <div className="mt-2 flex items-center gap-2">
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-500/10 border border-green-500/20 text-green-400">GraphQL</span>
                      <span className="text-[10px] font-mono text-[#888]">{(recon as any).graphql.endpoint}</span>
                      {(recon as any).graphql.types_count > 0 && <span className="text-[10px] text-[#666]">{(recon as any).graphql.types_count} types</span>}
                    </div>
                  )}
                </div>
              )}

              {/* Nuclei Findings */}
              {recon.nuclei_output && (
                <div>
                  <div className="text-xs text-[#8c8c8c] mb-3 flex items-center gap-2">
                    <ShieldAlert className="w-3 h-3" />
                    Vulnerability Scan
                    {recon.findings_count > 0 && (
                      <span className="bg-red-500/10 text-red-400 px-2 py-0.5 rounded-full border border-red-500/20 text-[10px]">
                        {recon.findings_count} findings
                      </span>
                    )}
                  </div>
                  <pre className="p-3 bg-[#0a0a0a] border border-[#222] rounded text-xs text-[#c0c0c0] font-mono overflow-x-auto max-h-[200px] overflow-y-auto custom-scrollbar whitespace-pre-wrap">
                    {recon.nuclei_output}
                  </pre>
                </div>
              )}

              {!recon.subdomains?.length && !recon.httpx_output && !recon.nuclei_output && (
                <div className="text-sm text-[#666] text-center py-4">No web application data collected</div>
              )}
            </>
          )}
        </div>
      </div>

      {/* Section 4: ROI Scoring */}
      {roiScores.length > 0 && (
        <div className="bg-[#111111] border border-[#222] rounded-lg shadow-lg overflow-hidden">
          <div className="p-5 border-b border-[#222] flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-[#a855f7]" />
            <h2 className="text-lg font-medium text-[#f2f2f2]">Target Priority Score</h2>
            <span className="text-xs text-[#666] ml-auto">Higher = more likely vulnerable</span>
          </div>
          <div className="divide-y divide-[#1a1a1a]">
            {roiScores.map((item, i) => {
              const barColor = item.priority === 'critical' ? 'bg-red-500' : item.priority === 'high' ? 'bg-orange-500' : item.priority === 'medium' ? 'bg-yellow-500' : 'bg-blue-500';
              const textColor = item.priority === 'critical' ? 'text-red-400' : item.priority === 'high' ? 'text-orange-400' : item.priority === 'medium' ? 'text-yellow-400' : 'text-blue-400';
              return (
                <div key={i} className="px-5 py-3 flex items-center gap-4">
                  <span className={cn("text-lg font-bold w-10 text-right", textColor)}>{item.score}</span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-[#d4d4d4] font-mono truncate">{item.subdomain}</span>
                      <span className={cn("text-[10px] px-1.5 py-0.5 rounded border",
                        item.priority === 'critical' ? "text-red-400 border-red-500/20 bg-red-500/10" :
                        item.priority === 'high' ? "text-orange-400 border-orange-500/20 bg-orange-500/10" :
                        item.priority === 'medium' ? "text-yellow-400 border-yellow-500/20 bg-yellow-500/10" :
                        "text-blue-400 border-blue-500/20 bg-blue-500/10"
                      )}>{item.priority}</span>
                      {item.status_code && <span className="text-[10px] text-[#666]">{item.status_code}</span>}
                    </div>
                    <div className="mt-1.5 h-1.5 w-full bg-[#1a1a1a] rounded-full overflow-hidden">
                      <div className={cn("h-full rounded-full transition-all", barColor)} style={{ width: `${item.score}%` }}></div>
                    </div>
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {item.factors.map((f, j) => (
                        <span key={j} className="text-[10px] px-1.5 py-0.5 bg-[#1a1a1a] border border-[#222] rounded text-[#888]">{f}</span>
                      ))}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// --- Dashboard Component ---
function Dashboard({ liveAgents, liveVulns }: { liveAgents?: any, liveVulns?: Vulnerability[] | null }) {
  const [expandedAgent, setExpandedAgent] = useState<number | null>(null);
  const [todos, setTodos] = useState<TodoItem[]>([]);
  const [secScore, setSecScore] = useState<any>(null);

  // Poll todos
  useEffect(() => {
    let active = true;
    const poll = async () => {
      const res = await api.getTodos();
      if (active && res) setTodos(res.todos);
      const scoreRes = await api.getSecurityScore();
      if (active && scoreRes) setSecScore(scoreRes);
    };
    poll();
    const id = setInterval(poll, 3000);
    return () => { active = false; clearInterval(id); };
  }, []);

  const vulnCount = liveVulns?.length ?? 0;
  const critCount = liveVulns?.filter(v => v.severity === 'critical').length ?? 0;
  const highCount = liveVulns?.filter(v => v.severity === 'high').length ?? 0;
  const medCount = liveVulns?.filter(v => v.severity === 'medium').length ?? 0;
  const lowCount = liveVulns?.filter(v => v.severity === 'low').length ?? 0;
  const agents = liveAgents?.agents ?? [];
  const activeCount = agents.filter((a: any) => a.status === 'running').length;

  const stats = [
    { label: 'Total Agents', value: String(agents.length), icon: Cpu, color: 'text-blue-500' },
    { label: 'Active Tests', value: String(activeCount), icon: Activity, color: 'text-green-500' },
    { label: 'Vulnerabilities', value: String(vulnCount), icon: ShieldAlert, color: 'text-red-500' },
    { label: 'Security Score', value: secScore?.grade || '?', icon: Shield, color: secScore?.grade === 'F' ? 'text-red-500' : secScore?.grade === 'D' ? 'text-orange-500' : secScore?.grade === 'C' ? 'text-yellow-500' : 'text-green-500' },
  ];

  // Show ALL agents, not just running
  const allAgents = agents.map((a: any, i: number) => ({
    id: i + 1,
    name: a.name || a.id,
    target: a.task || '—',
    status: a.status,
    progress: a.progress ?? 0,
    color: ['#3b82f6', '#eab308', '#8b5cf6', '#ef4444', '#22c55e'][i % 5],
    iteration: a.iteration,
    max_iterations: a.max_iterations,
  }));

  const vulnData = [
    { name: 'Critical', value: critCount, color: '#ef4444' },
    { name: 'High', value: highCount, color: '#f97316' },
    { name: 'Medium', value: medCount, color: '#eab308' },
    { name: 'Low', value: lowCount, color: '#3b82f6' },
  ];

  const hasData = vulnCount > 0 || agents.length > 0;

  return (
    <div className="max-w-7xl mx-auto space-y-6 animate-in fade-in duration-300">
      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {stats.map((stat, idx) => (
              <div key={idx} className="bg-[#141414] border border-[#222] rounded-lg p-5 flex justify-between h-[140px]">
                <div className="flex flex-col justify-between">
                  <p className="text-sm text-[#8c8c8c] leading-snug whitespace-pre-line">
                    {stat.label.replace(' ', '\n')}
                  </p>
                  <p className="text-4xl font-bold text-[#f2f2f2] tracking-tight">{stat.value}</p>
                </div>
                <div className="flex items-center">
                  <div className={cn("w-12 h-12 rounded-full bg-[#1a1a1a] flex items-center justify-center", stat.color)}>
                    <stat.icon className="w-6 h-6" strokeWidth={1.5} />
                  </div>
                </div>
              </div>
            ))}
      </div>

      {/* Charts Row — only show if there's data */}
      {hasData ? (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="bg-[#111111] border border-[#222] rounded-lg p-6 shadow-lg lg:col-span-1 flex flex-col">
              <div className="flex items-start justify-between mb-6">
                <h2 className="text-lg font-medium text-[#f2f2f2] italic">Vulnerabilities</h2>
                <div className="flex flex-wrap justify-end gap-x-3 gap-y-2 text-xs max-w-[60%]">
                  {vulnData.map((item, idx) => (
                    <div key={idx} className="flex items-center gap-1.5">
                      <div className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color, boxShadow: `0 0 6px ${item.color}` }}></div>
                      <span className="text-[#8c8c8c]">{item.name}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="flex-1 min-h-[250px] relative flex items-center justify-center">
                <PolarAreaChart data={vulnData} />
              </div>
            </div>

            {/* Live Agent Dispatcher */}
            <div className="bg-[#111111] border border-[#222] rounded-lg shadow-lg lg:col-span-2 flex flex-col overflow-hidden">
              <div className="px-5 py-4 border-b border-[#222] flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-green-400" />
                  <h2 className="text-lg font-medium text-[#f2f2f2]">Agent Dispatcher</h2>
                </div>
                <div className="flex items-center gap-2 text-xs">
                  {activeCount > 0 && <span className="flex items-center gap-1 text-green-400"><span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse"></span>{activeCount} active</span>}
                  <span className="text-[#666]">{allAgents.length} total</span>
                </div>
              </div>
              <div className="flex-1 p-4 overflow-y-auto custom-scrollbar max-h-[300px]">
                {allAgents.length === 0 ? (
                  <div className="text-center py-8 text-[#666] text-xs">No agents spawned yet</div>
                ) : (
                  <div className="space-y-2">
                    {allAgents.map((agent) => {
                      const isRunning = agent.status === 'running';
                      const isDone = agent.status === 'completed' || agent.status === 'finished';
                      const barColor = isRunning ? 'bg-green-500' : isDone ? 'bg-blue-500' : agent.status === 'error' ? 'bg-red-500' : 'bg-[#555]';
                      return (
                        <div key={agent.id} className="flex items-center gap-3 bg-[#0a0a0a] border border-[#1a1a1a] rounded-lg p-3">
                          <div className={cn("w-2 h-2 rounded-full flex-shrink-0", barColor, isRunning && "animate-pulse")}></div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-medium text-[#d4d4d4] truncate">{agent.name}</span>
                              <span className={cn("text-[10px] px-1.5 py-0.5 rounded",
                                isRunning ? "bg-green-500/10 text-green-400" : isDone ? "bg-blue-500/10 text-blue-400" : "bg-[#222] text-[#666]"
                              )}>{agent.status}</span>
                            </div>
                            <div className="text-[10px] text-[#666] mt-0.5 truncate">{agent.target}</div>
                            {agent.progress > 0 && (
                              <div className="mt-1.5 h-1 w-full bg-[#1a1a1a] rounded-full overflow-hidden">
                                <div className={cn("h-full rounded-full transition-all duration-500", barColor)} style={{ width: `${agent.progress}%` }}></div>
                              </div>
                            )}
                          </div>
                          {agent.iteration > 0 && (
                            <span className="text-[10px] text-[#555] flex-shrink-0">{agent.iteration}/{agent.max_iterations}</span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          </div>
        </>
      ) : (
        <div className="bg-[#111111] border border-[#222] rounded-lg p-12 flex flex-col items-center justify-center text-center">
          <ShieldAlert className="w-16 h-16 text-[#333] mb-4" />
          <h3 className="text-lg font-medium text-[#8c8c8c] mb-2">No Active Scans</h3>
          <p className="text-sm text-[#666] max-w-md">Create a new penetration test to start scanning. Results will appear here in real time.</p>
        </div>
      )}

      {/* Vulnerability Timeline */}
      {liveVulns && liveVulns.length > 0 && (
        <div className="bg-[#111111] border border-[#222] rounded-lg shadow-lg overflow-hidden">
          <div className="p-5 border-b border-[#222] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="w-5 h-5 text-red-400" />
              <h2 className="text-lg font-medium text-[#f2f2f2]">Vulnerability Timeline</h2>
            </div>
            <span className="text-xs text-[#666]">{liveVulns.length} findings</span>
          </div>
          <div className="p-5">
            <div className="relative">
              {/* Timeline line */}
              <div className="absolute left-3 top-0 bottom-0 w-px bg-[#222]"></div>
              <div className="space-y-3">
                {liveVulns.slice(0, 20).map((v, i) => {
                  const sevColor = v.severity === 'critical' ? 'bg-red-500' : v.severity === 'high' ? 'bg-orange-500' : v.severity === 'medium' ? 'bg-yellow-500' : 'bg-blue-500';
                  const sevText = v.severity === 'critical' ? 'text-red-400' : v.severity === 'high' ? 'text-orange-400' : v.severity === 'medium' ? 'text-yellow-400' : 'text-blue-400';
                  return (
                    <div key={i} className="flex items-start gap-3 pl-1">
                      <div className={cn("w-5 h-5 rounded-full flex-shrink-0 mt-0.5 flex items-center justify-center", sevColor)}>
                        <span className="text-[9px] font-bold text-white">{i + 1}</span>
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm text-[#d4d4d4] truncate">{v.title}</span>
                          <span className={cn("text-[10px] font-medium uppercase", sevText)}>{v.severity}</span>
                        </div>
                        <div className="flex items-center gap-3 mt-0.5 text-[10px] text-[#666]">
                          {v.target && <span className="font-mono truncate max-w-[200px]">{v.target}</span>}
                          {v.cvss && <span>CVSS {v.cvss}</span>}
                          {v.timestamp && <span>{v.timestamp.slice(11, 19)}</span>}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Agent Todo List */}
      {todos.length > 0 && (
      <div className="bg-[#111111] border border-[#222] rounded-lg shadow-lg overflow-hidden">
        <div className="p-5 border-b border-[#222] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ListTodo className="w-5 h-5 text-[#a855f7]" />
            <h2 className="text-lg font-medium text-[#f2f2f2]">Agent Task Plan</h2>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <span className="text-green-400">{todos.filter(t => t.status === 'done').length} done</span>
            <span className="text-[#555]">/</span>
            <span className="text-[#8c8c8c]">{todos.length} total</span>
          </div>
        </div>
        <div className="divide-y divide-[#1a1a1a] max-h-[400px] overflow-y-auto custom-scrollbar">
          {todos.map((todo) => (
            <div key={todo.id} className="px-5 py-3 flex items-start gap-3 hover:bg-[#1a1a1a] transition-colors">
              <div className={cn(
                "mt-0.5 w-5 h-5 rounded-full border flex items-center justify-center flex-shrink-0",
                todo.status === 'done' ? "border-green-500 bg-green-500/10 text-green-500" :
                todo.status === 'in_progress' ? "border-yellow-500 bg-yellow-500/10 text-yellow-500 animate-pulse" :
                "border-[#444] text-transparent"
              )}>
                {todo.status === 'done' ? <Check className="w-3 h-3" /> :
                 todo.status === 'in_progress' ? <Activity className="w-3 h-3" /> : null}
              </div>
              <div className="flex-1 min-w-0">
                <div className={cn(
                  "text-sm",
                  todo.status === 'done' ? "text-[#666] line-through" : "text-[#d4d4d4]"
                )}>
                  {todo.title}
                </div>
                {todo.description && (
                  <div className="text-xs text-[#666] mt-0.5 truncate">{todo.description}</div>
                )}
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                {todo.priority !== 'normal' && (
                  <span className={cn(
                    "text-[10px] px-1.5 py-0.5 rounded border",
                    todo.priority === 'critical' ? "text-red-400 border-red-500/20 bg-red-500/10" :
                    todo.priority === 'high' ? "text-orange-400 border-orange-500/20 bg-orange-500/10" :
                    "text-blue-400 border-blue-500/20 bg-blue-500/10"
                  )}>
                    {todo.priority}
                  </span>
                )}
                <span className="text-[10px] text-[#555]">{todo.agent_name}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
      )}

      {/* All Agents */}
      {allAgents.length > 0 && (
      <div className="bg-[#111111] border border-[#222] rounded-lg shadow-lg overflow-hidden">
        <div className="p-5 border-b border-[#222] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Cpu className="w-5 h-5 text-[#a855f7]" />
            <h2 className="text-lg font-medium text-[#f2f2f2]">Agents</h2>
          </div>
          <div className="flex items-center gap-2">
            {activeCount > 0 && (
              <span className="text-xs font-medium bg-green-500/10 text-green-400 px-2.5 py-1 rounded-full border border-green-500/20">
                {activeCount} running
              </span>
            )}
            <span className="text-xs font-medium bg-[#a855f7]/10 text-[#a855f7] px-2.5 py-1 rounded-full border border-[#a855f7]/20">
              {allAgents.length} total
            </span>
          </div>
        </div>
        <div className="divide-y divide-[#222]">
          {allAgents.map((agent) => {
            const statusColor = agent.status === 'running' ? 'bg-green-500' :
              agent.status === 'completed' || agent.status === 'finished' ? 'bg-blue-500' :
              agent.status === 'waiting' ? 'bg-yellow-500' :
              agent.status === 'error' || agent.status === 'failed' ? 'bg-red-500' :
              agent.status === 'stopping' || agent.status === 'stopped' ? 'bg-orange-500' : 'bg-[#555]';
            const isRunning = agent.status === 'running';

            return (
              <div key={agent.id} className="p-4 flex items-center justify-between hover:bg-[#1a1a1a] transition-colors">
                <div className="flex items-center gap-4">
                  <div className="relative">
                    <div className="w-10 h-10 rounded-lg bg-[#222] flex items-center justify-center border border-[#333]">
                      <Terminal className="w-5 h-5" style={{ color: agent.color }} />
                    </div>
                    <span className={cn(
                      "absolute -bottom-1 -right-1 w-3 h-3 rounded-full border-2 border-[#111111]",
                      statusColor,
                      isRunning && "animate-pulse"
                    )}></span>
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-[#f2f2f2]">{agent.name}</h3>
                    <div className="flex items-center gap-3 mt-1 text-xs text-[#8c8c8c]">
                      <span className="truncate max-w-[300px]">{agent.target}</span>
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <span className={cn(
                    "text-xs px-2 py-0.5 rounded border",
                    isRunning ? "text-green-400 border-green-500/20 bg-green-500/10" :
                    agent.status === 'completed' || agent.status === 'finished' ? "text-blue-400 border-blue-500/20 bg-blue-500/10" :
                    agent.status === 'error' || agent.status === 'failed' ? "text-red-400 border-red-500/20 bg-red-500/10" :
                    "text-[#8c8c8c] border-[#333] bg-[#222]"
                  )}>
                    {agent.status}
                  </span>
                  {agent.progress > 0 && (
                    <div className="w-20 hidden sm:block">
                      <div className="flex justify-between text-[10px] text-[#8c8c8c] mb-1">
                        <span>{agent.progress}%</span>
                      </div>
                      <div className="h-1.5 w-full bg-[#222] rounded-full overflow-hidden">
                        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${agent.progress}%`, backgroundColor: agent.color }}></div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
      )}
    </div>
  );
}

// --- Screenshots Gallery Component ---

function ScreenshotsGallery() {
  const [data, setData] = useState<ScreenshotsResponse | null>(null);
  const [filter, setFilter] = useState<'all' | 'alive' | 'down' | 'unprobed'>('all');

  useEffect(() => {
    let active = true;
    const poll = async () => {
      const res = await api.getScreenshots();
      if (active && res) setData(res);
    };
    poll();
    const id = setInterval(poll, 5000);
    return () => { active = false; clearInterval(id); };
  }, []);

  const cards = data?.screenshots ?? [];
  const filtered = filter === 'all' ? cards
    : filter === 'alive' ? cards.filter(c => c.alive === true)
    : filter === 'down' ? cards.filter(c => c.alive === false)
    : cards.filter(c => c.alive === null);

  const aliveCount = cards.filter(c => c.alive === true).length;
  const downCount = cards.filter(c => c.alive === false).length;
  const unprobedCount = cards.filter(c => c.alive === null).length;

  return (
    <div className="space-y-6 max-w-7xl mx-auto animate-in fade-in duration-500">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-medium text-[#f2f2f2]">Web Screenshots</h2>
          <p className="text-[#8c8c8c] text-sm mt-1">Visual overview of discovered web assets and their status.</p>
        </div>
        <div className="flex items-center gap-2">
          {[
            { key: 'all' as const, label: 'All', count: cards.length },
            { key: 'alive' as const, label: 'Alive', count: aliveCount },
            { key: 'down' as const, label: 'Down', count: downCount },
            { key: 'unprobed' as const, label: 'Unprobed', count: unprobedCount },
          ].map(f => (
            <button key={f.key} onClick={() => setFilter(f.key)} className={cn(
              "px-3 py-1.5 rounded text-xs font-medium transition-colors",
              filter === f.key ? "bg-[#a855f7]/20 text-[#a855f7] border border-[#a855f7]/30" : "text-[#8c8c8c] hover:text-[#d4d4d4] border border-transparent hover:border-[#333]"
            )}>
              {f.label} <span className="text-[10px] ml-1 opacity-60">({f.count})</span>
            </button>
          ))}
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 text-[#8c8c8c]">
          <Camera className="w-16 h-16 text-[#333] mb-4" />
          <h3 className="text-lg font-medium mb-2">No Web Assets</h3>
          <p className="text-sm text-[#666]">Start a scan to discover web assets and their status.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filtered.map((card, i) => {
            const statusColor = card.alive === true ? 'border-green-500/30 bg-green-500/5' : card.alive === false ? 'border-red-500/30 bg-red-500/5' : 'border-[#333] bg-[#111]';
            const domain = card.url.replace(/^https?:\/\//, '').split('/')[0];
            return (
              <div key={i} className={cn("border rounded-lg overflow-hidden transition-all hover:border-[#444]", statusColor)}>
                {/* Screenshot or gradient placeholder */}
                <div className="h-44 relative overflow-hidden">
                  {card.screenshot ? (
                    <img
                      src={`data:image/png;base64,${card.screenshot}`}
                      alt={domain}
                      className="w-full h-full object-cover object-top"
                    />
                  ) : (
                    <div className="w-full h-full bg-gradient-to-br from-[#1a1a2e] via-[#16213e] to-[#0f3460] flex items-center justify-center">
                      <div className="text-center">
                        <Globe className="w-8 h-8 text-[#555] mx-auto mb-2" />
                        <span className="text-xs font-mono text-[#888]">{domain}</span>
                      </div>
                    </div>
                  )}
                  {/* Status indicator */}
                  <div className="absolute top-2 right-2">
                    {card.alive === true ? <Wifi className="w-4 h-4 text-green-400 drop-shadow-lg" /> : card.alive === false ? <WifiOff className="w-4 h-4 text-red-400 drop-shadow-lg" /> : <span className="w-3 h-3 rounded-full bg-[#555] block" />}
                  </div>
                  {card.status_code && (
                    <div className="absolute top-2 left-2">
                      <span className={cn("text-[10px] font-mono px-1.5 py-0.5 rounded backdrop-blur-sm", card.status_code < 400 ? "bg-green-500/30 text-green-300" : "bg-red-500/30 text-red-300")}>
                        {card.status_code}
                      </span>
                    </div>
                  )}
                </div>
                <div className="p-3 space-y-2">
                  <div className="flex items-center gap-2">
                    <a href={card.url} target="_blank" rel="noopener" className="text-sm text-[#a855f7] hover:text-[#c084fc] font-mono truncate flex-1 transition-colors">
                      {card.url}
                    </a>
                    <ExternalLink className="w-3 h-3 text-[#666] flex-shrink-0" />
                  </div>
                  {card.title && <div className="text-xs text-[#8c8c8c] truncate">{card.title}</div>}
                  {card.technologies.length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {card.technologies.slice(0, 4).map((t, j) => (
                        <span key={j} className="text-[10px] px-1.5 py-0.5 bg-[#1a1a1a] border border-[#333] rounded text-[#999]">{t}</span>
                      ))}
                      {card.technologies.length > 4 && <span className="text-[10px] text-[#666]">+{card.technologies.length - 4}</span>}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// --- MITRE ATT&CK Heatmap Component ---

const MITRE_TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance' },
  { id: 'TA0042', name: 'Resource Development' },
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0011', name: 'Command and Control' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0040', name: 'Impact' },
];

// Map vulnerability types to MITRE tactics/techniques
function mapVulnsToMitre(vulns: Vulnerability[]): MitreHit[] {
  const hits: MitreHit[] = [];
  const seen = new Set<string>();

  const mappings: { pattern: RegExp; tactic: string; tacticId: string; technique: string; techniqueId: string }[] = [
    { pattern: /sql.?inject/i, tactic: 'Initial Access', tacticId: 'TA0001', technique: 'Exploit Public-Facing App', techniqueId: 'T1190' },
    { pattern: /xss|cross.?site.?script/i, tactic: 'Initial Access', tacticId: 'TA0001', technique: 'Drive-by Compromise', techniqueId: 'T1189' },
    { pattern: /rce|remote.?code|command.?inject/i, tactic: 'Execution', tacticId: 'TA0002', technique: 'Command & Scripting', techniqueId: 'T1059' },
    { pattern: /ssrf|server.?side.?request/i, tactic: 'Initial Access', tacticId: 'TA0001', technique: 'Exploit Public-Facing App', techniqueId: 'T1190' },
    { pattern: /auth.?bypass|broken.?auth/i, tactic: 'Initial Access', tacticId: 'TA0001', technique: 'Valid Accounts', techniqueId: 'T1078' },
    { pattern: /idor|insecure.?direct/i, tactic: 'Collection', tacticId: 'TA0009', technique: 'Data from Info Repos', techniqueId: 'T1213' },
    { pattern: /lfi|local.?file|path.?travers/i, tactic: 'Collection', tacticId: 'TA0009', technique: 'Data from Local System', techniqueId: 'T1005' },
    { pattern: /csrf|cross.?site.?request.?forg/i, tactic: 'Initial Access', tacticId: 'TA0001', technique: 'Phishing', techniqueId: 'T1566' },
    { pattern: /privil.?escalat|priv.?esc/i, tactic: 'Privilege Escalation', tacticId: 'TA0004', technique: 'Exploitation for Priv Esc', techniqueId: 'T1068' },
    { pattern: /credential|password|brute/i, tactic: 'Credential Access', tacticId: 'TA0006', technique: 'Brute Force', techniqueId: 'T1110' },
    { pattern: /informat.?disclos|sensitive.?data|expos/i, tactic: 'Discovery', tacticId: 'TA0007', technique: 'System Info Discovery', techniqueId: 'T1082' },
    { pattern: /open.?redirect/i, tactic: 'Initial Access', tacticId: 'TA0001', technique: 'Phishing', techniqueId: 'T1566' },
    { pattern: /header.?inject|crlf/i, tactic: 'Defense Evasion', tacticId: 'TA0005', technique: 'Indicator Removal', techniqueId: 'T1070' },
    { pattern: /deserializ/i, tactic: 'Execution', tacticId: 'TA0002', technique: 'Exploitation for Client Exec', techniqueId: 'T1203' },
    { pattern: /xxe|xml.?extern/i, tactic: 'Collection', tacticId: 'TA0009', technique: 'Data from Local System', techniqueId: 'T1005' },
    { pattern: /upload|file.?upload/i, tactic: 'Persistence', tacticId: 'TA0003', technique: 'Server Software Component', techniqueId: 'T1505' },
    { pattern: /dos|denial.?of.?service/i, tactic: 'Impact', tacticId: 'TA0040', technique: 'Endpoint DoS', techniqueId: 'T1499' },
    { pattern: /subdomain|dns/i, tactic: 'Reconnaissance', tacticId: 'TA0043', technique: 'Active Scanning', techniqueId: 'T1595' },
    { pattern: /cors|cross.?origin/i, tactic: 'Collection', tacticId: 'TA0009', technique: 'Browser Session Hijack', techniqueId: 'T1185' },
    { pattern: /jwt|token/i, tactic: 'Credential Access', tacticId: 'TA0006', technique: 'Steal Web Session Cookie', techniqueId: 'T1539' },
  ];

  for (const v of vulns) {
    const text = `${v.title} ${v.description || ''} ${v.cwe || ''}`;
    for (const m of mappings) {
      if (m.pattern.test(text)) {
        const key = `${m.techniqueId}-${v.id}`;
        if (seen.has(key)) continue;
        seen.add(key);

        const existing = hits.find(h => h.technique_id === m.techniqueId);
        if (existing) {
          existing.count++;
          existing.vulns.push(v.title);
          if (['critical', 'high'].includes(v.severity?.toLowerCase())) existing.severity = v.severity.toLowerCase();
        } else {
          hits.push({
            tactic_id: m.tacticId,
            tactic: m.tactic,
            technique_id: m.techniqueId,
            technique: m.technique,
            count: 1,
            severity: v.severity?.toLowerCase() || 'info',
            vulns: [v.title],
          });
        }
      }
    }
  }

  return hits;
}

function MitreHeatmap() {
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [selectedTechnique, setSelectedTechnique] = useState<MitreHit | null>(null);

  const vulnFetcher = useCallback(() => api.getVulnerabilities(), []);
  useEffect(() => {
    let active = true;
    const poll = async () => {
      const res = await vulnFetcher();
      if (active && res) setVulns(res);
    };
    poll();
    const id = setInterval(poll, 5000);
    return () => { active = false; clearInterval(id); };
  }, [vulnFetcher]);

  const hits = mapVulnsToMitre(vulns);
  const hitsByTactic: Record<string, MitreHit[]> = {};
  for (const h of hits) {
    if (!hitsByTactic[h.tactic_id]) hitsByTactic[h.tactic_id] = [];
    hitsByTactic[h.tactic_id].push(h);
  }

  const coveredTactics = new Set(hits.map(h => h.tactic_id));

  return (
    <div className="space-y-6 max-w-full mx-auto animate-in fade-in duration-500">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-medium text-[#f2f2f2]">MITRE ATT&CK Mapping</h2>
          <p className="text-[#8c8c8c] text-sm mt-1">Vulnerabilities mapped to MITRE ATT&CK tactics and techniques.</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs bg-[#a855f7]/10 text-[#a855f7] px-2.5 py-1 rounded-full border border-[#a855f7]/20">
            {hits.length} techniques
          </span>
          <span className="text-xs bg-blue-500/10 text-blue-400 px-2.5 py-1 rounded-full border border-blue-500/20">
            {coveredTactics.size}/{MITRE_TACTICS.length} tactics
          </span>
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 text-xs">
        <span className="text-[#666]">Severity:</span>
        <div className="flex items-center gap-1"><span className="w-3 h-3 rounded-sm bg-red-500/80"></span><span className="text-[#8c8c8c]">Critical</span></div>
        <div className="flex items-center gap-1"><span className="w-3 h-3 rounded-sm bg-orange-500/80"></span><span className="text-[#8c8c8c]">High</span></div>
        <div className="flex items-center gap-1"><span className="w-3 h-3 rounded-sm bg-yellow-500/60"></span><span className="text-[#8c8c8c]">Medium</span></div>
        <div className="flex items-center gap-1"><span className="w-3 h-3 rounded-sm bg-blue-500/50"></span><span className="text-[#8c8c8c]">Low</span></div>
        <div className="flex items-center gap-1"><span className="w-3 h-3 rounded-sm bg-[#222]"></span><span className="text-[#8c8c8c]">Not hit</span></div>
      </div>

      {hits.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 text-[#8c8c8c]">
          <Grid3X3 className="w-16 h-16 text-[#333] mb-4" />
          <h3 className="text-lg font-medium mb-2">No MITRE Mappings</h3>
          <p className="text-sm text-[#666]">Vulnerabilities will be mapped to MITRE ATT&CK as they are discovered.</p>
        </div>
      ) : (
        <div className="flex gap-1 overflow-x-auto custom-scrollbar pb-2">
          {MITRE_TACTICS.map(tactic => {
            const tacticHits = hitsByTactic[tactic.id] || [];
            const isActive = tacticHits.length > 0;
            return (
              <div key={tactic.id} className="flex-shrink-0 w-[120px]">
                {/* Tactic header */}
                <div className={cn(
                  "text-center py-2 px-1 rounded-t-lg border border-b-0 text-[10px] font-medium",
                  isActive ? "bg-[#1a1a1a] border-[#333] text-[#d4d4d4]" : "bg-[#0d0d0d] border-[#1a1a1a] text-[#555]"
                )}>
                  <div className="truncate" title={tactic.name}>{tactic.name}</div>
                  <div className="text-[9px] text-[#666] mt-0.5">{tactic.id}</div>
                </div>
                {/* Technique cells */}
                <div className="border border-t-0 border-[#222] rounded-b-lg overflow-hidden min-h-[80px] bg-[#0a0a0a]">
                  {tacticHits.length === 0 ? (
                    <div className="h-20 flex items-center justify-center">
                      <span className="w-6 h-6 rounded bg-[#151515] block"></span>
                    </div>
                  ) : (
                    <div className="p-1 space-y-1">
                      {tacticHits.map((h, i) => {
                        const bg = h.severity === 'critical' ? 'bg-red-500/30 border-red-500/40 hover:bg-red-500/40' :
                          h.severity === 'high' ? 'bg-orange-500/25 border-orange-500/35 hover:bg-orange-500/35' :
                          h.severity === 'medium' ? 'bg-yellow-500/20 border-yellow-500/30 hover:bg-yellow-500/30' :
                          'bg-blue-500/15 border-blue-500/25 hover:bg-blue-500/25';
                        return (
                          <button
                            key={i}
                            onClick={() => setSelectedTechnique(selectedTechnique?.technique_id === h.technique_id ? null : h)}
                            className={cn("w-full text-left px-1.5 py-1 rounded border text-[9px] transition-colors cursor-pointer", bg)}
                          >
                            <div className="font-mono text-[#d4d4d4] truncate">{h.technique_id}</div>
                            <div className="text-[#999] truncate">{h.technique}</div>
                            {h.count > 1 && <div className="text-[8px] text-[#666]">{h.count} hits</div>}
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Selected technique detail */}
      {selectedTechnique && (
        <div className="bg-[#111] border border-[#222] rounded-lg p-4 animate-in slide-in-from-top-2 duration-200">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3">
              <span className="text-sm font-mono text-[#a855f7]">{selectedTechnique.technique_id}</span>
              <span className="text-sm text-[#f2f2f2]">{selectedTechnique.technique}</span>
              <span className="text-xs text-[#666]">({selectedTechnique.tactic})</span>
            </div>
            <button onClick={() => setSelectedTechnique(null)} className="text-[#666] hover:text-[#999]"><X className="w-4 h-4" /></button>
          </div>
          <div className="text-xs text-[#8c8c8c] mb-2">Matching vulnerabilities:</div>
          <div className="space-y-1">
            {selectedTechnique.vulns.map((v, i) => (
              <div key={i} className="flex items-center gap-2 text-xs">
                <span className="w-1.5 h-1.5 rounded-full bg-red-400 flex-shrink-0"></span>
                <span className="text-[#d4d4d4]">{v}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// --- HTTP Request Log Component (mini-Burp) ---

function HttpRequestLog() {
  const [toolEvents, setToolEvents] = useState<ToolEvent[]>([]);
  const [selectedEntry, setSelectedEntry] = useState<ToolEvent | null>(null);
  const [filterText, setFilterText] = useState('');
  const [filterTool, setFilterTool] = useState<string>('all');

  useEffect(() => {
    let active = true;
    const poll = async () => {
      const res = await api.getAgentEvents(0);
      if (active && res) setToolEvents(res.tool_events);
    };
    poll();
    const id = setInterval(poll, 2000);
    return () => { active = false; clearInterval(id); };
  }, []);

  // Extract HTTP-related tools
  const httpTools = toolEvents.filter(t => {
    const name = t.tool_name.toLowerCase();
    return name.includes('http') || name.includes('request') || name.includes('curl') ||
      name.includes('fetch') || name.includes('browse') || name.includes('scan') ||
      name.includes('nmap') || name.includes('nuclei') || name.includes('subfinder') ||
      name.includes('httpx') || name.includes('execute_command') || name.includes('bash') ||
      name.includes('web');
  });

  const allTools = [...new Set(toolEvents.map(t => t.tool_name))].sort();

  const filtered = (filterTool === 'all' ? toolEvents : toolEvents.filter(t => t.tool_name === filterTool))
    .filter(t => !filterText || t.tool_name.toLowerCase().includes(filterText.toLowerCase()) || t.args_summary.toLowerCase().includes(filterText.toLowerCase()) || t.agent_name.toLowerCase().includes(filterText.toLowerCase()));

  const formatTime = (ts: string) => {
    if (!ts) return '';
    try {
      return new Date(ts).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch { return ''; }
  };

  const getMethodColor = (tool: string) => {
    if (/http|request|fetch|curl|browse|web/i.test(tool)) return 'text-green-400';
    if (/nmap|scan/i.test(tool)) return 'text-blue-400';
    if (/nuclei/i.test(tool)) return 'text-red-400';
    if (/subfinder|dns/i.test(tool)) return 'text-yellow-400';
    return 'text-[#8c8c8c]';
  };

  return (
    <div className="h-full flex flex-col animate-in fade-in duration-300 -m-6 lg:-m-8">
      {/* Header bar */}
      <div className="flex items-center justify-between px-5 py-3 bg-[#111111] border-b border-[#222] flex-shrink-0">
        <div className="flex items-center gap-3">
          <Layers className="w-4 h-4 text-[#a855f7]" />
          <span className="text-sm font-medium text-[#f2f2f2]">HTTP Request Log</span>
          <span className="text-xs text-[#666]">({filtered.length} entries)</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3 h-3 absolute left-2 top-1/2 -translate-y-1/2 text-[#666]" />
            <input
              value={filterText}
              onChange={e => setFilterText(e.target.value)}
              placeholder="Filter..."
              className="bg-[#0a0a0a] border border-[#333] rounded pl-7 pr-3 py-1 text-xs text-[#d4d4d4] w-48 focus:outline-none focus:border-[#a855f7]/50"
            />
          </div>
          <select
            value={filterTool}
            onChange={e => setFilterTool(e.target.value)}
            className="bg-[#0a0a0a] border border-[#333] rounded px-2 py-1 text-xs text-[#d4d4d4] focus:outline-none"
          >
            <option value="all">All tools</option>
            {allTools.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
      </div>

      <div className="flex-1 flex overflow-hidden">
        {/* Request list */}
        <div className="flex-1 overflow-y-auto custom-scrollbar bg-[#0a0a0a]">
          {/* Header */}
          <div className="grid grid-cols-[60px_100px_140px_80px_1fr] gap-2 px-4 py-2 text-[10px] text-[#666] uppercase tracking-wider border-b border-[#222] sticky top-0 bg-[#0a0a0a] z-10">
            <span>Time</span>
            <span>Agent</span>
            <span>Tool</span>
            <span>Status</span>
            <span>Details</span>
          </div>
          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-[#666]">
              <Layers className="w-12 h-12 mb-4 text-[#333]" />
              <p className="text-sm">No tool calls recorded</p>
            </div>
          ) : (
            [...filtered].reverse().map((entry, i) => (
              <div
                key={entry.execution_id ?? i}
                onClick={() => setSelectedEntry(selectedEntry?.execution_id === entry.execution_id ? null : entry)}
                className={cn(
                  "grid grid-cols-[60px_100px_140px_80px_1fr] gap-2 px-4 py-2 text-xs font-mono cursor-pointer transition-colors border-b border-[#111]",
                  selectedEntry?.execution_id === entry.execution_id ? "bg-[#1a1a2e]" : "hover:bg-[#111]"
                )}
              >
                <span className="text-[#555]">{formatTime(entry.started_at)}</span>
                <span className="text-[#a855f7] truncate">{entry.agent_name}</span>
                <span className={cn("truncate", getMethodColor(entry.tool_name))}>{entry.tool_name}</span>
                <span className={cn(
                  entry.status === 'completed' ? 'text-green-400' : entry.status === 'running' ? 'text-yellow-400' : entry.status === 'error' ? 'text-red-400' : 'text-[#666]'
                )}>
                  {entry.status === 'running' ? '...' : entry.status}
                </span>
                <span className="text-[#888] truncate">{entry.args_summary}</span>
              </div>
            ))
          )}
        </div>

        {/* Detail pane */}
        {selectedEntry && (
          <div className="w-80 flex-shrink-0 border-l border-[#222] bg-[#111] overflow-y-auto custom-scrollbar">
            <div className="px-4 py-3 bg-[#141414] border-b border-[#222] flex items-center justify-between">
              <span className="text-sm font-medium text-[#f2f2f2]">Detail</span>
              <button onClick={() => setSelectedEntry(null)} className="text-[#666] hover:text-[#999]"><X className="w-3.5 h-3.5" /></button>
            </div>
            <div className="p-4 space-y-3 text-xs overflow-y-auto custom-scrollbar" style={{scrollbarWidth:'none'}}>
              <div><span className="text-[#666]">Agent:</span> <span className="text-[#a855f7] ml-1">{selectedEntry.agent_name}</span></div>
              <div><span className="text-[#666]">Tool:</span> <span className={cn("ml-1", getMethodColor(selectedEntry.tool_name))}>{selectedEntry.tool_name}</span></div>
              <div><span className="text-[#666]">Status:</span> <span className="text-[#d4d4d4] ml-1">{selectedEntry.status}</span></div>
              <div><span className="text-[#666]">Started:</span> <span className="text-[#d4d4d4] ml-1">{formatTime(selectedEntry.started_at)}</span></div>
              {selectedEntry.completed_at && <div><span className="text-[#666]">Completed:</span> <span className="text-[#d4d4d4] ml-1">{formatTime(selectedEntry.completed_at)}</span></div>}
              {selectedEntry.args_summary && (
                <div>
                  <span className="text-[#666]">Arguments:</span>
                  <pre className="mt-1 p-2 bg-[#0a0a0a] rounded border border-[#222] text-[#c0c0c0] whitespace-pre-wrap break-all text-[10px] max-h-[150px] overflow-y-auto">{selectedEntry.args_summary}</pre>
                </div>
              )}
              {(selectedEntry as any).result_summary && (
                <div>
                  <span className="text-[#666]">Output:</span>
                  <pre className="mt-1 p-2 bg-[#0a120a] rounded border border-[#1a2a1a] text-[#6a9a6a] whitespace-pre-wrap break-all text-[10px] max-h-[200px] overflow-y-auto">{(selectedEntry as any).result_summary}</pre>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Status bar */}
      <div className="flex items-center justify-between px-4 py-1.5 bg-[#111111] border-t border-[#222] text-[10px] text-[#666] font-mono flex-shrink-0">
        <span>total: {toolEvents.length} calls</span>
        <span>http-related: {httpTools.length}</span>
        <span>poll: 2s</span>
      </div>
    </div>
  );
}

// --- Settings Page ---

function SettingsPage() {
  const [services, setServices] = useState<any[]>([]);
  const [keys, setKeys] = useState<Record<string, string>>({});
  const [editKeys, setEditKeys] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [configuredCount, setConfiguredCount] = useState(0);
  const [ultraMode, setUltraMode] = useState(false);
  const [lang, setLang] = useState('en');
  const [persona, setPersona] = useState('red_team');

  useEffect(() => {
    const load = async () => {
      const res = await fetch('/api/settings').then(r => r.json()).catch(() => null);
      if (res) {
        setServices(res.services || []);
        setKeys(res.keys || {});
        setEditKeys({});
        setConfiguredCount(res.configured_count || 0);
        setUltraMode(res.ultra_mode || false);
        setLang(res.language || 'en');
        setPersona(res.persona || 'red_team');
      }
    };
    load();
  }, []);

  const toggleUltraMode = async () => {
    const newVal = !ultraMode;
    setUltraMode(newVal);
    await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ultra_mode: newVal }),
    });
  };

  const handleSave = async () => {
    setSaving(true);
    const payload: Record<string, string> = {};
    for (const svc of services) {
      const val = editKeys[svc.id];
      if (val !== undefined) {
        payload[svc.id] = val;
      }
    }
    const res = await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ keys: payload }),
    }).then(r => r.json()).catch(() => null);
    if (res) {
      setConfiguredCount(res.configured_count || 0);
      // Reload to get masked values
      const fresh = await fetch('/api/settings').then(r => r.json()).catch(() => null);
      if (fresh) {
        setKeys(fresh.keys || {});
        setEditKeys({});
      }
    }
    setSaving(false);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="space-y-6 max-w-3xl mx-auto animate-in fade-in duration-500">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-medium text-[#f2f2f2]">Settings</h2>
          <p className="text-[#8c8c8c] text-sm mt-1">API keys for enhanced reconnaissance and intelligence gathering.</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs bg-[#a855f7]/10 text-[#a855f7] px-2.5 py-1 rounded-full border border-[#a855f7]/20">
            {configuredCount} / {services.length} configured
          </span>
          <button
            onClick={handleSave}
            disabled={saving || Object.keys(editKeys).length === 0}
            className={cn(
              "px-4 py-2 rounded-lg text-sm font-medium transition-all",
              Object.keys(editKeys).length > 0
                ? "bg-[#a855f7] hover:bg-[#c084fc] text-white"
                : "bg-[#222] text-[#666] cursor-not-allowed"
            )}
          >
            {saving ? 'Saving...' : saved ? '✓ Saved' : 'Save Keys'}
          </button>
        </div>
      </div>

      {/* Ultra Mode */}
      <div className={cn(
        "border rounded-lg p-5 transition-all",
        ultraMode ? "border-orange-500/50 bg-orange-500/5" : "border-[#222] bg-[#111]"
      )}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={cn("w-10 h-10 rounded-lg flex items-center justify-center", ultraMode ? "bg-orange-500/20" : "bg-[#222]")}>
              <Zap className={cn("w-5 h-5", ultraMode ? "text-orange-400" : "text-[#666]")} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-medium text-[#f2f2f2]">Ultra Mode</h3>
                {ultraMode && <span className="text-[10px] px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-400 border border-orange-500/30 font-medium">ACTIVE</span>}
              </div>
              <p className="text-xs text-[#888] mt-0.5">Advanced structured testing with specialized agents</p>
            </div>
          </div>
          <button
            onClick={toggleUltraMode}
            className={cn(
              "relative inline-flex items-center w-11 h-6 rounded-full transition-colors flex-shrink-0",
              ultraMode ? "bg-orange-500" : "bg-[#333]"
            )}
          >
            <span className={cn(
              "inline-block w-4 h-4 rounded-full bg-white transition-transform",
              ultraMode ? "translate-x-6" : "translate-x-1"
            )}></span>
          </button>
        </div>
        {ultraMode && (
          <div className="mt-4">
            <div className="grid grid-cols-5 gap-2">
            {[
              { name: 'Injection', desc: 'SQLi, CMDi, SSTI' },
              { name: 'XSS', desc: 'Reflected, Stored, DOM' },
              { name: 'Auth', desc: 'Bypass, JWT, Session' },
              { name: 'SSRF', desc: 'Cloud, Internal' },
              { name: 'AuthZ', desc: 'IDOR, Priv. Esc.' },
              { name: 'API Fuzz', desc: 'Params, Types' },
              { name: 'Logic', desc: 'Race, State' },
              { name: 'Recon', desc: 'Crawl, JS, Secrets' },
              { name: 'WAF', desc: 'Bypass, 403' },
              { name: 'Cache', desc: 'Poison, Smuggle' },
            ].map((a, i) => (
              <div key={i} className="bg-[#0a0a0a] border border-orange-500/20 rounded p-2 text-center">
                <div className="text-[10px] font-medium text-orange-300">{a.name}</div>
                <div className="text-[9px] text-[#666] mt-0.5">{a.desc}</div>
              </div>
            ))}
            </div>
            <p className="text-[9px] text-[#555] mt-2 text-center">8-15 agents spawned per scan based on target</p>
          </div>
        )}
      </div>

      {/* Persona */}
      <div className="bg-[#111] border border-[#222] rounded-lg p-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Crosshair className="w-5 h-5 text-red-400" />
          <div>
            <h3 className="text-sm font-medium text-[#f2f2f2]">Agent Persona</h3>
            <p className="text-xs text-[#888] mt-0.5">How the AI approaches testing</p>
          </div>
        </div>
        <div className="flex items-center gap-1 bg-[#0a0a0a] rounded-lg p-1 border border-[#222]">
          {([
            { id: 'red_team', label: 'Red Team', Icon: Crosshair, color: 'text-red-400' },
            { id: 'blue_team', label: 'Blue Team', Icon: Shield, color: 'text-blue-400' },
            { id: 'bug_bounty', label: 'Bug Bounty', Icon: Bug, color: 'text-green-400' },
          ] as const).map(p => (
            <button key={p.id} onClick={async () => {
              setPersona(p.id);
              await fetch('/api/settings', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({persona: p.id}) });
            }} className={cn("px-3 py-1.5 rounded text-xs font-medium transition-colors flex items-center gap-1.5", persona === p.id ? "bg-[#a855f7] text-white" : "text-[#888] hover:text-[#d4d4d4]")}>
              <p.Icon className="w-3 h-3" /> {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* Rate Limit */}
      <div className="bg-[#111] border border-[#222] rounded-lg p-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Clock className="w-5 h-5 text-yellow-400" />
          <div>
            <h3 className="text-sm font-medium text-[#f2f2f2]">AI Rate Limit</h3>
            <p className="text-xs text-[#888] mt-0.5">Max requests per minute to LLM provider (0 = unlimited)</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <input
            type="number"
            min="0"
            max="1000"
            defaultValue={(window as any).__rpmLimit || 0}
            ref={el => { if (el) { fetch('/api/settings').then(r=>r.json()).then(d => { el.value = String(d.rpm_limit || 0); (window as any).__rpmLimit = d.rpm_limit || 0; }); } }}
            onChange={async (e) => {
              const rpm = parseInt(e.target.value) || 0;
              await fetch('/api/settings', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({rpm_limit: rpm}) });
            }}
            className="w-20 bg-[#0a0a0a] border border-[#333] rounded px-3 py-1.5 text-sm text-center text-[#d4d4d4] font-mono focus:outline-none focus:border-[#a855f7]/50"
          />
          <span className="text-xs text-[#666]">req/min</span>
        </div>
      </div>

      {/* Info */}
      <div className="bg-[#111] border border-[#222] rounded-lg p-4 text-xs text-[#888] flex items-start gap-3">
        <Info className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
        <div>
          <p>API keys are stored locally in <code className="text-[#a855f7]">~/.ziro/settings.json</code> and used during reconnaissance.</p>
          <p className="mt-1">All keys have free tiers. Adding Shodan + SecurityTrails significantly improves discovery.</p>
        </div>
      </div>

      <div className="space-y-3">
        {services.map((svc: any) => {
          const currentValue = editKeys[svc.id] !== undefined ? editKeys[svc.id] : (keys[svc.id] || '');
          const isConfigured = keys[svc.id] && keys[svc.id] !== '';
          const isEdited = editKeys[svc.id] !== undefined;

          return (
            <div key={svc.id} className={cn("bg-[#111] border rounded-lg p-4 transition-colors", isConfigured ? "border-green-500/20" : "border-[#222]")}>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  {isConfigured && <span className="w-2 h-2 rounded-full bg-green-500 flex-shrink-0"></span>}
                  <span className="text-sm font-medium text-[#f2f2f2]">{svc.name}</span>
                  <span className="text-[10px] text-[#666] bg-[#1a1a1a] px-1.5 py-0.5 rounded">{svc.free}</span>
                </div>
                <a href={svc.url} target="_blank" rel="noopener" className="text-[10px] text-[#a855f7] hover:text-[#c084fc] flex items-center gap-1">
                  Get key <ExternalLink className="w-2.5 h-2.5" />
                </a>
              </div>
              <p className="text-xs text-[#666] mb-2">{svc.desc}</p>
              <input
                type="password"
                value={currentValue}
                onChange={e => setEditKeys(prev => ({ ...prev, [svc.id]: e.target.value }))}
                onFocus={e => {
                  if (keys[svc.id] && !editKeys[svc.id]) {
                    setEditKeys(prev => ({ ...prev, [svc.id]: '' }));
                  }
                }}
                placeholder={isConfigured ? '••••••••' : `Enter ${svc.name} API key...`}
                className={cn(
                  "w-full bg-[#0a0a0a] border rounded px-3 py-2 text-xs font-mono text-[#d4d4d4] focus:outline-none transition-colors",
                  isEdited ? "border-[#a855f7]/50 focus:border-[#a855f7]" : "border-[#333] focus:border-[#444]"
                )}
              />
            </div>
          );
        })}
      </div>
    </div>
  );
}

// --- AI Chat Tab ---

function AiChat() {
  const [messages, setMessages] = useState<{role: string; content: string; time: string}[]>([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const chatRef = useRef<HTMLDivElement>(null);

  const [scanActive, setScanActive] = useState(false);

  // Poll agent messages to show responses
  useEffect(() => {
    let active = true;
    const poll = async () => {
      const [res, statusRes] = await Promise.all([api.getAgentEvents(0), api.getStatus()]);
      if (active) {
        setScanActive(statusRes?.status === 'running' || statusRes?.status === 'scanning');
        if (res && res.events.length > 0) {
          const rootMsgs = res.events.slice(-50).map((e: any) => ({
            role: e.role === 'assistant' ? 'assistant' : 'user',
            content: e.content?.slice(0, 1000) || '',
            time: e.timestamp ? new Date(e.timestamp).toLocaleTimeString('en-US', {hour12: false, hour:'2-digit', minute:'2-digit'}) : '',
            agent: e.agent_name || '',
          })).filter((m: any) => m.content && !m.content.includes('<inherited_context') && !m.content.includes('<agent_delegation>') && !m.content.includes('<function='));
          // Merge with optimistic local messages (keep user messages that aren't in server yet)
          setMessages(prev => {
            const localOnly = prev.filter(m => m.role === 'user' && !rootMsgs.some((rm: any) => rm.content === m.content));
            return [...rootMsgs, ...localOnly];
          });
        }
      }
    };
    poll();
    const id = setInterval(poll, 3000);
    return () => { active = false; clearInterval(id); };
  }, []);

  useEffect(() => {
    if (chatRef.current) chatRef.current.scrollTop = chatRef.current.scrollHeight;
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim() || sending) return;
    const msg = input.trim();
    // Optimistically show user message immediately
    setMessages(prev => [...prev, {
      role: 'user',
      content: msg,
      time: new Date().toLocaleTimeString('en-US', {hour12: false, hour:'2-digit', minute:'2-digit'}),
    }]);
    setInput('');
    setSending(true);
    await api.sendAgentMessage(msg);
    setSending(false);
  };

  return (
    <div className="h-full flex flex-col animate-in fade-in duration-300 -m-6 lg:-m-8">
      <div className="px-5 py-3 bg-[#111] border-b border-[#222] flex items-center gap-3 flex-shrink-0">
        <AtSign className="w-4 h-4 text-[#a855f7]" />
        <span className="text-sm font-medium text-[#f2f2f2]">AI Security Chat</span>
        <span className="text-xs text-[#666]">Talk to the agent about security, findings, and next steps</span>
      </div>

      <div ref={chatRef} className="flex-1 overflow-y-auto p-6 space-y-4 custom-scrollbar" style={{scrollbarWidth:'none'}}>
        {messages.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-[#666]">
            <AtSign className="w-12 h-12 mb-4 text-[#333]" />
            <p className="text-sm">{scanActive ? 'Chat with the running AI agent' : 'Start a scan to chat with the AI agent'}</p>
            <p className="text-xs mt-1 text-[#555]">{scanActive ? 'Ask about vulnerabilities, request deeper analysis, or discuss findings' : 'The agent will be available once a scan is running'}</p>
            <div className="mt-6 flex flex-wrap gap-2 max-w-lg justify-center">
              {['Explain the most critical vulnerability found', 'What attack vectors should I focus on?', 'Check for IDOR on all API endpoints', 'Summarize all findings'].map((q, i) => (
                <button key={i} onClick={() => { setInput(q); }} className="text-xs px-3 py-1.5 bg-[#1a1a1a] border border-[#333] rounded-lg text-[#999] hover:text-[#d4d4d4] hover:border-[#444] transition-colors">
                  {q}
                </button>
              ))}
            </div>
          </div>
        ) : (
          messages.map((msg, i) => (
            <div key={i} className={cn("flex", msg.role === 'user' ? "justify-end" : "justify-start")}>
              <div className={cn("max-w-[70%] rounded-lg px-4 py-3", msg.role === 'user' ? "bg-[#a855f7]/20 border border-[#a855f7]/30" : "bg-[#111] border border-[#222]")}>
                <div className="flex items-center gap-2 mb-1">
                  <span className={cn("text-[10px] font-medium", msg.role === 'user' ? "text-[#a855f7]" : "text-green-400")}>
                    {msg.role === 'user' ? 'You' : (msg as any).agent || 'Agent'}
                  </span>
                  {msg.time && <span className="text-[10px] text-[#555]">{msg.time}</span>}
                </div>
                <p className="text-sm text-[#d4d4d4] whitespace-pre-wrap break-words">{msg.content.slice(0, 500)}{msg.content.length > 500 ? '...' : ''}</p>
              </div>
            </div>
          ))
        )}
      </div>

      <div className="flex-shrink-0 border-t border-[#222] bg-[#0d0d0d] p-4">
        <div className="flex items-center gap-3 max-w-4xl mx-auto">
          <input
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && !e.shiftKey && handleSend()}
            placeholder="Ask the AI agent anything about security..."
            className="flex-1 bg-[#111] border border-[#333] rounded-lg px-4 py-3 text-sm text-[#d4d4d4] focus:outline-none focus:border-[#a855f7]/50 placeholder-[#555]"
            disabled={sending}
          />
          <button
            onClick={handleSend}
            disabled={sending || !input.trim()}
            className={cn("p-3 rounded-lg transition-colors", input.trim() ? "bg-[#a855f7] hover:bg-[#c084fc] text-white" : "bg-[#222] text-[#555]")}
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}

// --- Compliance Page (OWASP Top 10) ---

function CompliancePage() {
  const [data, setData] = useState<any>(null);
  useEffect(() => {
    const load = async () => { const res = await api.getCompliance(); if (res) setData(res); };
    load(); const id = setInterval(load, 10000); return () => clearInterval(id);
  }, []);
  const owasp = data?.owasp || {};
  const total = data?.total_mapped || 0;
  const sevColor = (s: string) => s === 'critical' ? 'text-red-400' : s === 'high' ? 'text-orange-400' : s === 'medium' ? 'text-yellow-400' : 'text-blue-400';

  return (
    <div className="space-y-6 max-w-5xl mx-auto animate-in fade-in duration-500">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-medium text-[#f2f2f2]">OWASP Top 10 Compliance</h2>
          <p className="text-[#8c8c8c] text-sm mt-1">Vulnerabilities mapped to OWASP Top 10 2021 categories.</p>
        </div>
        <span className="text-xs bg-[#a855f7]/10 text-[#a855f7] px-2.5 py-1 rounded-full border border-[#a855f7]/20">{total} mapped findings</span>
      </div>
      <div className="space-y-2">
        {Object.entries(owasp).map(([code, info]: [string, any]) => (
          <div key={code} className={cn("bg-[#111] border rounded-lg p-4 transition-colors", info.count > 0 ? "border-red-500/30" : "border-[#222]")}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className={cn("text-sm font-mono font-bold", info.count > 0 ? "text-red-400" : "text-[#555]")}>{code}</span>
                <span className="text-sm text-[#d4d4d4]">{info.name}</span>
              </div>
              <span className={cn("text-xs px-2 py-0.5 rounded", info.count > 0 ? "bg-red-500/10 text-red-400 border border-red-500/20" : "bg-[#222] text-[#666]")}>{info.count}</span>
            </div>
            {info.vulns?.length > 0 && (
              <div className="mt-2 space-y-1">
                {info.vulns.map((v: any, i: number) => (
                  <div key={i} className="flex items-center gap-2 text-xs pl-10">
                    <span className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0", sevColor(v.severity) === 'text-red-400' ? 'bg-red-400' : sevColor(v.severity) === 'text-orange-400' ? 'bg-orange-400' : 'bg-yellow-400')}></span>
                    <span className="text-[#999]">{v.title}</span>
                    <span className={cn("text-[10px]", sevColor(v.severity))}>{v.severity}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// --- Replay Page ---

function ReplayPage() {
  const [actions, setActions] = useState<any[]>([]);
  const [playing, setPlaying] = useState(false);
  const [currentIdx, setCurrentIdx] = useState(-1);
  const [speed, setSpeed] = useState(1);
  const timelineRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const load = async () => {
      const res = await api.getActions();
      if (res) setActions(res.actions);
    };
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, []);

  // Auto-play
  useEffect(() => {
    if (!playing || currentIdx >= actions.length - 1) {
      if (currentIdx >= actions.length - 1) setPlaying(false);
      return;
    }
    const timer = setTimeout(() => setCurrentIdx(prev => prev + 1), 1500 / speed);
    return () => clearTimeout(timer);
  }, [playing, currentIdx, speed, actions.length]);

  // Auto-scroll to current
  useEffect(() => {
    if (timelineRef.current && currentIdx >= 0) {
      const el = timelineRef.current.children[currentIdx] as HTMLElement;
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  }, [currentIdx]);

  const formatTime = (ts: string) => {
    if (!ts) return '';
    try { return new Date(ts).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
    catch { return ''; }
  };

  const getTypeColor = (type: string) => {
    const t = type.toLowerCase();
    if (t.includes('browser') || t.includes('navigate')) return 'border-green-500/40 bg-green-500/5';
    if (t.includes('terminal') || t.includes('bash')) return 'border-blue-500/40 bg-blue-500/5';
    if (t.includes('python')) return 'border-yellow-500/40 bg-yellow-500/5';
    if (t.includes('vuln') || t.includes('report')) return 'border-red-500/40 bg-red-500/5';
    if (t.includes('proxy') || t.includes('request')) return 'border-[#a855f7]/40 bg-[#a855f7]/5';
    return 'border-[#333] bg-[#111]';
  };

  const getTypeIcon = (type: string) => {
    const t = type.toLowerCase();
    if (t.includes('browser')) return '🌐';
    if (t.includes('terminal') || t.includes('bash')) return '>';
    if (t.includes('python')) return '#';
    if (t.includes('vuln') || t.includes('report')) return '!';
    if (t.includes('proxy') || t.includes('request')) return '~';
    if (t.includes('agent') || t.includes('create')) return '+';
    if (t.includes('todo')) return 'v';
    return '.';
  };

  const progress = actions.length > 0 ? ((currentIdx + 1) / actions.length) * 100 : 0;

  return (
    <div className="h-full flex flex-col animate-in fade-in duration-300 -m-6 lg:-m-8">
      {/* Header */}
      <div className="px-5 py-3 bg-[#111] border-b border-[#222] flex items-center justify-between flex-shrink-0">
        <div className="flex items-center gap-3">
          <Activity className="w-4 h-4 text-[#a855f7]" />
          <span className="text-sm font-medium text-[#f2f2f2]">Attack Replay</span>
          <span className="text-xs text-[#666]">{actions.length} actions recorded</span>
        </div>
        <div className="flex items-center gap-2">
          {/* Speed control */}
          <div className="flex items-center gap-1 bg-[#0a0a0a] rounded p-0.5 border border-[#222]">
            {[0.5, 1, 2, 4].map(s => (
              <button key={s} onClick={() => setSpeed(s)} className={cn("px-2 py-0.5 rounded text-[10px] font-mono", speed === s ? "bg-[#a855f7] text-white" : "text-[#666] hover:text-[#999]")}>
                {s}x
              </button>
            ))}
          </div>
          {/* Controls */}
          <button onClick={() => { setCurrentIdx(0); setPlaying(false); }} className="px-2 py-1 text-xs text-[#888] hover:text-[#d4d4d4] border border-[#333] rounded">
            Reset
          </button>
          <button onClick={() => { if (currentIdx < 0) setCurrentIdx(0); setPlaying(!playing); }} className={cn("px-3 py-1 rounded text-xs font-medium", playing ? "bg-red-500/20 text-red-400 border border-red-500/30" : "bg-[#a855f7] text-white")}>
            {playing ? 'Pause' : currentIdx >= 0 ? 'Resume' : 'Play'}
          </button>
        </div>
      </div>

      {/* Progress bar */}
      <div className="h-1 bg-[#222] flex-shrink-0">
        <div className="h-full bg-[#a855f7] transition-all duration-300" style={{ width: `${progress}%` }}></div>
      </div>

      {/* Timeline */}
      <div ref={timelineRef} className="flex-1 overflow-y-auto p-4 space-y-1 custom-scrollbar" style={{scrollbarWidth:'none'}}>
        {actions.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-[#666]">
            <Activity className="w-12 h-12 mb-4 text-[#333]" />
            <p className="text-sm">No actions recorded yet</p>
            <p className="text-xs mt-1 text-[#555]">Run a scan to record agent actions for playback</p>
          </div>
        ) : (
          actions.map((action, i) => {
            const isCurrent = i === currentIdx;
            const isPast = i < currentIdx;
            const isFuture = i > currentIdx && currentIdx >= 0;

            return (
              <div
                key={i}
                onClick={() => { setCurrentIdx(i); setPlaying(false); }}
                className={cn(
                  "flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-all",
                  isCurrent ? `${getTypeColor(action.type)} ring-1 ring-[#a855f7]/50` :
                  isPast ? "border-[#1a1a1a] bg-[#0d0d0d] opacity-60" :
                  isFuture ? "border-[#1a1a1a] bg-[#0a0a0a] opacity-30" :
                  "border-[#222] bg-[#111] hover:border-[#333]"
                )}
              >
                {/* Step number */}
                <div className={cn("w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 text-xs font-mono font-bold",
                  isCurrent ? "bg-[#a855f7] text-white" : isPast ? "bg-[#222] text-[#666]" : "bg-[#1a1a1a] text-[#444]"
                )}>
                  {getTypeIcon(action.type)}
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-[#555] font-mono">{formatTime(action.timestamp)}</span>
                    <span className="text-xs font-medium text-[#a855f7]">{action.agent_name}</span>
                    <span className={cn("text-[10px] px-1.5 py-0.5 rounded font-mono",
                      action.status === 'completed' ? "bg-green-500/10 text-green-400" :
                      action.status === 'running' ? "bg-yellow-500/10 text-yellow-400" :
                      "bg-[#222] text-[#666]"
                    )}>
                      {action.type}
                    </span>
                  </div>
                  {action.details && (
                    <p className="text-xs text-[#888] mt-1 truncate">{action.details}</p>
                  )}
                  {isCurrent && action.result && (
                    <pre className="mt-2 p-2 bg-[#0a120a] border border-[#1a2a1a] rounded text-[10px] text-[#6a9a6a] whitespace-pre-wrap break-all max-h-[100px] overflow-hidden">
                      {action.result}
                    </pre>
                  )}
                </div>

                {/* Step indicator */}
                <span className="text-[10px] text-[#444] font-mono flex-shrink-0">{i + 1}/{actions.length}</span>
              </div>
            );
          })
        )}
      </div>

      {/* Footer */}
      <div className="px-4 py-2 bg-[#111] border-t border-[#222] flex items-center justify-between text-[10px] text-[#666] font-mono flex-shrink-0">
        <span>{currentIdx >= 0 ? `Step ${currentIdx + 1} of ${actions.length}` : 'Click Play to start'}</span>
        <span>speed: {speed}x</span>
      </div>
    </div>
  );
}

// --- History Page ---

function HistoryPage() {
  const [scans, setScans] = useState<any[]>([]);
  useEffect(() => { api.getHistory().then(res => { if (res) setScans(res.scans); }); }, []);

  return (
    <div className="space-y-6 max-w-5xl mx-auto animate-in fade-in duration-500">
      <div>
        <h2 className="text-xl font-medium text-[#f2f2f2]">Scan History</h2>
        <p className="text-[#8c8c8c] text-sm mt-1">Past penetration test results.</p>
      </div>
      {scans.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 text-[#666]">
          <Clock className="w-12 h-12 mb-4 text-[#333]" />
          <p className="text-sm">No completed scans yet</p>
        </div>
      ) : (
        <div className="space-y-3">
          {scans.map((scan: any) => (
            <div key={scan.id} className="bg-[#111] border border-[#222] rounded-lg p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className="text-sm font-medium text-[#d4d4d4]">{scan.target || 'Unknown'}</span>
                  <span className={cn("text-[10px] px-1.5 py-0.5 rounded", scan.status === 'completed' ? "bg-green-500/10 text-green-400" : "bg-[#222] text-[#666]")}>{scan.status}</span>
                </div>
                <span className="text-[10px] text-[#666]">{scan.started_at?.slice(0, 16)}</span>
              </div>
              <div className="flex items-center gap-4 mt-2 text-xs text-[#888]">
                <span>Vulns: <strong className="text-[#d4d4d4]">{scan.vuln_count}</strong></span>
                {scan.critical > 0 && <span className="text-red-400">Critical: {scan.critical}</span>}
                {scan.high > 0 && <span className="text-orange-400">High: {scan.high}</span>}
                {scan.medium > 0 && <span className="text-yellow-400">Medium: {scan.medium}</span>}
                <span>Tokens: {scan.total_tokens?.toLocaleString()}</span>
                {scan.cost > 0 && <span>Cost: ${scan.cost?.toFixed(2)}</span>}
                <span>Agents: {scan.agent_count}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// --- Task Tree (Background Content) ---
function TaskTree() {
  return (
    <div className="max-w-5xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-semibold text-[#f2f2f2]">Penetration Test Task Tree</h1>
        <div className="text-sm text-[#8c8c8c]">Overall progress: 1/40 Items (3%)</div>
      </div>

      <div className="bg-[#111111] border border-[#222] rounded-lg p-6 shadow-lg">
        <div className="space-y-6">
          <TaskPhase 
            title="Phase 1: Reconnaissance & Asset Enumeration (P0/P1)"
            progress="1/5"
            tasks={[
              { label: "P1: Extended subdomain and related domain enumeration", completed: true },
              { label: "P1: Detailed port scanning and service identification", completed: false },
              { label: "P1: Web technology fingerprinting and WAF detection", completed: false },
              { label: "P1: Directory, hidden path, and backup enumeration", completed: false },
              { label: "P0: GraphQL API analysis and schema extraction", completed: false },
            ]}
          />
          <TaskPhase 
            title="Phase 2: Business Logic Vulnerability Discovery (P0 - Critical)"
            progress="0/6"
            tasks={[
              { label: "P0: Race condition testing for gift duplication", completed: false },
              { label: "P0: Price and purchase parameter manipulation", completed: false },
              { label: "P0: Balance verification bypass testing", completed: false },
            ]}
          />
        </div>
      </div>
    </div>
  );
}

function TaskPhase({ title, progress, tasks }: { title: string, progress: string, tasks: { label: string, completed: boolean }[] }) {
  return (
    <div className="relative pl-4 border-l border-[#333]">
      <div className="absolute -left-[5px] top-1.5 w-2 h-2 rounded-full bg-[#444]"></div>
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-[#d4d4d4] font-medium">{title}</h3>
        <span className="text-xs text-[#666]">{progress}</span>
      </div>
      <div className="space-y-2 pl-2">
        {tasks.map((task, idx) => (
          <div key={idx} className="flex items-start gap-3 group cursor-pointer">
            <div className={cn(
              "mt-0.5 w-4 h-4 rounded-full border flex items-center justify-center flex-shrink-0 transition-colors",
              task.completed 
                ? "border-green-500 bg-green-500/10 text-green-500" 
                : "border-[#444] group-hover:border-[#666] text-transparent"
            )}>
              <Check className="w-3 h-3" />
            </div>
            <span className={cn(
              "text-sm transition-colors",
              task.completed ? "text-[#8c8c8c] line-through" : "text-[#a3a3a3] group-hover:text-[#d4d4d4]"
            )}>
              {task.label}
            </span>
          </div>
        ))}
        <button className="flex items-center gap-1 text-xs text-[#a855f7] hover:text-[#c084fc] mt-2 ml-7 transition-colors">
          <Plus className="w-3 h-3" />
          Add check item
        </button>
      </div>
    </div>
  );
}

// --- Modal Component ---
function CreateTestModal({ onClose }: { onClose: () => void }) {
  const [step, setStep] = useState(1);
  const [isProcessing, setIsProcessing] = useState(false);
  const [processingStep, setProcessingStep] = useState(1);
  const [processingLogs, setProcessingLogs] = useState<string[]>([]);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanTotal, setScanTotal] = useState(0);

  const [formData, setFormData] = useState<TestFormData>({
    taskName: '',
    testTarget: '',
    note: '',
    autoRiskFilter: true,
    scanMode: 'standard',
    businessContext: '',
    testingScope: '',
    criticalAssets: '',
    knownIssues: '',
    complianceRequirements: '',
    credentials: [],
    requestHeaders: []
  });

  const [expandedSections, setExpandedSections] = useState({
    access: true,
    recon: true
  });

  const [isCredentialModalOpen, setIsCredentialModalOpen] = useState(false);
  const [isHeaderModalOpen, setIsHeaderModalOpen] = useState(false);
  
  const [newCredential, setNewCredential] = useState<Credential>({ username: '', password: '', description: '' });
  const [newHeader, setNewHeader] = useState<RequestHeader>({ name: '', value: '' });

  const scanStartedRef = React.useRef(false);

  React.useEffect(() => {
    if (!isProcessing || scanStartedRef.current) return;
    scanStartedRef.current = true;

    const runProcess = async () => {
      setProcessingStep(1);
      setProcessingLogs(['[Recon] Starting pre-scan reconnaissance...']);

      // Start recon
      let reconId: string | null = null;
      try {
        const reconRes = await api.startRecon(formData.testTarget);
        if (reconRes) {
          reconId = reconRes.recon_id;
          setProcessingLogs(prev => [...prev, `[Recon] Session started: ${reconId}`]);
        } else {
          setProcessingLogs(prev => [...prev, '[Recon] Failed to start, proceeding without recon']);
        }
      } catch {
        setProcessingLogs(prev => [...prev, '[Recon] Failed to start, proceeding without recon']);
      }

      // Poll recon status until complete
      if (reconId) {
        let logIndex = 0;
        await new Promise<void>((resolve) => {
          const interval = setInterval(async () => {
            try {
              const status = await api.getReconStatus(reconId!, logIndex);
              if (!status) return;

              // Append new logs
              if (status.logs.length > 0) {
                const newMessages = status.logs.map((l: any) => l.message);
                setProcessingLogs(prev => [...prev, ...newMessages]);
                logIndex = status.total_logs;
              }

              // Update step indicator + scan progress
              if (status.current_step > 0) {
                setProcessingStep(status.current_step);
              }
              if (status.scan_progress !== undefined) {
                setScanProgress(status.scan_progress);
                setScanTotal(status.scan_total || 0);
              }

              // Done?
              if (status.status === 'completed' || status.status === 'failed') {
                clearInterval(interval);
                resolve();
              }
            } catch {
              // Connection lost, continue anyway
            }
          }, 1500);

          // Timeout after 4 minutes max
          setTimeout(() => { clearInterval(interval); resolve(); }, 240000);
        });
      }

      // Now start the actual AI agent scan
      setProcessingLogs(prev => [...prev, '', '[Scan] Starting AI agent scan...']);
      try {
        const res = await fetch('/api/scans', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target: formData.testTarget,
            task_name: formData.taskName,
            instruction: formData.note,
            scan_mode: formData.scanMode === 'standard' ? 'standard' : 'deep',
            red_team: formData.scanMode === 'full' || formData.scanMode === 'infra',
            zeroday: formData.scanMode === 'full' || formData.scanMode === 'infra',
            infra_mode: formData.scanMode === 'infra',
            smart_contract: formData.scanMode === 'smartcontract',
            auto_risk_filter: formData.autoRiskFilter,
            credentials: formData.credentials,
            request_headers: formData.requestHeaders,
            business_context: formData.businessContext,
            testing_scope: formData.testingScope,
            critical_assets: formData.criticalAssets,
            known_issues: formData.knownIssues,
            compliance_requirements: formData.complianceRequirements,
            recon_id: reconId || '',
          }),
        });

        if (!res.ok) {
          const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
          setProcessingLogs(prev => [...prev, `[ERROR] ${err.detail || 'Server error'}`]);
        } else {
          const data = await res.json();
          setProcessingLogs(prev => [...prev, `[Scan] Agent started: ${data.run_name}`]);
        }
      } catch {
        setProcessingLogs(prev => [...prev, '[ERROR] Failed to connect to server']);
      }

      setProcessingLogs(prev => [...prev, '', '✓ Reconnaissance complete. AI agent scan starting...']);
      // Give user 15 seconds to review results, with a skip button
      setScanReady(true);
      setTimeout(() => { onClose(); }, 15000);
    };

    runProcess();
  }, [isProcessing]);

  const [scanReady, setScanReady] = useState(false);

  const toggleSection = (section: 'access' | 'recon') => {
    setExpandedSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  const addCredential = () => {
    if (newCredential.username) {
      setFormData(prev => ({ ...prev, credentials: [...prev.credentials, newCredential] }));
      setNewCredential({ username: '', password: '', description: '' });
      setIsCredentialModalOpen(false);
    }
  };

  const removeCredential = (index: number) => {
    setFormData(prev => ({ ...prev, credentials: prev.credentials.filter((_, i) => i !== index) }));
  };

  const addHeader = () => {
    if (newHeader.name && newHeader.value) {
      setFormData(prev => ({ ...prev, requestHeaders: [...prev.requestHeaders, newHeader] }));
      setNewHeader({ name: '', value: '' });
      setIsHeaderModalOpen(false);
    }
  };

  const removeHeader = (index: number) => {
    setFormData(prev => ({ ...prev, requestHeaders: prev.requestHeaders.filter((_, i) => i !== index) }));
  };

  const updateForm = (field: keyof TestFormData, value: any) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  if (isProcessing) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#0a0a0a] animate-in fade-in duration-200">
        <div className="w-full max-w-6xl h-full flex flex-col bg-[#0a0a0a]">
          {/* Stepper */}
          <div className="flex items-center justify-between px-12 py-10 mt-10">
            {[
              { num: 1, label: 'Asset Discovery' },
              { num: 2, label: 'API & Endpoints' },
              { num: 3, label: 'Risk Analysis' },
              { num: 4, label: 'WAF Bypass' },
              { num: 5, label: 'Task Plan' },
            ].map((s, idx, arr) => {
              const isActive = processingStep === s.num;
              const isPast = processingStep > s.num;

              return (
                <React.Fragment key={s.num}>
                  <div className={cn(
                    "flex flex-col items-center justify-center border rounded-sm px-4 py-2 w-64 text-center z-10 transition-all duration-300",
                    isActive
                      ? "border-[#a855f7] text-[#a855f7] bg-[#a855f7]/10 shadow-[0_0_20px_rgba(168,85,247,0.3)] animate-pulse"
                      : isPast
                        ? "border-[#a855f7] text-[#a855f7] bg-[#0a0a0a]"
                        : "border-[#333] text-[#666] bg-[#0a0a0a]"
                  )}>
                    <span className="text-[11px] font-bold mb-0.5 uppercase tracking-wider">
                      {isPast ? '✓ ' : isActive ? '● ' : ''}STEP-{s.num}
                    </span>
                    <span className="text-[12px] font-medium leading-tight">{s.label}</span>
                  </div>
                  {idx < arr.length - 1 && (
                    <div className={cn(
                      "flex-1 h-[1px] transition-colors mx-2",
                      processingStep > s.num ? "bg-[#a855f7]" : "bg-[#333]"
                    )}></div>
                  )}
                </React.Fragment>
              );
            })}
          </div>

          {/* Progress bar for endpoint scanning */}
          {scanTotal > 0 && (
            <div className="px-12 pt-4">
              <div className="flex items-center justify-between text-xs text-[#8c8c8c] mb-2">
                <span>{scanProgress >= scanTotal ? 'Scan complete' : `Scanning ${scanTotal} endpoints...`}</span>
                <span className="font-mono text-[#a855f7]">{scanProgress} / {scanTotal}</span>
              </div>
              <div className="h-2 w-full bg-[#222] rounded-full overflow-hidden">
                <div
                  className="h-full bg-[#a855f7] rounded-full transition-all duration-500"
                  style={{ width: `${scanTotal > 0 ? Math.min(100, (scanProgress / scanTotal) * 100) : 0}%` }}
                ></div>
              </div>
            </div>
          )}

          {/* Terminal */}
          <div className="flex-1 px-12 py-8 font-mono text-[13px] text-[#a3a3a3] overflow-auto whitespace-pre-wrap leading-relaxed custom-scrollbar" style={{scrollbarWidth: 'none'}}>
            {processingLogs.map((log, i) => {
              const isComplete = log.includes('Complete');
              return (
                <div key={i} className={cn(
                  log === '' ? 'h-4' : '',
                  isComplete ? 'text-[#a855f7]' : 'text-[#a3a3a3]'
                )}>
                  {log}
                </div>
              );
            })}
          </div>

          {/* Footer */}
          <div className="p-8 flex flex-col items-center gap-4 mb-10">
            {scanReady ? (
              <button
                onClick={onClose}
                className="px-6 py-2.5 bg-[#a855f7] hover:bg-[#c084fc] text-white rounded-lg font-medium text-sm transition-all shadow-[0_0_20px_rgba(168,85,247,0.3)] hover:shadow-[0_0_30px_rgba(168,85,247,0.5)]"
              >
                Continue to scan →
              </button>
            ) : (<>
            <svg width="48" height="48" viewBox="0 0 64 64" fill="none" className="opacity-80">
              {/* Steam lines */}
              <path d="M20 18 Q20 10 24 6" stroke="#a855f7" strokeWidth="2" strokeLinecap="round" fill="none" opacity="0.6">
                <animate attributeName="d" values="M20 18 Q20 10 24 6;M20 18 Q18 10 22 4;M20 18 Q20 10 24 6" dur="2s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.6;0.2;0.6" dur="2s" repeatCount="indefinite" />
              </path>
              <path d="M30 16 Q30 8 34 4" stroke="#a855f7" strokeWidth="2" strokeLinecap="round" fill="none" opacity="0.5">
                <animate attributeName="d" values="M30 16 Q30 8 34 4;M30 16 Q32 8 28 2;M30 16 Q30 8 34 4" dur="2.5s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.5;0.15;0.5" dur="2.5s" repeatCount="indefinite" />
              </path>
              <path d="M40 18 Q40 10 36 6" stroke="#a855f7" strokeWidth="2" strokeLinecap="round" fill="none" opacity="0.4">
                <animate attributeName="d" values="M40 18 Q40 10 36 6;M40 18 Q42 10 38 4;M40 18 Q40 10 36 6" dur="3s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.4;0.1;0.4" dur="3s" repeatCount="indefinite" />
              </path>
              {/* Cup body */}
              <path d="M12 24 L14 52 C14 56 46 56 46 52 L48 24 Z" fill="#1a1a1a" stroke="#a855f7" strokeWidth="1.5" />
              {/* Coffee surface */}
              <ellipse cx="30" cy="28" rx="16" ry="4" fill="#6b3a1a" opacity="0.6" />
              {/* Handle */}
              <path d="M48 30 Q56 30 56 38 Q56 46 48 46" stroke="#a855f7" strokeWidth="2" fill="none" strokeLinecap="round" />
              {/* Saucer */}
              <ellipse cx="30" cy="54" rx="22" ry="4" fill="none" stroke="#a855f7" strokeWidth="1" opacity="0.3" />
            </svg>
            <div className="text-center">
              <p className="text-[#a855f7] font-medium text-[13px]">Preliminary reconnaissance in progress</p>
              <p className="text-[#666] text-[11px] mt-1">Grab a cup of coffee while we map the attack surface</p>
            </div>
            </>)}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-[#111111] border border-[#333] rounded-xl shadow-2xl w-full max-w-2xl flex flex-col overflow-hidden animate-in zoom-in-95 duration-200">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#222] bg-[#141414]">
          <div className="flex items-center gap-2 text-[#f2f2f2] font-medium">
            <Target className="w-5 h-5 text-[#a855f7]" />
            <h2>Create Penetration Test</h2>
          </div>
          <button 
            onClick={onClose}
            className="text-[#8c8c8c] hover:text-white transition-colors p-1 rounded-md hover:bg-[#222]"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Stepper */}
        <div className="px-6 py-5 border-b border-[#222] bg-[#0d0d0d]">
          <div className="flex items-center justify-between max-w-md mx-auto relative">
            <div className="absolute top-1/2 left-0 right-0 h-[1px] bg-[#333] -z-10 -translate-y-1/2"></div>
            
            {[
              { num: 1, label: 'Target Details', icon: Crosshair },
              { num: 2, label: 'Access Config', icon: Key },
              { num: 3, label: 'Confirmation', icon: ClipboardCheck }
            ].map((s) => (
              <div key={s.num} className="flex flex-col items-center gap-2 bg-[#0d0d0d] px-4">
                <div className={cn(
                  "w-10 h-10 rounded-full flex items-center justify-center text-base font-bold transition-colors",
                  step === s.num 
                    ? "bg-[#a855f7] text-white ring-4 ring-[#a855f7]/20" 
                    : step > s.num 
                      ? "bg-[#a855f7] text-white"
                      : "border-2 border-[#333] text-[#666] bg-[#111]"
                )}>
                  {step > s.num ? <Check className="w-5 h-5" /> : <s.icon className="w-5 h-5" />}
                </div>
                <div className="flex flex-col items-center">
                  <span className={cn(
                    "text-[10px] uppercase tracking-wider font-bold mb-0.5",
                    step >= s.num ? "text-[#a855f7]" : "text-[#555]"
                  )}>
                    Step {s.num}
                  </span>
                  <span className={cn(
                    "text-xs font-medium text-center",
                    step >= s.num ? "text-[#d4d4d4]" : "text-[#666]"
                  )}>
                    {s.label}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto max-h-[60vh] custom-scrollbar">
          {step === 1 && (
            <div className="space-y-5">
              
              {/* Task Name */}
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-[#d4d4d4] flex items-center gap-1">
                  Task Name <span className="text-[#a855f7]">*</span>
                </label>
                <input 
                  type="text" 
                  value={formData.taskName}
                  onChange={(e) => updateForm('taskName', e.target.value)}
                  placeholder="e.g. Corporate website security test"
                  className="w-full bg-[#1a1a1a] border border-[#333] rounded-md px-3 py-2.5 text-sm text-[#f2f2f2] placeholder-[#555] focus:outline-none focus:border-[#a855f7] focus:ring-1 focus:ring-[#a855f7] transition-all"
                />
              </div>

              {/* Test Target */}
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-[#d4d4d4] flex items-center gap-1">
                  Test Target <span className="text-[#a855f7]">*</span>
                </label>
                <input 
                  type="text" 
                  value={formData.testTarget}
                  onChange={(e) => updateForm('testTarget', e.target.value)}
                  placeholder="e.g. example.com or 192.168.1.100"
                  className="w-full bg-[#1a1a1a] border border-[#333] rounded-md px-3 py-2.5 text-sm text-[#f2f2f2] placeholder-[#555] focus:outline-none focus:border-[#a855f7] focus:ring-1 focus:ring-[#a855f7] transition-all"
                />
              </div>

              {/* Note */}
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-[#d4d4d4] flex items-center gap-2">
                  Notes <span className="text-[10px] uppercase tracking-wider bg-[#222] text-[#888] px-1.5 py-0.5 rounded">Optional</span>
                </label>
                <textarea 
                  value={formData.note}
                  onChange={(e) => updateForm('note', e.target.value)}
                  placeholder="Enter task description (optional)"
                  rows={3}
                  className="w-full bg-[#1a1a1a] border border-[#333] rounded-md px-3 py-2.5 text-sm text-[#f2f2f2] placeholder-[#555] focus:outline-none focus:border-[#a855f7] focus:ring-1 focus:ring-[#a855f7] transition-all resize-none"
                />
              </div>

              {/* Auto Risk Filter */}
              <div className="space-y-3 pt-2 border-t border-[#222]">
                <label className="text-sm font-medium text-[#d4d4d4] block">
                  Automatic API risk filtering for target website <span className="text-xs text-[#666] font-normal ml-1">(~10 minutes)</span>
                </label>
                <div className="flex items-center gap-3">
                  <Checkbox 
                    label="Enable" 
                    checked={formData.autoRiskFilter} 
                    onChange={(checked) => updateForm('autoRiskFilter', checked)} 
                  />
                </div>
                
                {/* Scan Mode Selection */}
                <div className="mt-3 space-y-2">
                  <span className="text-sm text-[#8c8c8c]">Scan Mode:</span>
                  <div className="grid grid-cols-1 gap-3">
                    {([
                      { id: 'standard' as ScanMode, label: 'Standard Scan', desc: 'Reconnaissance, vulnerability discovery, technology fingerprinting. Fast and comprehensive surface analysis.', Icon: Search, color: 'blue' },
                      { id: 'full' as ScanMode, label: 'Deep + Exploit', desc: 'Full depth: exploit testing, 0day hunting, CVE research, race conditions, auth bypass, business logic abuse, fuzzing.', Icon: Shield, color: 'red' },
                      { id: 'infra' as ScanMode, label: 'Infrastructure', desc: 'Server/IP pentest: full port scan, service exploits, SSH/FTP brute-force, privilege escalation, cloud metadata, container escape.', Icon: Server, color: 'purple' },
                      { id: 'smartcontract' as ScanMode, label: 'Smart Contract', desc: 'Solidity/EVM audit: reentrancy, overflow, access control, flash loans, front-running, oracle manipulation. Slither + Mythril + AI analysis.', Icon: Code, color: 'cyan' },
                    ]).map(mode => {
                      const isSelected = formData.scanMode === mode.id;
                      const colorMap: Record<string, [string, string, string]> = {
                        blue: ['border-blue-500/50', 'bg-blue-500/10', 'text-blue-400'],
                        red: ['border-red-500/50', 'bg-red-500/10', 'text-red-400'],
                        purple: ['border-[#a855f7]/50', 'bg-[#a855f7]/10', 'text-[#a855f7]'],
                        cyan: ['border-cyan-500/50', 'bg-cyan-500/10', 'text-cyan-400'],
                      };
                      const [borderColor, bgColor, iconColor] = colorMap[mode.color] || colorMap.blue;
                      return (
                        <button
                          key={mode.id}
                          type="button"
                          onClick={() => updateForm('scanMode', mode.id)}
                          className={cn(
                            "flex items-start gap-4 p-4 rounded-lg border text-left transition-all",
                            isSelected
                              ? `${borderColor} ${bgColor}`
                              : "border-[#333] hover:border-[#444] hover:bg-[#1a1a1a]"
                          )}
                        >
                          <mode.Icon className={cn("w-6 h-6 mt-0.5 flex-shrink-0", isSelected ? iconColor : "text-[#666]")} />
                          <div>
                            <div className={cn("text-sm font-medium", isSelected ? "text-[#f2f2f2]" : "text-[#d4d4d4]")}>{mode.label}</div>
                            <div className="text-[11px] text-[#888] mt-1 leading-relaxed">{mode.desc}</div>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                  {formData.scanMode === 'full' && (
                    <div className="flex items-start gap-2 p-3 rounded-lg border border-red-500/30 bg-red-500/5 mt-2">
                      <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" />
                      <div className="text-xs text-red-300 leading-relaxed">
                        <strong>Deep + Exploit</strong> — Agents will actively exploit found vulnerabilities, test race conditions, bypass authentication, abuse business logic, research CVEs, perform deep fuzzing, and hunt for unknown vulns. <span className="text-red-400/80">Test only on your own applications.</span>
                      </div>
                    </div>
                  )}
                  {formData.scanMode === 'infra' && (
                    <div className="flex items-start gap-2 p-3 rounded-lg border border-[#a855f7]/30 bg-[#a855f7]/5 mt-2">
                      <Server className="w-4 h-4 text-[#a855f7] mt-0.5 flex-shrink-0" />
                      <div className="text-xs text-purple-300 leading-relaxed">
                        <strong>Infrastructure Pentest</strong> — Full port scan (all 65535), service version detection, exploit search for each service, SSH/FTP brute-force, privilege escalation checks, cloud metadata probing, container escape testing. <span className="text-[#a855f7]/80">Enter an IP address or hostname as target.</span>
                      </div>
                    </div>
                  )}
                  {formData.scanMode === 'smartcontract' && (
                    <div className="flex items-start gap-2 p-3 rounded-lg border border-cyan-500/30 bg-cyan-500/5 mt-2">
                      <Code className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
                      <div className="text-xs text-cyan-300 leading-relaxed">
                        <strong>Smart Contract Audit</strong> — Solidity/EVM analysis with Slither (static, 92+ detectors) + Mythril (symbolic execution). Detects: reentrancy, integer overflow, access control, flash loan vectors, front-running, oracle manipulation, delegatecall injection, storage collision. <span className="text-cyan-400/80">Enter contract address (Etherscan) or GitHub repo URL with Solidity code.</span>
                      </div>
                    </div>
                  )}
                </div>
              </div>

            </div>
          )}

          {step === 2 && (
            <div className="space-y-4">
              {/* Access Configuration Section */}
              <div className="border border-[#333] rounded-lg bg-[#111] overflow-hidden">
                <div 
                  className="flex items-center justify-between p-4 cursor-pointer hover:bg-[#1a1a1a] transition-colors"
                  onClick={() => toggleSection('access')}
                >
                  <div className="flex items-start gap-3">
                    <Key className="w-5 h-5 text-[#8c8c8c] mt-0.5" />
                    <div>
                      <div className="flex items-center gap-3">
                        <h3 className="text-[#f2f2f2] font-medium text-sm">Access Configuration</h3>
                        <span className="text-[10px] uppercase tracking-wider bg-[#222] text-[#888] px-1.5 py-0.5 rounded">Optional</span>
                      </div>
                      <p className="text-xs text-[#666] mt-0.5">Credentials and custom request headers</p>
                    </div>
                  </div>
                  {expandedSections.access ? <ChevronUp className="w-4 h-4 text-[#666]" /> : <ChevronDown className="w-4 h-4 text-[#666]" />}
                </div>
                {expandedSections.access && (
                  <div className="p-4 pt-2 border-t border-[#222] space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-[#d4d4d4]">Authentication Credentials</span>
                      <button 
                        onClick={() => setIsCredentialModalOpen(true)}
                        className="flex items-center gap-1.5 text-xs font-medium text-[#d4d4d4] bg-[#1a1a1a] hover:bg-[#222] border border-[#333] px-3 py-1.5 rounded transition-colors"
                      >
                        <Plus className="w-3.5 h-3.5" />
                        Add Credentials
                      </button>
                    </div>
                    {formData.credentials.length > 0 && (
                      <div className="space-y-2 mt-2">
                        {formData.credentials.map((cred, idx) => (
                          <div key={idx} className="flex items-center justify-between bg-[#1a1a1a] border border-[#333] p-2 rounded text-sm text-[#d4d4d4]">
                            <span>{cred.username}</span>
                            <button onClick={() => removeCredential(idx)} className="text-[#8c8c8c] hover:text-red-500"><X className="w-4 h-4" /></button>
                          </div>
                        ))}
                      </div>
                    )}
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-[#d4d4d4]">Custom Request Headers</span>
                      <button 
                        onClick={() => setIsHeaderModalOpen(true)}
                        className="flex items-center gap-1.5 text-xs font-medium text-[#d4d4d4] bg-[#1a1a1a] hover:bg-[#222] border border-[#333] px-3 py-1.5 rounded transition-colors"
                      >
                        <Plus className="w-3.5 h-3.5" />
                        Add Request Header
                      </button>
                    </div>
                    {formData.requestHeaders.length > 0 && (
                      <div className="space-y-2 mt-2">
                        {formData.requestHeaders.map((header, idx) => (
                          <div key={idx} className="flex items-center gap-2 bg-[#1a1a1a] border border-[#333] p-2 rounded text-sm text-[#d4d4d4]">
                            <span className="truncate flex-1 min-w-0 font-mono text-xs">{header.name}: {header.value}</span>
                            <button onClick={() => removeHeader(idx)} className="text-[#8c8c8c] hover:text-red-500 flex-shrink-0"><X className="w-4 h-4" /></button>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Reconnaissance and Guidance Section */}
              <div className="border border-[#333] rounded-lg bg-[#111] overflow-hidden">
                <div 
                  className="flex items-center justify-between p-4 cursor-pointer hover:bg-[#1a1a1a] transition-colors"
                  onClick={() => toggleSection('recon')}
                >
                  <div className="flex items-start gap-3">
                    <Key className="w-5 h-5 text-[#8c8c8c] mt-0.5" />
                    <div>
                      <div className="flex items-center gap-3">
                        <h3 className="text-[#f2f2f2] font-medium text-sm">Reconnaissance & Guidance</h3>
                        <span className="text-[10px] uppercase tracking-wider bg-[#222] text-[#888] px-1.5 py-0.5 rounded">Optional</span>
                      </div>
                      <p className="text-xs text-[#666] mt-0.5">Provide detailed context to guide the penetration test</p>
                    </div>
                  </div>
                  {expandedSections.recon ? <ChevronUp className="w-4 h-4 text-[#666]" /> : <ChevronDown className="w-4 h-4 text-[#666]" />}
                </div>
                {expandedSections.recon && (
                  <div className="p-4 pt-2 border-t border-[#222] space-y-5">
                  
                  {/* Business Context */}
                  <div className="space-y-1.5">
                    <label className="text-sm font-medium text-[#d4d4d4]">Business Context & Application Purpose</label>
                    <p className="text-xs text-[#666]">What is the app's role? What sensitive data and transactions does it handle? Any recent changes or new features?</p>
                    <textarea 
                      value={formData.businessContext}
                      onChange={(e) => updateForm('businessContext', e.target.value)}
                      rows={3}
                      className="w-full bg-[#1a1a1a] border border-[#333] rounded-md px-3 py-2.5 text-sm text-[#f2f2f2] placeholder-[#555] focus:outline-none focus:border-[#a855f7] focus:ring-1 focus:ring-[#a855f7] transition-all resize-none mt-1"
                    />
                  </div>

                  {/* Testing Scope */}
                  <div className="space-y-1.5">
                    <label className="text-sm font-medium text-[#d4d4d4]">Testing Scope & Method Preferences</label>
                    <p className="text-xs text-[#666]">Which areas to test? Specific attack vectors to focus on or avoid? Testing intensity preferences?</p>
                    <textarea 
                      value={formData.testingScope}
                      onChange={(e) => updateForm('testingScope', e.target.value)}
                      rows={3}
                      className="w-full bg-[#1a1a1a] border border-[#333] rounded-md px-3 py-2.5 text-sm text-[#f2f2f2] placeholder-[#555] focus:outline-none focus:border-[#a855f7] focus:ring-1 focus:ring-[#a855f7] transition-all resize-none mt-1"
                    />
                  </div>

                  {/* Critical Assets */}
                  <div className="space-y-1.5">
                    <label className="text-sm font-medium text-[#d4d4d4]">Critical Assets & High-Value Targets</label>
                    <p className="text-xs text-[#666]">Which components are most sensitive? What would cause the most damage if compromised?</p>
                    <textarea 
                      value={formData.criticalAssets}
                      onChange={(e) => updateForm('criticalAssets', e.target.value)}
                      rows={3}
                      className="w-full bg-[#1a1a1a] border border-[#333] rounded-md px-3 py-2.5 text-sm text-[#f2f2f2] placeholder-[#555] focus:outline-none focus:border-[#a855f7] focus:ring-1 focus:ring-[#a855f7] transition-all resize-none mt-1"
                    />
                  </div>

                  {/* Known Issues */}
                  <div className="space-y-1.5">
                    <label className="text-sm font-medium text-[#d4d4d4]">Known Issues & Historical Findings</label>
                    <p className="text-xs text-[#666]">Recent security incidents? Previous pentest findings? Known vulnerabilities to re-test?</p>
                    <textarea 
                      value={formData.knownIssues}
                      onChange={(e) => updateForm('knownIssues', e.target.value)}
                      rows={3}
                      className="w-full bg-[#1a1a1a] border border-[#333] rounded-md px-3 py-2.5 text-sm text-[#f2f2f2] placeholder-[#555] focus:outline-none focus:border-[#a855f7] focus:ring-1 focus:ring-[#a855f7] transition-all resize-none mt-1"
                    />
                  </div>

                  {/* Compliance Requirements */}
                  <div className="space-y-1.5">
                    <label className="text-sm font-medium text-[#d4d4d4]">Compliance Requirements</label>
                    <p className="text-xs text-[#666]">Which compliance standards should be covered in the report? (SOC 2, PCI DSS, HIPAA, GDPR, etc.)</p>
                    <textarea 
                      value={formData.complianceRequirements}
                      onChange={(e) => updateForm('complianceRequirements', e.target.value)}
                      rows={3}
                      className="w-full bg-[#1a1a1a] border border-[#333] rounded-md px-3 py-2.5 text-sm text-[#f2f2f2] placeholder-[#555] focus:outline-none focus:border-[#a855f7] focus:ring-1 focus:ring-[#a855f7] transition-all resize-none mt-1"
                    />
                  </div>

                </div>
                )}
              </div>
            </div>
          )}

          {step === 3 && (
            <div className="space-y-6 animate-in slide-in-from-right-4 duration-300">
              <div className="bg-[#1a1a1a] border border-[#333] rounded-lg p-5">
                <h3 className="text-[#f2f2f2] font-medium mb-4 flex items-center gap-2">
                  <Info className="w-4 h-4 text-[#a855f7]" />
                  Basic Details
                </h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-xs text-[#8c8c8c] mb-1">Task Name</p>
                    <p className="text-sm text-[#d4d4d4]">{formData.taskName || <span className="text-[#555]">Not specified</span>}</p>
                  </div>
                  <div>
                    <p className="text-xs text-[#8c8c8c] mb-1">Test Target</p>
                    <p className="text-sm text-[#d4d4d4]">{formData.testTarget || <span className="text-[#555]">Not specified</span>}</p>
                  </div>
                  <div className="col-span-2">
                    <p className="text-xs text-[#8c8c8c] mb-1">Notes</p>
                    <p className="text-sm text-[#d4d4d4] whitespace-pre-wrap break-all overflow-hidden max-h-[200px] overflow-y-auto custom-scrollbar" style={{scrollbarWidth:'none'}}>{formData.note || <span className="text-[#555]">No notes</span>}</p>
                  </div>
                </div>
              </div>

              <div className="bg-[#1a1a1a] border border-[#333] rounded-lg p-5">
                <h3 className="text-[#f2f2f2] font-medium mb-4 flex items-center gap-2">
                  <Settings className="w-4 h-4 text-[#a855f7]" />
                  Scan Settings
                </h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-xs text-[#8c8c8c] mb-1">Auto Risk Filter</p>
                    <p className="text-sm text-[#d4d4d4]">{formData.autoRiskFilter ? 'Enabled' : 'Disabled'}</p>
                  </div>
                  <div>
                    <p className="text-xs text-[#8c8c8c] mb-1">Scan Mode</p>
                    <p className={cn("text-sm font-medium", formData.scanMode === 'redteam' ? "text-red-400" : "text-[#d4d4d4]")}>
                      {formData.scanMode === 'standard' ? 'Standard Scan' : formData.scanMode === 'infra' ? 'Infrastructure' : formData.scanMode === 'smartcontract' ? 'Smart Contract Audit' : 'Deep + Exploit'}
                    </p>
                  </div>
                </div>
              </div>

              <div className="bg-[#1a1a1a] border border-[#333] rounded-lg p-5">
                <h3 className="text-[#f2f2f2] font-medium mb-4 flex items-center gap-2">
                  <Key className="w-4 h-4 text-[#a855f7]" />
                  Access Configuration
                </h3>
                <div className="space-y-4">
                  <div>
                    <p className="text-xs text-[#8c8c8c] mb-2">Credentials</p>
                    {formData.credentials.length > 0 ? (
                      <div className="space-y-2">
                        {formData.credentials.map((cred, idx) => (
                          <div key={idx} className="bg-[#111] border border-[#222] p-2.5 rounded text-sm text-[#d4d4d4] flex flex-col gap-1">
                            <div className="flex items-center gap-2">
                              <span className="text-[#8c8c8c]">User:</span>
                              <span className="font-medium text-[#f2f2f2]">{cred.username}</span>
                            </div>
                            {cred.description && (
                              <div className="flex items-start gap-2">
                                <span className="text-[#8c8c8c]">Description:</span>
                                <span className="text-[#d4d4d4]">{cred.description}</span>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-[#555]">Not specified</p>
                    )}
                  </div>
                  <div>
                    <p className="text-xs text-[#8c8c8c] mb-2">Request Headers</p>
                    {formData.requestHeaders.length > 0 ? (
                      <div className="space-y-2">
                        {formData.requestHeaders.map((header, idx) => (
                          <div key={idx} className="bg-[#111] border border-[#222] p-2.5 rounded text-xs text-[#d4d4d4] overflow-hidden">
                            <span className="font-medium text-[#f2f2f2]">{header.name}:</span> <span className="text-[#8c8c8c] break-all">{header.value}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-[#555]">Not specified</p>
                    )}
                  </div>
                </div>
              </div>

              <div className="bg-[#1a1a1a] border border-[#333] rounded-lg p-5">
                <h3 className="text-[#f2f2f2] font-medium mb-4 flex items-center gap-2">
                  <FileText className="w-4 h-4 text-[#a855f7]" />
                  Reconnaissance & Guidance
                </h3>
                <div className="space-y-4">
                  <div>
                    <p className="text-xs text-[#8c8c8c] mb-1">Business Context</p>
                    <p className="text-sm text-[#d4d4d4] whitespace-pre-wrap">{formData.businessContext || <span className="text-[#555]">Not specified</span>}</p>
                  </div>
                  <div>
                    <p className="text-xs text-[#8c8c8c] mb-1">Testing Scope</p>
                    <p className="text-sm text-[#d4d4d4] whitespace-pre-wrap">{formData.testingScope || <span className="text-[#555]">Not specified</span>}</p>
                  </div>
                  <div>
                    <p className="text-xs text-[#8c8c8c] mb-1">Critical Assets</p>
                    <p className="text-sm text-[#d4d4d4] whitespace-pre-wrap">{formData.criticalAssets || <span className="text-[#555]">Not specified</span>}</p>
                  </div>
                  <div>
                    <p className="text-xs text-[#8c8c8c] mb-1">Known Issues</p>
                    <p className="text-sm text-[#d4d4d4] whitespace-pre-wrap">{formData.knownIssues || <span className="text-[#555]">Not specified</span>}</p>
                  </div>
                  <div>
                    <p className="text-xs text-[#8c8c8c] mb-1">Compliance</p>
                    <p className="text-sm text-[#d4d4d4] whitespace-pre-wrap">{formData.complianceRequirements || <span className="text-[#555]">Not specified</span>}</p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-4 border-t border-[#222] bg-[#141414] flex justify-end gap-3">
          {step > 1 && (
            <button 
              onClick={() => setStep(s => s - 1)}
              className="px-4 py-2 rounded-md text-sm font-medium text-[#d4d4d4] hover:bg-[#222] hover:text-white transition-colors border border-[#333]"
            >
              Back
            </button>
          )}
          <button 
            onClick={() => {
              if (step < 3) setStep(s => s + 1);
              else setIsProcessing(true);
            }}
            className="px-6 py-2 rounded-md text-sm font-medium bg-[#a855f7] hover:bg-[#c084fc] text-white transition-all shadow-[0_0_10px_rgba(168,85,247,0.2)] hover:shadow-[0_0_15px_rgba(168,85,247,0.4)]"
          >
            {step === 3 ? 'Start Test' : 'Next'}
          </button>
        </div>

      </div>

      {/* Credential Modal */}
      {isCredentialModalOpen && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-[#111111] border border-[#333] rounded-xl shadow-2xl w-full max-w-md flex flex-col overflow-hidden animate-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between px-6 py-4 border-b border-[#222] bg-[#141414]">
              <h3 className="text-[#f2f2f2] font-medium">Add Credentials</h3>
              <button onClick={() => setIsCredentialModalOpen(false)} className="text-[#8c8c8c] hover:text-white transition-colors p-1 rounded-md hover:bg-[#222]">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-[#d4d4d4]">Username:</label>
                <input 
                  type="text" 
                  value={newCredential.username}
                  onChange={(e) => setNewCredential(prev => ({ ...prev, username: e.target.value }))}
                  placeholder="username"
                  className="w-full bg-[#1a1a1a] border border-[#333] rounded-md px-3 py-2.5 text-sm text-[#f2f2f2] placeholder-[#555] focus:outline-none focus:border-[#a855f7] focus:ring-1 focus:ring-[#a855f7] transition-all"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-[#d4d4d4]">Password:</label>
                <input 
                  type="password" 
                  value={newCredential.password || ''}
                  onChange={(e) => setNewCredential(prev => ({ ...prev, password: e.target.value }))}
                  placeholder="password"
                  className="w-full bg-[#1a1a1a] border border-[#333] rounded-md px-3 py-2.5 text-sm text-[#f2f2f2] placeholder-[#555] focus:outline-none focus:border-[#a855f7] focus:ring-1 focus:ring-[#a855f7] transition-all"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-[#d4d4d4]">Description:</label>
                <textarea 
                  value={newCredential.description || ''}
                  onChange={(e) => setNewCredential(prev => ({ ...prev, description: e.target.value }))}
                  placeholder="description"
                  rows={3}
                  className="w-full bg-[#1a1a1a] border border-[#333] rounded-md px-3 py-2.5 text-sm text-[#f2f2f2] placeholder-[#555] focus:outline-none focus:border-[#a855f7] focus:ring-1 focus:ring-[#a855f7] transition-all resize-none"
                />
              </div>
            </div>
            <div className="px-6 py-4 border-t border-[#222] bg-[#141414] flex justify-end gap-3">
              <button 
                onClick={() => setIsCredentialModalOpen(false)}
                className="px-4 py-2 rounded-md text-sm font-medium text-[#d4d4d4] hover:bg-[#222] hover:text-white transition-colors border border-[#333]"
              >
                Cancel
              </button>
              <button 
                onClick={addCredential}
                disabled={!newCredential.username}
                className="px-6 py-2 rounded-md text-sm font-medium bg-[#3b82f6] hover:bg-[#2563eb] disabled:opacity-50 disabled:cursor-not-allowed text-white transition-all shadow-[0_0_10px_rgba(59,130,246,0.2)] hover:shadow-[0_0_15px_rgba(59,130,246,0.4)]"
              >
                Add
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Header Modal */}
      {isHeaderModalOpen && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-[#111111] border border-[#333] rounded-xl shadow-2xl w-full max-w-md flex flex-col overflow-hidden animate-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between px-6 py-4 border-b border-[#222] bg-[#141414]">
              <h3 className="text-[#f2f2f2] font-medium">Add Custom Request Header</h3>
              <button onClick={() => setIsHeaderModalOpen(false)} className="text-[#8c8c8c] hover:text-white transition-colors p-1 rounded-md hover:bg-[#222]">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-[#d4d4d4]">Header Name:</label>
                <input 
                  type="text" 
                  value={newHeader.name}
                  onChange={(e) => setNewHeader(prev => ({ ...prev, name: e.target.value }))}
                  placeholder="e.g. Authorization"
                  className="w-full bg-[#1a1a1a] border border-[#333] rounded-md px-3 py-2.5 text-sm text-[#f2f2f2] placeholder-[#555] focus:outline-none focus:border-[#a855f7] focus:ring-1 focus:ring-[#a855f7] transition-all"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-[#d4d4d4]">Header Value:</label>
                <input 
                  type="text" 
                  value={newHeader.value}
                  onChange={(e) => setNewHeader(prev => ({ ...prev, value: e.target.value }))}
                  placeholder="e.g. Bearer token"
                  className="w-full bg-[#1a1a1a] border border-[#333] rounded-md px-3 py-2.5 text-sm text-[#f2f2f2] placeholder-[#555] focus:outline-none focus:border-[#a855f7] focus:ring-1 focus:ring-[#a855f7] transition-all"
                />
              </div>
            </div>
            <div className="px-6 py-4 border-t border-[#222] bg-[#141414] flex justify-end gap-3">
              <button 
                onClick={() => setIsHeaderModalOpen(false)}
                className="px-4 py-2 rounded-md text-sm font-medium text-[#d4d4d4] hover:bg-[#222] hover:text-white transition-colors border border-[#333]"
              >
                Cancel
              </button>
              <button 
                onClick={addHeader}
                disabled={!newHeader.name || !newHeader.value}
                className="px-6 py-2 rounded-md text-sm font-medium bg-[#3b82f6] hover:bg-[#2563eb] disabled:opacity-50 disabled:cursor-not-allowed text-white transition-all shadow-[0_0_10px_rgba(59,130,246,0.2)] hover:shadow-[0_0_15px_rgba(59,130,246,0.4)]"
              >
                Add
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// --- Custom UI Elements ---

function RadioOption({ label, selected, onClick }: { label: string, selected: boolean, onClick: () => void }) {
  return (
    <label className="flex items-center gap-2 cursor-pointer group">
      <div className={cn(
        "w-4 h-4 rounded-full border flex items-center justify-center transition-all",
        selected 
          ? "border-[#a855f7] bg-[#a855f7]/10" 
          : "border-[#555] group-hover:border-[#888] bg-[#1a1a1a]"
      )}>
        {selected && <div className="w-2 h-2 rounded-full bg-[#a855f7]" />}
      </div>
      <span className={cn(
        "text-sm transition-colors",
        selected ? "text-[#f2f2f2]" : "text-[#a3a3a3] group-hover:text-[#d4d4d4]"
      )}>
        {label}
      </span>
    </label>
  );
}

function Checkbox({ label, checked, onChange }: { label: string, checked: boolean, onChange: (c: boolean) => void }) {
  return (
    <label className="flex items-center gap-2 cursor-pointer group" onClick={(e) => { e.preventDefault(); onChange(!checked); }}>
      <div className={cn(
        "w-4 h-4 rounded border flex items-center justify-center transition-all",
        checked 
          ? "border-[#a855f7] bg-[#a855f7]" 
          : "border-[#555] group-hover:border-[#888] bg-[#1a1a1a]"
      )}>
        {checked && <Check className="w-3 h-3 text-white" strokeWidth={3} />}
      </div>
      <span className={cn(
        "text-sm transition-colors",
        checked ? "text-[#f2f2f2]" : "text-[#a3a3a3] group-hover:text-[#d4d4d4]"
      )}>
        {label}
      </span>
    </label>
  );
}

