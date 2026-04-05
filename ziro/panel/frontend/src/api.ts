const API_BASE = '/api';

async function fetchJSON<T>(path: string): Promise<T | null> {
  try {
    const res = await fetch(`${API_BASE}${path}`);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

export interface ScanStatus {
  status: string;
  run_id: string;
  run_name: string | null;
  start_time: string;
  end_time: string | null;
  targets: TargetInfo[];
  vulnerability_count: number;
  severity_counts: Record<string, number>;
}

export interface TargetInfo {
  type: string;
  original: string;
  details: Record<string, any>;
}

export interface Vulnerability {
  id: string;
  title: string;
  severity: string;
  timestamp: string;
  description?: string;
  impact?: string;
  target?: string;
  technical_analysis?: string;
  poc_description?: string;
  poc_script_code?: string;
  remediation_steps?: string;
  cvss?: number;
  endpoint?: string;
  method?: string;
  cve?: string;
  cwe?: string;
  business_impact?: {
    score: number;
    risk_level: string;
    reasoning: string;
  };
}

export interface AgentInfo {
  id: string;
  name: string;
  task: string;
  status: string;
  parent_id: string | null;
  created_at: string;
  finished_at: string | null;
  agent_type: string;
  iteration?: number;
  max_iterations?: number;
  progress?: number;
  completed?: boolean;
  errors?: string[];
  actions_count?: number;
  observations_count?: number;
}

export interface AgentsResponse {
  agents: AgentInfo[];
  edges: { from: string; to: string; type: string }[];
}

export interface ToolExecution {
  execution_id: number;
  agent_id: string;
  tool_name: string;
  status: string;
  started_at: string;
  completed_at: string | null;
}

export interface AttackGraphNode {
  id: string;
  type: string;
  description: string;
  status: string;
  target: string;
  technique: string;
  evidence: string;
  priority: number;
}

export interface AttackGraphResponse {
  nodes: AttackGraphNode[];
  edges: [string, string, string][];
}

export interface ReconLog {
  timestamp: number;
  step: number;
  message: string;
}

export interface ReconStatus {
  recon_id: string;
  status: string;
  current_step: number;
  logs: ReconLog[];
  total_logs: number;
  results: Record<string, any>;
  docker_available: boolean;
}

export interface AgentEvent {
  type: string;
  agent_id: string;
  agent_name: string;
  role: string;
  content: string;
  timestamp: string;
  index: number;
}

export interface ToolEvent {
  execution_id: number;
  agent_id: string;
  agent_name: string;
  tool_name: string;
  status: string;
  started_at: string;
  completed_at: string | null;
  args_summary: string;
}

export interface StreamingInfo {
  agent_name: string;
  content: string;
}

export interface ThinkingInfo {
  agent_name: string;
  thinking: string;
}

export interface AgentEventsResponse {
  events: AgentEvent[];
  total_messages: number;
  streaming: Record<string, StreamingInfo>;
  tool_events: ToolEvent[];
  thinking: Record<string, ThinkingInfo>;
}

export interface PortInfo {
  port: string;
  state: string;
  service: string;
}

export interface HttpxInfo {
  url?: string;
  status_code?: number;
  title?: string;
  server?: string;
  technologies?: string[];
}

export interface ReconResults {
  subdomains: string[];
  httpx_output: string;
  httpx_info: HttpxInfo;
  nmap_output: string;
  ports: PortInfo[];
  nuclei_output: string;
  findings_count: number;
}

export interface TodoItem {
  id: string;
  agent_id: string;
  agent_name: string;
  title: string;
  description?: string;
  priority: string;
  status: string;
  created_at: string;
  updated_at: string;
  completed_at?: string;
}

export interface TodosResponse {
  todos: TodoItem[];
  total: number;
}

export interface ScreenshotCard {
  url: string;
  status_code: number | null;
  title: string;
  technologies: string[];
  alive: boolean | null;
  screenshot: string | null;
}

export interface ScreenshotsResponse {
  screenshots: ScreenshotCard[];
  total: number;
}

export interface MitreHit {
  tactic_id: string;
  tactic: string;
  technique_id: string;
  technique: string;
  count: number;
  severity: string;
  vulns: string[];
}

export interface MitreResponse {
  hits: MitreHit[];
  coverage: number;
  total_techniques: number;
}

export interface HttpLogEntry {
  id: string;
  agent_id: string;
  agent_name: string;
  tool_name: string;
  method: string;
  url: string;
  status_code: number | null;
  started_at: string;
  completed_at: string | null;
  request_summary: string;
  response_summary: string;
}

export interface HttpLogsResponse {
  logs: HttpLogEntry[];
  total: number;
}

export interface RoiScore {
  subdomain: string;
  score: number;
  priority: string;
  factors: string[];
  url: string;
  status_code: number | null;
  nuclei_findings: number;
}

export interface RoiScoresResponse {
  scores: RoiScore[];
  total: number;
}

async function postJSON<T>(path: string, body: any): Promise<T | null> {
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

export interface BrowserView {
  agent_name: string;
  screenshot: string;
  media_type: string;
  url?: string;
  title?: string;
}

export interface BrowserViewResponse {
  browsers: Record<string, BrowserView>;
  total: number;
}

export const api = {
  getStatus: () => fetchJSON<ScanStatus>('/status'),
  getVulnerabilities: () => fetchJSON<Vulnerability[]>('/vulnerabilities'),
  getAgents: () => fetchJSON<AgentsResponse>('/agents'),
  getTools: () => fetchJSON<ToolExecution[]>('/tools'),
  getAttackGraph: () => fetchJSON<AttackGraphResponse>('/attack-graph'),
  getScanResults: () => fetchJSON<any>('/scan-results'),
  getLlmStats: () => fetchJSON<any>('/llm-stats'),
  getScanConfig: () => fetchJSON<any>('/scan-config'),
  startRecon: (target: string) => postJSON<{ recon_id: string; status: string }>('/recon', { target }),
  getReconStatus: (reconId: string, sinceIndex: number = 0) =>
    fetchJSON<ReconStatus>(`/recon/${reconId}/status?since_index=${sinceIndex}`),
  getAgentEvents: (sinceIndex: number = 0) =>
    fetchJSON<AgentEventsResponse>(`/agent-events?since_index=${sinceIndex}`),
  getReconResults: () => fetchJSON<ReconResults>('/recon-results'),
  getTodos: () => fetchJSON<TodosResponse>('/todos'),
  getScreenshots: () => fetchJSON<ScreenshotsResponse>('/screenshots'),
  getMitre: () => fetchJSON<MitreResponse>('/mitre'),
  getHttpLogs: () => fetchJSON<HttpLogsResponse>('/http-logs'),
  getRoiScores: () => fetchJSON<RoiScoresResponse>('/roi-scores'),
  sendAgentMessage: (message: string, agentId?: string) =>
    postJSON<{ status: string; agent_id: string }>('/agent-message', { message, agent_id: agentId || '' }),
  getBrowserView: () => fetchJSON<BrowserViewResponse>('/browser-view'),
  getAssistRequests: () => fetchJSON<{ requests: any[]; total: number }>('/assist-requests'),
  resolveAssist: (requestId: string) => postJSON<any>('/assist-resolve', { request_id: requestId }),
  // History & Templates
  getHistory: () => fetchJSON<{ scans: any[]; total: number }>('/history'),
  getTemplates: () => fetchJSON<{ templates: any[] }>('/templates'),
  saveTemplate: (t: any) => postJSON<any>('/templates', t),
  deleteTemplate: (id: number) => fetch(`/api/templates/${id}`, { method: 'DELETE' }),
  // Export
  exportMarkdown: () => window.open('/api/report/markdown', '_blank'),
  exportJson: () => window.open('/api/report/json', '_blank'),
  exportEvidence: () => window.open('/api/evidence/download', '_blank'),
  // i18n
  getTranslations: (lang: string) => fetchJSON<Record<string, string>>(`/i18n/${lang}`),
  // Actions
  getActions: () => fetchJSON<{ actions: any[]; total: number }>('/actions'),
  // Knowledge Graph
  getKnowledge: () => fetchJSON<any>('/knowledge'),
  getPatterns: (tech: string) => fetchJSON<any>(`/knowledge/patterns?tech=${encodeURIComponent(tech)}`),
  // OpenAPI Import
  importOpenAPI: (url: string) => postJSON<any>('/import/openapi', { url }),
  // TOTP
  generateTotp: (secret: string) => postJSON<any>('/totp/generate', { secret }),
  // Telegram
  sendTelegram: (message?: string) => postJSON<any>('/notify/telegram', { message: message || '' }),
  // Compliance
  getCompliance: () => fetchJSON<any>('/compliance'),
};
