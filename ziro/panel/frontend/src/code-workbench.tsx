/**
 * Code Workbench — VS Code-like editor inside Ziro panel.
 *
 * Three-pane layout:
 *   Left   — file tree (collapsible dirs) + search bar + mobile project quick-launcher
 *   Center — tabbed Monaco editor for open files
 *   Right  — AI task panel (send a scoped freeform task to the running agent)
 *
 * Works on any workspace path but has first-class mobile-decompile integration:
 * upload APK/IPA -> auto-decompile -> open in workbench.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Editor from '@monaco-editor/react';
import {
  ChevronDown,
  ChevronRight,
  File as FileIcon,
  Folder,
  FolderOpen,
  Loader2,
  Play,
  Save,
  Search,
  Smartphone,
  Upload,
  X,
  Sparkles,
  RefreshCw,
  FileSearch,
} from 'lucide-react';
import { api } from './api';
import { cn } from './lib/utils';

interface TreeNode {
  name: string;
  path: string;
  type: 'dir' | 'file';
  size?: number;
  language?: string;
  children?: TreeNode[];
  truncated?: boolean;
}

interface OpenFile {
  path: string;
  name: string;
  content: string;
  originalContent: string;
  language: string;
  isDirty: boolean;
  isBinary: boolean;
}

export function CodeWorkbench() {
  const [root, setRoot] = useState<string>('');
  const [tree, setTree] = useState<TreeNode[]>([]);
  const [treeLoading, setTreeLoading] = useState(false);
  const [openFiles, setOpenFiles] = useState<OpenFile[]>([]);
  const [activeTab, setActiveTab] = useState<string>('');
  const [showMobilePanel, setShowMobilePanel] = useState(false);
  const [aiTask, setAiTask] = useState('');
  const [aiTaskBusy, setAiTaskBusy] = useState(false);
  const [aiTaskResult, setAiTaskResult] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<any[] | null>(null);
  const [searchBusy, setSearchBusy] = useState(false);
  const [saveBusy, setSaveBusy] = useState(false);

  const loadTree = useCallback(
    async (p: string) => {
      setTreeLoading(true);
      try {
        const r = await api.workspaceTree(p, 4);
        if (r?.success) {
          setRoot(r.root || '');
          setTree(r.entries || []);
        } else {
          setTree([]);
        }
      } finally {
        setTreeLoading(false);
      }
    },
    [],
  );

  useEffect(() => {
    loadTree('');
  }, [loadTree]);

  const openFile = useCallback(
    async (path: string, name: string) => {
      const existing = openFiles.find((f) => f.path === path);
      if (existing) {
        setActiveTab(path);
        return;
      }
      const r = await api.workspaceReadFile(path);
      if (!r?.success) {
        alert(`Failed to open ${path}`);
        return;
      }
      const newFile: OpenFile = {
        path,
        name,
        content: r.content || '',
        originalContent: r.content || '',
        language: r.language || 'plaintext',
        isDirty: false,
        isBinary: Boolean(r.is_binary),
      };
      setOpenFiles((prev) => [...prev, newFile]);
      setActiveTab(path);
    },
    [openFiles],
  );

  const closeFile = useCallback(
    (path: string) => {
      const f = openFiles.find((x) => x.path === path);
      if (f?.isDirty && !confirm(`${f.name} has unsaved changes. Close anyway?`)) return;
      setOpenFiles((prev) => prev.filter((x) => x.path !== path));
      if (activeTab === path) {
        const remaining = openFiles.filter((x) => x.path !== path);
        setActiveTab(remaining.length ? remaining[remaining.length - 1].path : '');
      }
    },
    [openFiles, activeTab],
  );

  const updateContent = useCallback(
    (path: string, newContent: string) => {
      setOpenFiles((prev) =>
        prev.map((f) =>
          f.path === path
            ? {
                ...f,
                content: newContent,
                isDirty: newContent !== f.originalContent,
              }
            : f,
        ),
      );
    },
    [],
  );

  const saveActive = useCallback(async () => {
    const f = openFiles.find((x) => x.path === activeTab);
    if (!f || !f.isDirty) return;
    setSaveBusy(true);
    try {
      const r = await api.workspaceWriteFile(f.path, f.content);
      if (r?.success) {
        setOpenFiles((prev) =>
          prev.map((x) =>
            x.path === f.path ? { ...x, originalContent: f.content, isDirty: false } : x,
          ),
        );
      } else {
        alert(`Save failed: ${r?.error}`);
      }
    } finally {
      setSaveBusy(false);
    }
  }, [openFiles, activeTab]);

  const runSearch = useCallback(async () => {
    if (!searchQuery.trim()) return;
    setSearchBusy(true);
    try {
      const r = await api.workspaceSearch(searchQuery, root);
      setSearchResults(r?.matches || []);
    } finally {
      setSearchBusy(false);
    }
  }, [searchQuery, root]);

  const submitAiTask = useCallback(async () => {
    if (!aiTask.trim()) return;
    setAiTaskBusy(true);
    setAiTaskResult('');
    try {
      const f = openFiles.find((x) => x.path === activeTab);
      const r = await api.workspaceAiTask(
        f?.path || root,
        aiTask.trim(),
        f?.content?.substring(0, 8000),
      );
      if (r?.success) {
        setAiTaskResult(
          `Task routed to agent ${r.agent_id}. Monitor via Agent Terminal or LLM Debug page.`,
        );
        setAiTask('');
      } else {
        setAiTaskResult(`Error: ${r?.error || 'unknown'}`);
      }
    } finally {
      setAiTaskBusy(false);
    }
  }, [aiTask, openFiles, activeTab, root]);

  const activeFile = openFiles.find((x) => x.path === activeTab);

  return (
    <div className="flex h-full gap-3">
      {/* LEFT: file tree + search + mobile */}
      <div className="w-72 flex flex-col bg-[#111] border border-[#222] rounded-xl overflow-hidden">
        <div className="px-3 py-2 border-b border-[#222] flex items-center justify-between">
          <span className="text-xs uppercase text-[#666] font-semibold">
            Workspace
          </span>
          <button
            onClick={() => setShowMobilePanel(!showMobilePanel)}
            className={cn(
              'p-1 rounded text-xs',
              showMobilePanel
                ? 'bg-[#a855f7]/20 text-[#a855f7]'
                : 'text-[#666] hover:bg-[#1a1a1a]',
            )}
            title="Mobile decompile"
          >
            <Smartphone className="w-3 h-3" />
          </button>
        </div>

        {showMobilePanel && <MobileQuickPanel onProjectOpen={(p) => loadTree(p)} />}

        <div className="px-3 py-2 border-b border-[#222]">
          <div className="flex items-center gap-1 bg-[#0e0e0e] border border-[#222] rounded px-2">
            <Search className="w-3 h-3 text-[#555]" />
            <input
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && runSearch()}
              placeholder="Search code…"
              className="flex-1 bg-transparent text-xs py-1 text-[#e0e0e0] placeholder:text-[#555] focus:outline-none"
            />
            {searchBusy && <Loader2 className="w-3 h-3 animate-spin text-[#a855f7]" />}
          </div>
        </div>

        <div className="flex-1 overflow-y-auto custom-scrollbar">
          {searchResults !== null ? (
            <div className="p-2">
              <div className="flex items-center justify-between px-2 py-1">
                <span className="text-xs text-[#666]">
                  {searchResults.length} matches
                </span>
                <button
                  onClick={() => setSearchResults(null)}
                  className="text-[#666] hover:text-[#e0e0e0]"
                  title="Close search"
                >
                  <X className="w-3 h-3" />
                </button>
              </div>
              <div className="space-y-1">
                {searchResults.slice(0, 100).map((m, i) => (
                  <button
                    key={i}
                    onClick={() => openFile(m.path, m.path.split('/').pop())}
                    className="w-full text-left px-2 py-1 rounded hover:bg-[#1a1a1a] text-xs"
                  >
                    <div className="text-[#a855f7] truncate font-mono">
                      {m.path}:{m.line}
                    </div>
                    <div className="text-[#999] font-mono truncate pl-2 text-[11px]">
                      {m.match}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          ) : treeLoading ? (
            <div className="py-8 text-center text-[#666]">
              <Loader2 className="w-4 h-4 animate-spin mx-auto" />
            </div>
          ) : (
            <TreeView entries={tree} onOpenFile={openFile} depth={0} />
          )}
        </div>

        <div className="px-3 py-2 border-t border-[#222] flex items-center justify-between">
          <span className="text-[10px] text-[#666] truncate">
            {root ? `/${root}` : '/workspace'}
          </span>
          <button
            onClick={() => loadTree(root)}
            className="text-[#666] hover:text-[#a855f7] p-1"
            title="Refresh"
          >
            <RefreshCw className="w-3 h-3" />
          </button>
        </div>
      </div>

      {/* CENTER: tabs + editor */}
      <div className="flex-1 flex flex-col min-w-0 bg-[#111] border border-[#222] rounded-xl overflow-hidden">
        {/* Tab bar */}
        <div className="flex items-center overflow-x-auto border-b border-[#222] custom-scrollbar bg-[#0e0e0e]">
          {openFiles.length === 0 ? (
            <div className="px-4 py-3 text-xs text-[#666]">
              No files open. Click a file in the tree to edit.
            </div>
          ) : (
            openFiles.map((f) => (
              <div
                key={f.path}
                onClick={() => setActiveTab(f.path)}
                className={cn(
                  'flex items-center gap-1 px-3 py-2 border-r border-[#222] cursor-pointer group text-xs whitespace-nowrap',
                  activeTab === f.path
                    ? 'bg-[#111] text-[#e0e0e0]'
                    : 'text-[#8c8c8c] hover:bg-[#1a1a1a]',
                )}
              >
                <FileIcon className="w-3 h-3" />
                <span>{f.name}</span>
                {f.isDirty && <span className="text-[#a855f7]">●</span>}
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    closeFile(f.path);
                  }}
                  className="ml-1 opacity-0 group-hover:opacity-100 text-[#666] hover:text-red-400"
                >
                  <X className="w-3 h-3" />
                </button>
              </div>
            ))
          )}

          {activeFile && (
            <button
              onClick={saveActive}
              disabled={!activeFile.isDirty || saveBusy}
              className="ml-auto mr-2 flex items-center gap-1 px-2 py-1 text-xs bg-[#1a1a1a] border border-[#333] text-[#e0e0e0] rounded disabled:opacity-40 hover:bg-[#222]"
            >
              {saveBusy ? <Loader2 className="w-3 h-3 animate-spin" /> : <Save className="w-3 h-3" />}
              Save
            </button>
          )}
        </div>

        {/* Editor */}
        <div className="flex-1 min-h-0">
          {activeFile ? (
            activeFile.isBinary ? (
              <div className="p-8 text-center text-[#666] italic">
                Binary file — cannot display in editor.
              </div>
            ) : (
              <Editor
                height="100%"
                theme="vs-dark"
                language={activeFile.language}
                value={activeFile.content}
                onChange={(v) => updateContent(activeFile.path, v || '')}
                options={{
                  fontSize: 12,
                  minimap: { enabled: true, scale: 1 },
                  scrollBeyondLastLine: false,
                  automaticLayout: true,
                  wordWrap: 'off',
                  formatOnPaste: false,
                  readOnly: false,
                  lineNumbers: 'on',
                  renderLineHighlight: 'all',
                  smoothScrolling: true,
                }}
              />
            )
          ) : (
            <div className="h-full flex items-center justify-center text-[#555] italic">
              <div className="text-center">
                <FileSearch className="w-16 h-16 mx-auto mb-3 text-[#333]" />
                <div>Open a file from the tree to start editing.</div>
                <div className="text-xs mt-2 text-[#444]">
                  Tip: use Mobile panel to upload + decompile an APK/IPA.
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* RIGHT: AI task panel */}
      <div className="w-80 flex flex-col bg-[#111] border border-[#222] rounded-xl overflow-hidden">
        <div className="px-3 py-2 border-b border-[#222] flex items-center gap-2">
          <Sparkles className="w-3 h-3 text-[#a855f7]" />
          <span className="text-xs uppercase text-[#666] font-semibold">
            AI Task
          </span>
        </div>

        <div className="px-3 py-2 text-xs text-[#8c8c8c] border-b border-[#1a1a1a]">
          Scope: {activeFile ? (
            <span className="text-[#a855f7] font-mono">{activeFile.path}</span>
          ) : (
            <span className="font-mono">{root ? `/${root}` : '/workspace'}</span>
          )}
        </div>

        <div className="p-3 flex-1 flex flex-col gap-2">
          <textarea
            value={aiTask}
            onChange={(e) => setAiTask(e.target.value)}
            placeholder="e.g. 'Find hardcoded API keys in this file' / 'Refactor the SSL pinning check to support multiple hosts' / 'Add input validation to the login handler'"
            className="w-full flex-1 min-h-[120px] p-2 bg-[#0e0e0e] border border-[#222] rounded text-xs text-[#e0e0e0] placeholder:text-[#555] focus:border-[#a855f7] focus:outline-none font-mono"
          />

          <button
            onClick={submitAiTask}
            disabled={aiTaskBusy || !aiTask.trim()}
            className="w-full flex items-center justify-center gap-2 bg-[#a855f7] hover:bg-[#9333ea] text-white py-2 rounded text-sm font-medium disabled:opacity-50 transition"
          >
            {aiTaskBusy ? (
              <Loader2 className="w-3 h-3 animate-spin" />
            ) : (
              <Play className="w-3 h-3" />
            )}
            Send to running agent
          </button>

          {aiTaskResult && (
            <div className="mt-2 p-2 bg-[#0e0e0e] border border-[#222] rounded text-xs text-[#d4d4d4]">
              {aiTaskResult}
            </div>
          )}

          <div className="mt-auto space-y-1">
            <div className="text-[10px] text-[#555] uppercase">Quick tasks</div>
            {[
              'Audit this file for security issues',
              'Find hardcoded secrets or credentials',
              'Extract all API endpoints and document them',
              'Rewrite this function using safer APIs',
              'Add input validation and error handling',
            ].map((q) => (
              <button
                key={q}
                onClick={() => setAiTask(q)}
                className="w-full text-left px-2 py-1 text-[11px] text-[#8c8c8c] hover:bg-[#1a1a1a] hover:text-[#e0e0e0] rounded"
              >
                → {q}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// --- Tree view ---

function TreeView({
  entries,
  onOpenFile,
  depth,
}: {
  entries: TreeNode[];
  onOpenFile: (path: string, name: string) => void;
  depth: number;
}) {
  return (
    <div>
      {entries.map((node) => (
        <TreeNodeRow
          key={node.path}
          node={node}
          onOpenFile={onOpenFile}
          depth={depth}
        />
      ))}
    </div>
  );
}

function TreeNodeRow({
  node,
  onOpenFile,
  depth,
}: {
  node: TreeNode;
  onOpenFile: (path: string, name: string) => void;
  depth: number;
}) {
  const [expanded, setExpanded] = useState(depth < 1);
  const indent = depth * 12 + 6;

  if (node.type === 'dir') {
    const hasChildren = node.children && node.children.length > 0;
    return (
      <div>
        <button
          onClick={() => setExpanded(!expanded)}
          className="w-full flex items-center gap-1 px-1 py-0.5 hover:bg-[#1a1a1a] text-left text-xs"
          style={{ paddingLeft: indent }}
        >
          {expanded ? (
            <ChevronDown className="w-3 h-3 text-[#555]" />
          ) : (
            <ChevronRight className="w-3 h-3 text-[#555]" />
          )}
          {expanded ? (
            <FolderOpen className="w-3 h-3 text-[#a855f7]" />
          ) : (
            <Folder className="w-3 h-3 text-[#a855f7]" />
          )}
          <span className="text-[#d4d4d4] truncate">{node.name}</span>
        </button>
        {expanded && hasChildren && (
          <TreeView
            entries={node.children!}
            onOpenFile={onOpenFile}
            depth={depth + 1}
          />
        )}
        {expanded && node.truncated && (
          <div className="text-[10px] text-[#555] italic" style={{ paddingLeft: indent + 20 }}>
            …truncated
          </div>
        )}
      </div>
    );
  }

  return (
    <button
      onClick={() => onOpenFile(node.path, node.name)}
      className="w-full flex items-center gap-1 px-1 py-0.5 hover:bg-[#1a1a1a] text-left text-xs"
      style={{ paddingLeft: indent + 16 }}
    >
      <FileIcon className="w-3 h-3 text-[#666]" />
      <span className="text-[#c0c0c0] truncate">{node.name}</span>
      {typeof node.size === 'number' && node.size > 0 && (
        <span className="ml-auto text-[10px] text-[#555]">
          {formatSize(node.size)}
        </span>
      )}
    </button>
  );
}

function formatSize(n: number): string {
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)}K`;
  return `${(n / 1024 / 1024).toFixed(1)}M`;
}

// --- Mobile quick panel ---

function MobileQuickPanel({ onProjectOpen }: { onProjectOpen: (p: string) => void }) {
  const [projects, setProjects] = useState<any[]>([]);
  const [uploading, setUploading] = useState(false);
  const [decompiling, setDecompiling] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const loadProjects = useCallback(async () => {
    const r = await api.mobileProjects();
    setProjects(r?.projects || []);
  }, []);

  useEffect(() => {
    loadProjects();
  }, [loadProjects]);

  const handleUpload = useCallback(
    async (file: File) => {
      setUploading(true);
      try {
        const r = await api.mobileUpload(file);
        if (!r?.success) {
          alert(`Upload failed: ${r?.detail || r?.error}`);
          return;
        }
        const kind: 'apk' | 'ipa' = file.name.toLowerCase().endsWith('.ipa')
          ? 'ipa'
          : 'apk';
        setDecompiling(true);
        const d = await api.mobileDecompile(r.path, kind);
        if (d?.success) {
          await loadProjects();
          const src =
            d.source_dir || d.decompile_results?.class_dump_dir || d.project_dir;
          // Trim leading /workspace/
          const rel = src.replace(/^\/workspace\/?/, '');
          onProjectOpen(rel);
        } else {
          alert(`Decompile failed: ${d?.error}`);
        }
      } finally {
        setUploading(false);
        setDecompiling(false);
      }
    },
    [loadProjects, onProjectOpen],
  );

  return (
    <div className="border-b border-[#222] bg-[#0e0e0e]">
      <div className="px-3 py-2 border-b border-[#1a1a1a] flex items-center gap-2">
        <Smartphone className="w-3 h-3 text-[#a855f7]" />
        <span className="text-xs font-semibold text-[#d4d4d4]">
          Mobile Projects
        </span>
      </div>

      <div className="p-3 space-y-2">
        <input
          ref={fileInputRef}
          type="file"
          accept=".apk,.ipa,.aab,.xapk,.zip"
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) handleUpload(f);
            e.target.value = '';
          }}
        />
        <button
          disabled={uploading || decompiling}
          onClick={() => fileInputRef.current?.click()}
          className="w-full flex items-center justify-center gap-1 text-xs px-2 py-1.5 bg-[#a855f7] hover:bg-[#9333ea] text-white rounded disabled:opacity-50"
        >
          {uploading ? (
            <>
              <Loader2 className="w-3 h-3 animate-spin" /> Uploading…
            </>
          ) : decompiling ? (
            <>
              <Loader2 className="w-3 h-3 animate-spin" /> Decompiling…
            </>
          ) : (
            <>
              <Upload className="w-3 h-3" /> Upload APK / IPA
            </>
          )}
        </button>

        <div className="space-y-1 max-h-48 overflow-y-auto custom-scrollbar">
          {projects.length === 0 ? (
            <div className="text-[10px] text-[#555] italic text-center py-2">
              No projects yet.
            </div>
          ) : (
            projects.map((p) => (
              <button
                key={p.name}
                onClick={() =>
                  onProjectOpen(p.path.replace(/^\/workspace\/?/, ''))
                }
                className="w-full text-left px-2 py-1.5 hover:bg-[#1a1a1a] rounded text-xs"
              >
                <div className="font-semibold text-[#d4d4d4] truncate">
                  {p.name}
                </div>
                <div className="text-[10px] text-[#666] flex justify-between">
                  <span>{p.methods.join(', ')}</span>
                  <span>{formatSize(p.size_bytes)}</span>
                </div>
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
