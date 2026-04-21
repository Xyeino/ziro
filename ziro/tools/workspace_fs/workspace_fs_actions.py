"""Workspace filesystem tools — tree/read/write/search for the Code Workbench UI.

Acts on /workspace/**, blocks path traversal, caps file sizes, provides safe
search and editing primitives that power the panel's VS-Code-like editor.
"""

from __future__ import annotations

import os
import re
from typing import Any

from ziro.tools.registry import register_tool


_WORKSPACE_ROOT = "/workspace"
_MAX_READ_BYTES = 2_000_000  # 2 MB hard cap
_MAX_TREE_ENTRIES = 5000


def _safe_join(path: str) -> str:
    """Resolve a path under /workspace, blocking traversal."""
    if not path:
        return _WORKSPACE_ROOT
    if os.path.isabs(path):
        resolved = os.path.realpath(path)
    else:
        resolved = os.path.realpath(os.path.join(_WORKSPACE_ROOT, path))
    if not resolved.startswith(_WORKSPACE_ROOT):
        raise ValueError(f"Path {path!r} escapes /workspace")
    return resolved


def _is_binary(path: str, sample_size: int = 1024) -> bool:
    try:
        with open(path, "rb") as f:
            sample = f.read(sample_size)
        return b"\x00" in sample
    except Exception:
        return True


def _guess_language(path: str) -> str:
    ext_map = {
        ".py": "python", ".js": "javascript", ".ts": "typescript", ".tsx": "typescript",
        ".jsx": "javascript", ".java": "java", ".kt": "kotlin", ".swift": "swift",
        ".m": "objective-c", ".mm": "objective-c", ".h": "objective-c",
        ".c": "c", ".cpp": "cpp", ".cc": "cpp", ".rs": "rust", ".go": "go",
        ".rb": "ruby", ".php": "php", ".sh": "shell", ".bash": "shell",
        ".yaml": "yaml", ".yml": "yaml", ".toml": "toml", ".json": "json",
        ".xml": "xml", ".html": "html", ".css": "css", ".scss": "scss",
        ".md": "markdown", ".sql": "sql", ".smali": "smali",
        ".sol": "solidity", ".plist": "xml", ".pbxproj": "xml",
        ".gradle": "groovy", ".groovy": "groovy",
        ".dockerfile": "dockerfile", "Dockerfile": "dockerfile",
        ".tf": "hcl", ".hcl": "hcl",
    }
    ext = os.path.splitext(path)[1].lower()
    base = os.path.basename(path)
    return ext_map.get(ext) or ext_map.get(base) or "plaintext"


@register_tool(sandbox_execution=False)
def get_file_tree(
    agent_state: Any,
    path: str = "",
    max_depth: int = 4,
    show_hidden: bool = False,
) -> dict[str, Any]:
    """Return a nested file tree for the Code Workbench panel.

    path: relative to /workspace or absolute. Empty = /workspace itself.
    max_depth: recursion cap (default 4).
    show_hidden: include dotfiles and common noise dirs (node_modules, .git,
      __pycache__) — default false.
    """
    try:
        root = _safe_join(path)
    except ValueError as e:
        return {"success": False, "error": str(e)}

    if not os.path.isdir(root):
        return {"success": False, "error": f"Not a directory: {root}"}

    _skip = {"node_modules", "__pycache__", ".git", ".venv", "venv",
             "dist", "build", ".mypy_cache", ".pytest_cache", ".ruff_cache"}

    entry_count = [0]

    def _walk(dir_path: str, depth: int) -> list[dict[str, Any]]:
        if depth > max_depth or entry_count[0] > _MAX_TREE_ENTRIES:
            return []
        out: list[dict[str, Any]] = []
        try:
            entries = sorted(os.listdir(dir_path), key=str.lower)
        except PermissionError:
            return []
        # Directories first
        dirs = []
        files = []
        for name in entries:
            if entry_count[0] > _MAX_TREE_ENTRIES:
                break
            if name.startswith(".") and not show_hidden:
                continue
            if name in _skip and not show_hidden:
                continue
            full = os.path.join(dir_path, name)
            try:
                if os.path.islink(full):
                    continue
                is_dir = os.path.isdir(full)
                if is_dir:
                    dirs.append((name, full))
                else:
                    files.append((name, full))
            except Exception:
                continue

        for name, full in dirs:
            entry_count[0] += 1
            children = _walk(full, depth + 1)
            rel = os.path.relpath(full, _WORKSPACE_ROOT)
            out.append({
                "name": name,
                "path": rel,
                "type": "dir",
                "children": children,
                "truncated": depth == max_depth and bool(
                    os.listdir(full) if os.access(full, os.R_OK) else False
                ),
            })
        for name, full in files:
            entry_count[0] += 1
            try:
                size = os.path.getsize(full)
            except Exception:
                size = 0
            rel = os.path.relpath(full, _WORKSPACE_ROOT)
            out.append({
                "name": name,
                "path": rel,
                "type": "file",
                "size": size,
                "language": _guess_language(name),
            })
        return out

    tree = _walk(root, 1)
    return {
        "success": True,
        "root": os.path.relpath(root, _WORKSPACE_ROOT) if root != _WORKSPACE_ROOT else "",
        "entries": tree,
        "entry_count": entry_count[0],
        "truncated": entry_count[0] >= _MAX_TREE_ENTRIES,
    }


@register_tool(sandbox_execution=False)
def read_workspace_file(
    agent_state: Any,
    path: str,
    max_bytes: int = 0,
    offset: int = 0,
) -> dict[str, Any]:
    """Read a workspace file. Caps at 2 MB unless max_bytes is smaller.

    Returns text content + language hint. Binary files return metadata only
    with is_binary=true.
    """
    try:
        full = _safe_join(path)
    except ValueError as e:
        return {"success": False, "error": str(e)}
    if not os.path.isfile(full):
        return {"success": False, "error": f"Not a file: {full}"}

    size = os.path.getsize(full)
    cap = min(max_bytes or _MAX_READ_BYTES, _MAX_READ_BYTES)

    if _is_binary(full):
        return {
            "success": True,
            "path": os.path.relpath(full, _WORKSPACE_ROOT),
            "is_binary": True,
            "size": size,
            "language": "binary",
            "content": f"<binary file — {size} bytes>",
        }

    try:
        with open(full, "rb") as f:
            if offset:
                f.seek(offset)
            raw = f.read(cap)
        content = raw.decode("utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Read failed: {e!s}"}

    return {
        "success": True,
        "path": os.path.relpath(full, _WORKSPACE_ROOT),
        "is_binary": False,
        "size": size,
        "bytes_read": len(raw),
        "truncated": len(raw) < size - offset if offset else size > cap,
        "language": _guess_language(full),
        "content": content,
    }


@register_tool(sandbox_execution=False)
def write_workspace_file(
    agent_state: Any,
    path: str,
    content: str,
    create_dirs: bool = True,
) -> dict[str, Any]:
    """Write content to a workspace file. Creates parent dirs if needed.

    Used by the Code Workbench editor to save edits and by the AI-task flow
    to apply agent-suggested modifications.
    """
    try:
        full = _safe_join(path)
    except ValueError as e:
        return {"success": False, "error": str(e)}

    if create_dirs:
        parent = os.path.dirname(full)
        if parent:
            os.makedirs(parent, exist_ok=True)

    try:
        with open(full, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Write failed: {e!s}"}

    return {
        "success": True,
        "path": os.path.relpath(full, _WORKSPACE_ROOT),
        "size": len(content.encode("utf-8")),
    }


@register_tool(sandbox_execution=False)
def search_workspace_files(
    agent_state: Any,
    query: str,
    root: str = "",
    is_regex: bool = False,
    case_sensitive: bool = False,
    glob: str = "",
    max_matches: int = 200,
    context_lines: int = 2,
) -> dict[str, Any]:
    """Grep-style search across workspace. Used by Workbench search bar.

    Skips binary files, caps results at max_matches.
    """
    try:
        root_path = _safe_join(root)
    except ValueError as e:
        return {"success": False, "error": str(e)}

    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        pattern = re.compile(query if is_regex else re.escape(query), flags)
    except re.error as e:
        return {"success": False, "error": f"Invalid regex: {e!s}"}

    glob_re = None
    if glob:
        # Simple glob → regex
        glob_re = re.compile(
            "^" + glob.replace(".", r"\.").replace("*", ".*").replace("?", ".") + "$"
        )

    _skip = {"node_modules", "__pycache__", ".git", ".venv", "venv", "dist", "build"}
    matches: list[dict[str, Any]] = []

    for current, dirs, files in os.walk(root_path):
        dirs[:] = [d for d in dirs if d not in _skip and not d.startswith(".")]
        for fname in files:
            if len(matches) >= max_matches:
                break
            if glob_re and not glob_re.match(fname):
                continue
            full = os.path.join(current, fname)
            if _is_binary(full, sample_size=256):
                continue
            try:
                with open(full, encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
            except Exception:
                continue

            for i, line in enumerate(lines):
                if len(matches) >= max_matches:
                    break
                if pattern.search(line):
                    ctx_before = lines[max(0, i - context_lines) : i]
                    ctx_after = lines[i + 1 : i + 1 + context_lines]
                    matches.append({
                        "path": os.path.relpath(full, _WORKSPACE_ROOT),
                        "line": i + 1,
                        "match": line.rstrip("\n")[:500],
                        "context_before": [l.rstrip("\n")[:200] for l in ctx_before],
                        "context_after": [l.rstrip("\n")[:200] for l in ctx_after],
                    })
        if len(matches) >= max_matches:
            break

    return {
        "success": True,
        "query": query,
        "root": os.path.relpath(root_path, _WORKSPACE_ROOT) if root_path != _WORKSPACE_ROOT else "",
        "match_count": len(matches),
        "truncated": len(matches) >= max_matches,
        "matches": matches,
    }
