from typing import Any, Literal

from ziro.tools.registry import register_tool

from .manager import get_manager


@register_tool(sandbox_execution=True)
def tmux_interactive(
    agent_state: Any,
    action: Literal["start", "send", "key", "read", "wait", "kill", "list"],
    name: str = "",
    command: str = "",
    text: str = "",
    key: str = "",
    pattern: str = "",
    prompt_regex: str = "",
    work_dir: str = "/workspace",
    wait_for_prompt_after_send: bool = True,
    lines: int = 0,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Persistent tmux session for interactive security tools.

    Use this for tools that take over the shell and expect a series of interactive
    commands: msfconsole, sliver-client, sqlmap --wizard, evil-winrm, hydra --pause,
    wpscan interactive, mysql, psql, python/ipython REPL, pdb debugger, smbclient,
    ftp, telnet, custom rlwrap-ed tools.

    Actions:
    - start: Launch a new session by name, running `command` inside it. Optional
      `prompt_regex` overrides the auto-detected prompt pattern. Well-known tools
      (msfconsole, sliver, sqlmap, etc.) get their prompts inferred automatically.
    - send: Send a line of `text` to the session (Enter appended). By default
      blocks until the prompt reappears (wait_for_prompt_after_send=True).
    - key: Send a raw key like `C-c`, `Up`, `Enter`, `Tab`, `BSpace`. No newline.
    - read: Return the current pane buffer. Pass `lines=N` to tail the last N lines.
    - wait: Block until `pattern` matches anywhere in the buffer, or until the
      prompt returns if no pattern is given. Useful for waiting on slow operations
      ("[+] Session opened:", "[*] Exploit completed").
    - kill: Terminate the session.
    - list: Return metadata for all this agent's interactive sessions.

    Session names are per-agent. You can run up to 8 concurrent sessions per agent.
    """
    manager = get_manager()

    if action == "list":
        sessions = manager.list_sessions()
        return {"success": True, "sessions": sessions, "count": len(sessions)}

    if action == "start":
        if not name or not command:
            return {"success": False, "error": "start requires both name and command"}
        return manager.start(
            name=name,
            command=command,
            work_dir=work_dir,
            prompt_regex=prompt_regex or None,
        )

    if action == "send":
        if not name:
            return {"success": False, "error": "send requires name"}
        return manager.send(
            name=name,
            text=text,
            wait_for_prompt=wait_for_prompt_after_send,
            timeout=timeout if timeout > 0 else None,
        )

    if action == "key":
        if not name or not key:
            return {"success": False, "error": "key requires name and key"}
        return manager.send_key(name=name, key=key)

    if action == "read":
        if not name:
            return {"success": False, "error": "read requires name"}
        return manager.read(name=name, lines=lines or None)

    if action == "wait":
        if not name:
            return {"success": False, "error": "wait requires name"}
        return manager.wait_for(
            name=name,
            pattern=pattern or None,
            timeout=timeout if timeout > 0 else None,
        )

    if action == "kill":
        if not name:
            return {"success": False, "error": "kill requires name"}
        return manager.kill(name=name)

    return {"success": False, "error": f"unknown action: {action}"}
