#!/usr/bin/env python3
"""
Ziro Agent Interface
"""

import argparse
import asyncio
import logging
import shutil
import sys
import time
from pathlib import Path
from typing import Any

import litellm
from docker.errors import DockerException
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ziro.config import Config, apply_saved_config, save_current_config
from ziro.config.config import resolve_llm_config
from ziro.llm.utils import resolve_ziro_model


apply_saved_config()

from ziro.interface.cli import run_cli  # noqa: E402
from ziro.interface.tui import run_tui  # noqa: E402
from ziro.interface.utils import (  # noqa: E402
    assign_workspace_subdirs,
    build_final_stats_text,
    check_docker_connection,
    clone_repository,
    collect_local_sources,
    generate_run_name,
    image_exists,
    infer_target_type,
    process_pull_line,
    rewrite_localhost_targets,
    validate_config_file,
    validate_llm_response,
)
from ziro.runtime.docker_runtime import HOST_GATEWAY_HOSTNAME  # noqa: E402
from ziro.telemetry import posthog  # noqa: E402
from ziro.telemetry.tracer import get_global_tracer  # noqa: E402


logging.getLogger().setLevel(logging.ERROR)


def validate_environment() -> None:  # noqa: PLR0912, PLR0915
    console = Console()
    missing_required_vars = []
    missing_optional_vars = []

    ziro_llm = Config.get("ziro_llm")
    uses_ziro_models = ziro_llm and ziro_llm.startswith("ziro/")

    if not ziro_llm:
        missing_required_vars.append("ZIRO_LLM")

    has_base_url = uses_ziro_models or any(
        [
            Config.get("llm_api_base"),
            Config.get("openai_api_base"),
            Config.get("litellm_base_url"),
            Config.get("ollama_api_base"),
        ]
    )

    if not Config.get("llm_api_key"):
        missing_optional_vars.append("LLM_API_KEY")

    if not has_base_url:
        missing_optional_vars.append("LLM_API_BASE")

    if not Config.get("perplexity_api_key"):
        missing_optional_vars.append("PERPLEXITY_API_KEY")

    if not Config.get("ziro_reasoning_effort"):
        missing_optional_vars.append("ZIRO_REASONING_EFFORT")

    if missing_required_vars:
        error_text = Text()
        error_text.append("MISSING REQUIRED ENVIRONMENT VARIABLES", style="bold red")
        error_text.append("\n\n", style="white")

        for var in missing_required_vars:
            error_text.append(f"• {var}", style="bold yellow")
            error_text.append(" is not set\n", style="white")

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="dim white")
            for var in missing_optional_vars:
                error_text.append(f"• {var}", style="dim yellow")
                error_text.append(" is not set\n", style="dim white")

        error_text.append("\nRequired environment variables:\n", style="white")
        for var in missing_required_vars:
            if var == "ZIRO_LLM":
                error_text.append("• ", style="white")
                error_text.append("ZIRO_LLM", style="bold cyan")
                error_text.append(
                    " - Model name to use with litellm (e.g., 'openai/gpt-5.4')\n",
                    style="white",
                )

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="white")
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_KEY", style="bold cyan")
                    error_text.append(
                        " - API key for the LLM provider "
                        "(not needed for local models, Vertex AI, AWS, etc.)\n",
                        style="white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_BASE", style="bold cyan")
                    error_text.append(
                        " - Custom API base URL if using local models (e.g., Ollama, LMStudio)\n",
                        style="white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("PERPLEXITY_API_KEY", style="bold cyan")
                    error_text.append(
                        " - API key for Perplexity AI web search (enables real-time research)\n",
                        style="white",
                    )
                elif var == "ZIRO_REASONING_EFFORT":
                    error_text.append("• ", style="white")
                    error_text.append("ZIRO_REASONING_EFFORT", style="bold cyan")
                    error_text.append(
                        " - Reasoning effort level: none, minimal, low, medium, high, xhigh "
                        "(default: high)\n",
                        style="white",
                    )

        error_text.append("\nExample setup:\n", style="white")
        error_text.append("export ZIRO_LLM='openai/gpt-5.4'\n", style="dim white")

        if missing_optional_vars:
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append(
                        "export LLM_API_KEY='your-api-key-here'  "
                        "# not needed for local models, Vertex AI, AWS, etc.\n",
                        style="dim white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append(
                        "export LLM_API_BASE='http://localhost:11434'  "
                        "# needed for local models only\n",
                        style="dim white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append(
                        "export PERPLEXITY_API_KEY='your-perplexity-key-here'\n", style="dim white"
                    )
                elif var == "ZIRO_REASONING_EFFORT":
                    error_text.append(
                        "export ZIRO_REASONING_EFFORT='high'\n",
                        style="dim white",
                    )

        panel = Panel(
            error_text,
            title="[bold white]ZIRO",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)


def check_docker_installed() -> None:
    console = Console()

    if shutil.which("docker") is None:
        error_text = Text()
        error_text.append("DOCKER NOT FOUND\n\n", style="bold red")
        error_text.append("Ziro needs Docker to run its security sandbox.\n\n", style="white")
        error_text.append("Install Docker:\n", style="bold white")
        error_text.append("  Ubuntu/Debian  ", style="dim")
        error_text.append("curl -fsSL https://get.docker.com | sh\n", style="#a855f7")
        error_text.append("  macOS          ", style="dim")
        error_text.append("brew install --cask docker\n", style="#a855f7")
        error_text.append("  Other          ", style="dim")
        error_text.append("https://docs.docker.com/get-docker/", style="#60a5fa")

        panel = Panel(
            error_text,
            title="[bold white]ZIRO",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n", panel, "\n")
        sys.exit(1)

    # Check if Docker daemon is running
    import subprocess

    result = subprocess.run(  # noqa: S603, S607
        ["docker", "info"],
        capture_output=True,
        timeout=10,
    )
    if result.returncode != 0:
        error_text = Text()
        error_text.append("DOCKER NOT RUNNING\n\n", style="bold red")
        error_text.append("Docker is installed but the daemon is not running.\n\n", style="white")
        error_text.append("Start Docker:\n", style="bold white")
        error_text.append("  Linux   ", style="dim")
        error_text.append("sudo systemctl start docker\n", style="#a855f7")
        error_text.append("  macOS   ", style="dim")
        error_text.append("open -a Docker", style="#a855f7")

        panel = Panel(
            error_text,
            title="[bold white]ZIRO",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n", panel, "\n")
        sys.exit(1)


async def warm_up_llm() -> None:
    console = Console()

    try:
        model_name, api_key, api_base = resolve_llm_config()
        litellm_model, _ = resolve_ziro_model(model_name)
        litellm_model = litellm_model or model_name

        test_messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Reply with just 'OK'."},
        ]

        llm_timeout = int(Config.get("llm_timeout") or "300")

        completion_kwargs: dict[str, Any] = {
            "model": litellm_model,
            "messages": test_messages,
            "timeout": llm_timeout,
        }
        if api_key:
            completion_kwargs["api_key"] = api_key
        if api_base:
            completion_kwargs["api_base"] = api_base

        response = litellm.completion(**completion_kwargs)

        validate_llm_response(response)

    except Exception as e:  # noqa: BLE001
        error_str = str(e).lower()
        error_text = Text()
        error_text.append("LLM CONNECTION FAILED\n\n", style="bold red")

        # Detect specific error types and give actionable advice
        if "401" in error_str or "unauthorized" in error_str or "invalid api key" in error_str:
            error_text.append("Invalid API key. ", style="bold yellow")
            error_text.append("Check that LLM_API_KEY is correct.\n", style="white")
            error_text.append(f"  Current model: {Config.get('ziro_llm')}\n", style="dim")
        elif "404" in error_str or "not found" in error_str:
            error_text.append("Model not found. ", style="bold yellow")
            model = Config.get("ziro_llm")
            error_text.append(f'Check that ZIRO_LLM="{model}" is a valid model name.\n', style="white")
        elif "timeout" in error_str or "timed out" in error_str:
            error_text.append("Connection timed out. ", style="bold yellow")
            error_text.append("The LLM provider is not responding.\n", style="white")
            error_text.append("  - Check your internet connection\n", style="dim")
            error_text.append("  - If using local model, ensure it's running\n", style="dim")
        elif "connection" in error_str or "refused" in error_str:
            error_text.append("Cannot reach LLM provider. ", style="bold yellow")
            api_base = Config.get("llm_api_base") or Config.get("ollama_api_base")
            if api_base:
                error_text.append(f"  Endpoint: {api_base}\n", style="dim")
            error_text.append("  - Check that the server is running\n", style="dim")
            error_text.append("  - Verify LLM_API_BASE is correct\n", style="dim")
        else:
            error_text.append("Could not connect to the language model.\n", style="white")

        error_text.append(f"\nError: {e}", style="dim")

        panel = Panel(
            error_text,
            title="[bold white]ZIRO",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)


def get_version() -> str:
    try:
        from importlib.metadata import version

        return version("ziro-agent")
    except Exception:  # noqa: BLE001
        return "unknown"


def check_for_updates() -> None:
    """Check GitHub for newer version, non-blocking."""
    try:
        import requests

        current = get_version()
        if current == "unknown":
            return

        resp = requests.get(
            "https://api.github.com/repos/Xyeino/ziro/releases/latest",
            timeout=3,
        )
        if resp.status_code != 200:
            return

        latest = resp.json().get("tag_name", "").lstrip("v")
        if not latest:
            return

        from packaging.version import Version

        if Version(latest) > Version(current):
            console = Console()
            console.print(
                f"  [dim]Update available:[/] [bold #a855f7]v{latest}[/] "
                f"[dim](current: v{current})[/]"
            )
            console.print(
                "  [dim]Run:[/] pip install --upgrade git+https://github.com/Xyeino/ziro.git\n"
            )
    except Exception:  # noqa: BLE001
        pass


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ziro Multi-Agent Cybersecurity Penetration Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Web application penetration test
  ziro --target https://example.com

  # GitHub repository analysis
  ziro --target https://github.com/user/repo
  ziro --target git@github.com:user/repo.git

  # Local code analysis
  ziro --target ./my-project

  # Domain penetration test
  ziro --target example.com

  # IP address penetration test
  ziro --target 192.168.1.42

  # Multiple targets (e.g., white-box testing with source and deployed app)
  ziro --target https://github.com/user/repo --target https://example.com
  ziro --target ./my-project --target https://staging.example.com --target https://prod.example.com

  # Custom instructions (inline)
  ziro --target example.com --instruction "Focus on authentication vulnerabilities"

  # Custom instructions (from file)
  ziro --target example.com --instruction-file ./instructions.txt
  ziro --target https://app.com --instruction-file /path/to/detailed_instructions.md
        """,
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"ziro {get_version()}",
    )

    parser.add_argument(
        "-t",
        "--target",
        type=str,
        required=True,
        action="append",
        help="Target to test (URL, repository, local directory path, domain name, or IP address). "
        "Can be specified multiple times for multi-target scans.",
    )
    parser.add_argument(
        "--instruction",
        type=str,
        help="Custom instructions for the penetration test. This can be "
        "specific vulnerability types to focus on (e.g., 'Focus on IDOR and XSS'), "
        "testing approaches (e.g., 'Perform thorough authentication testing'), "
        "test credentials (e.g., 'Use the following credentials to access the app: "
        "admin:password123'), "
        "or areas of interest (e.g., 'Check login API endpoint for security issues').",
    )

    parser.add_argument(
        "--instruction-file",
        type=str,
        help="Path to a file containing detailed custom instructions for the penetration test. "
        "Use this option when you have lengthy or complex instructions saved in a file "
        "(e.g., '--instruction-file ./detailed_instructions.txt').",
    )

    parser.add_argument(
        "-n",
        "--non-interactive",
        action="store_true",
        help=(
            "Run in non-interactive mode (no TUI, exits on completion). "
            "Default is interactive mode with TUI."
        ),
    )

    parser.add_argument(
        "-m",
        "--scan-mode",
        type=str,
        choices=["quick", "standard", "deep"],
        default="deep",
        help=(
            "Scan mode: "
            "'quick' for fast CI/CD checks, "
            "'standard' for routine testing, "
            "'deep' for thorough security reviews (default). "
            "Default: deep."
        ),
    )

    parser.add_argument(
        "--config",
        type=str,
        help="Path to a custom config file (JSON) to use instead of ~/.ziro/cli-config.json",
    )

    args = parser.parse_args()

    if args.instruction and args.instruction_file:
        parser.error(
            "Cannot specify both --instruction and --instruction-file. Use one or the other."
        )

    if args.instruction_file:
        instruction_path = Path(args.instruction_file)
        try:
            with instruction_path.open(encoding="utf-8") as f:
                args.instruction = f.read().strip()
                if not args.instruction:
                    parser.error(f"Instruction file '{instruction_path}' is empty")
        except Exception as e:  # noqa: BLE001
            parser.error(f"Failed to read instruction file '{instruction_path}': {e}")

    args.targets_info = []
    for target in args.target:
        try:
            target_type, target_dict = infer_target_type(target)

            if target_type == "local_code":
                display_target = target_dict.get("target_path", target)
            else:
                display_target = target

            args.targets_info.append(
                {"type": target_type, "details": target_dict, "original": display_target}
            )
        except ValueError:
            parser.error(f"Invalid target '{target}'")

    assign_workspace_subdirs(args.targets_info)
    rewrite_localhost_targets(args.targets_info, HOST_GATEWAY_HOSTNAME)

    return args


def _format_duration(seconds: float) -> str:
    """Format seconds into human-readable duration."""
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h > 0:
        return f"{h}h {m}m {s}s"
    if m > 0:
        return f"{m}m {s}s"
    return f"{s}s"


def _get_severity_color(severity: str) -> str:
    colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#22c55e",
        "info": "#3b82f6",
    }
    return colors.get(severity.lower(), "#6b7280")


def display_completion_message(
    args: argparse.Namespace, results_path: Path, scan_duration: float = 0.0
) -> None:
    console = Console()
    tracer = get_global_tracer()

    scan_completed = False
    if tracer and tracer.scan_results:
        scan_completed = tracer.scan_results.get("scan_completed", False)

    # --- Header ---
    if scan_completed:
        header = Text("SCAN COMPLETE", style="bold #a855f7")
    else:
        header = Text("SESSION ENDED", style="bold #eab308")

    # --- Target ---
    target_text = Text()
    target_text.append("Target  ", style="dim")
    if len(args.targets_info) == 1:
        target_text.append(args.targets_info[0]["original"], style="bold white")
    else:
        target_text.append(f"{len(args.targets_info)} targets", style="bold white")

    # --- Vulnerability summary table ---
    vuln_text = Text()
    if tracer and tracer.vulnerability_reports:
        vulns = tracer.vulnerability_reports
        severity_counts: dict[str, int] = {}
        for v in vulns:
            sev = v.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        vuln_text.append(f"\nFound  ", style="dim")
        vuln_text.append(f"{len(vulns)}", style="bold white")
        vuln_text.append(" vulnerabilities  ", style="dim")

        parts = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                parts.append((f"{count} {sev.upper()}", _get_severity_color(sev)))

        for i, (label, color) in enumerate(parts):
            if i > 0:
                vuln_text.append(" · ", style="dim")
            vuln_text.append(label, style=f"bold {color}")
    else:
        vuln_text.append("\nFound  ", style="dim")
        vuln_text.append("0", style="bold white")
        vuln_text.append(" vulnerabilities", style="dim")

    # --- Stats line ---
    stats_line = Text()
    if tracer:
        agent_count = len(tracer.agents)
        tool_count = tracer.get_real_tool_count()
        llm_stats = tracer.get_total_llm_stats()
        total_tokens = llm_stats.get("total", {}).get("total_tokens", 0)

        stats_line.append("\n")
        stats_line.append("Agents ", style="dim")
        stats_line.append(str(agent_count), style="white")
        stats_line.append("  ·  ", style="dim")
        stats_line.append("Tools ", style="dim")
        stats_line.append(str(tool_count), style="white")
        stats_line.append("  ·  ", style="dim")
        stats_line.append("Tokens ", style="dim")
        stats_line.append(f"{total_tokens:,}", style="white")

        if scan_duration > 0:
            stats_line.append("  ·  ", style="dim")
            stats_line.append("Duration ", style="dim")
            stats_line.append(_format_duration(scan_duration), style="white")

    # --- Output path ---
    output_text = Text()
    output_text.append("\nOutput ", style="dim")
    output_text.append(str(results_path), style="#60a5fa")

    # --- Assemble panel ---
    panel_content = Text.assemble(
        header, "\n\n", target_text, vuln_text, stats_line, output_text
    )

    border_style = "#a855f7" if scan_completed else "#eab308"

    panel = Panel(
        panel_content,
        title="[bold white]ZIRO",
        title_align="left",
        border_style=border_style,
        padding=(1, 2),
    )

    console.print("\n")
    console.print(panel)
    console.print()
    console.print("[#60a5fa]github.com/Xyeino/ziro[/]")
    console.print()


def pull_docker_image() -> None:
    console = Console()
    client = check_docker_connection()

    if image_exists(client, Config.get("ziro_image")):  # type: ignore[arg-type]
        return

    console.print()
    console.print(f"[dim]Pulling image[/] {Config.get('ziro_image')}")
    console.print("[dim yellow]This only happens on first run and may take a few minutes...[/]")
    console.print()

    with console.status("[bold cyan]Downloading image layers...", spinner="dots") as status:
        try:
            layers_info: dict[str, str] = {}
            last_update = ""

            for line in client.api.pull(Config.get("ziro_image"), stream=True, decode=True):
                last_update = process_pull_line(line, layers_info, status, last_update)

        except DockerException as e:
            console.print()
            error_text = Text()
            error_text.append("FAILED TO PULL IMAGE", style="bold red")
            error_text.append("\n\n", style="white")
            error_text.append(f"Could not download: {Config.get('ziro_image')}\n", style="white")
            error_text.append(str(e), style="dim red")

            panel = Panel(
                error_text,
                title="[bold white]ZIRO",
                title_align="left",
                border_style="red",
                padding=(1, 2),
            )
            console.print(panel, "\n")
            sys.exit(1)

    success_text = Text()
    success_text.append("Docker image ready", style="#a855f7")
    console.print(success_text)
    console.print()


def apply_config_override(config_path: str) -> None:
    Config._config_file_override = validate_config_file(config_path)
    apply_saved_config(force=True)


def persist_config() -> None:
    if Config._config_file_override is None:
        save_current_config()


def main() -> None:
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    args = parse_arguments()

    if args.config:
        apply_config_override(args.config)

    check_for_updates()

    check_docker_installed()
    pull_docker_image()

    validate_environment()
    asyncio.run(warm_up_llm())

    persist_config()

    _scan_start_time = time.monotonic()

    args.run_name = generate_run_name(args.targets_info)

    for target_info in args.targets_info:
        if target_info["type"] == "repository":
            repo_url = target_info["details"]["target_repo"]
            dest_name = target_info["details"].get("workspace_subdir")
            cloned_path = clone_repository(repo_url, args.run_name, dest_name)
            target_info["details"]["cloned_repo_path"] = cloned_path

    args.local_sources = collect_local_sources(args.targets_info)

    is_whitebox = bool(args.local_sources)

    posthog.start(
        model=Config.get("ziro_llm"),
        scan_mode=args.scan_mode,
        is_whitebox=is_whitebox,
        interactive=not args.non_interactive,
        has_instructions=bool(args.instruction),
    )

    exit_reason = "user_exit"
    try:
        if args.non_interactive:
            asyncio.run(run_cli(args))
        else:
            asyncio.run(run_tui(args))
    except KeyboardInterrupt:
        exit_reason = "interrupted"
    except Exception as e:
        exit_reason = "error"
        posthog.error("unhandled_exception", str(e))
        raise
    finally:
        tracer = get_global_tracer()
        if tracer:
            posthog.end(tracer, exit_reason=exit_reason)

    scan_duration = time.monotonic() - _scan_start_time
    results_path = Path("ziro_runs") / args.run_name
    display_completion_message(args, results_path, scan_duration=scan_duration)

    if args.non_interactive:
        tracer = get_global_tracer()
        if tracer and tracer.vulnerability_reports:
            sys.exit(2)


if __name__ == "__main__":
    main()
