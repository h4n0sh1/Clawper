"""
CLI interface for Clawper.
"""

from __future__ import annotations

import os
import sys
import json
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.markup import escape

from clawper import __version__
from clawper.config import (
    AgentConfig,
    ClawperConfig,
    ExecutionConfig,
    FileConditionConfig,
    FlagConditionConfig,
    RootConditionConfig,
    ScriptConditionConfig,
    TargetConfig,
)
from clawper.engine.supervisor import ClawperEngine
from clawper.workspace.manager import WorkspaceManager
from clawper.workspace.reporter import CTFReporter

console = Console()


def print_banner() -> None:
    banner = r"""
 [bold cyan]  ____ _                                [/bold cyan]
 [bold cyan] / ___| | __ ___      ___ __   ___ _ __ [/bold cyan]
 [bold cyan]| |   | |/ _` \ \ /\ / / '_ \ / _ \ '__|[/bold cyan]
 [bold cyan]| |___| | (_| |\ V  V /| |_) |  __/ |   [/bold cyan]
 [bold cyan] \____|_|\__,_| \_/\_/ | .__/ \___|_|   [/bold cyan]
 [bold cyan]                       |_|               [/bold cyan]
 [bold yellow]Autonomous & Unattended CTF Wrapper for Claude Code[/bold yellow]
"""
    console.print(banner)


@click.group(invoke_without_command=True)
@click.option("--version", "-v", is_flag=True, help="Show Clawper version.")
@click.pass_context
def main(ctx: click.Context, version: bool) -> None:
    """Clawper: Autonomous & Unattended CTF Wrapper for Claude Code."""
    if version:
        console.print(f"[bold cyan]Clawper[/bold cyan] version [bold green]{__version__}[/bold green]")
        ctx.exit()
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print(ctx.get_help())


@main.command()
@click.option("--config", "-c", "config_file", type=click.Path(exists=True), help="Path to clawper.yaml or JSON config.")
@click.option("--target", "-t", "target_ip", help="Target IP address or host.")
@click.option("--box-name", "-b", help="CTF box or challenge name (e.g., 'Sau', 'Lame').")
@click.option("--prompt", "-p", "user_prompt", default="Root the box, capture user and root flags, and document all findings.", help="Mission prompt for the agent.")
@click.option("--flags", "-f", "flags_count", default=2, type=int, help="Required number of flags to capture (default: 2 for HTB user+root).")
@click.option("--flag-pattern", help="Custom regex pattern for flags (e.g., 'CTF\\{[^\\}]+\\}').")
@click.option("--require-root/--no-require-root", default=True, help="Require verification of root privileges.")
@click.option("--platform", default="htb", help="Target platform (htb, thm, prolab, generic).")
@click.option("--agent", "agent_type", default="claude_code", type=click.Choice(["claude_code", "mock", "command"], case_sensitive=False), help="Agent driver to use.")
@click.option("--claude-bin", default="claude", help="Path to Claude Code CLI binary.")
@click.option("--model", "-m", help="Model to pass to Claude Code CLI.")
@click.option("--workspace", "-w", default="./clawper_workspace", help="Path to workspace directory.")
@click.option("--max-iterations", default=0, type=int, help="Maximum iterations safeguard (0 = unlimited / never stop until solved).")
@click.option("--timeout", default=600, type=int, help="Timeout per iteration in seconds.")
@click.option("--delay", default=2.0, type=float, help="Delay in seconds between iterations.")
def run(
    config_file: Optional[str],
    target_ip: Optional[str],
    box_name: Optional[str],
    user_prompt: str,
    flags_count: int,
    flag_pattern: Optional[str],
    require_root: bool,
    platform: str,
    agent_type: str,
    claude_bin: str,
    model: Optional[str],
    workspace: str,
    max_iterations: int,
    timeout: int,
    delay: float,
) -> None:
    """Start autonomous CTF solving session."""
    print_banner()

    # Build or load configuration
    if config_file:
        cfg_path = Path(config_file)
        if cfg_path.suffix.lower() in [".yaml", ".yml"]:
            config = ClawperConfig.from_yaml(cfg_path)
        else:
            config = ClawperConfig.from_json(cfg_path)
        console.print(f"[green]Loaded configuration from {config_file}[/green]")
    else:
        config = ClawperConfig(
            prompt=user_prompt,
            target=TargetConfig(
                ip=target_ip,
                box_name=box_name,
                platform=platform,
            ),
            flags=FlagConditionConfig(
                required_count=flags_count,
                require_root_flag=require_root,
            ),
            root=RootConditionConfig(
                enabled=require_root,
            ),
            agent=AgentConfig(
                driver_type=agent_type,
                binary_path=claude_bin,
                timeout_per_run=timeout,
                model=model,
            ),
            execution=ExecutionConfig(
                max_iterations=max_iterations,
                loop_delay=delay,
            ),
            workspace_dir=workspace,
        )

    if flag_pattern:
        config.flags.patterns.insert(0, flag_pattern)

    # Display configuration panel
    table = Table(title="Clawper Mission Briefing", show_header=True, header_style="bold magenta")
    table.add_column("Parameter", style="cyan")
    table.add_column("Value", style="yellow")
    table.add_row("Target", config.target.summary())
    table.add_row("Agent Driver", config.agent.driver_type)
    table.add_row("Required Flags", str(config.flags.required_count))
    table.add_row("Root Required", str(config.root.enabled))
    table.add_row("Max Iterations", "Unlimited (Never Stop)" if config.execution.max_iterations == 0 else str(config.execution.max_iterations))
    table.add_row("Workspace", config.workspace_dir)
    console.print(table)
    console.print()

    # Callbacks for rich output
    def on_status(msg: str, state) -> None:
        safe = escape(msg)
        if "VICTORY" in msg:
            console.print(Panel(safe, style="bold green"))
        elif "NEW FLAG" in msg:
            console.print(f"[bold green]🚩 {safe}[/bold green]")
        elif msg.startswith(">>>"):
            console.print(f"[bold cyan]{safe}[/bold cyan]")
        else:
            console.print(f"[blue][*][/blue] {safe}")

    def on_stream(chunk: str) -> None:
        # Driver emits concise, prefixed lines (⚙ tool, 💬 text, ↳ result).
        # Render them with light styling so the live feed reads like a chat.
        for line in chunk.splitlines():
            if not line:
                continue
            safe = escape(line)
            if line.startswith("💬"):
                console.print(f"[white]{safe}[/white]")
            elif line.startswith("⚙"):
                console.print(f"[cyan]{safe}[/cyan]")
            elif line.lstrip().startswith("↳"):
                console.print(f"[dim]{safe}[/dim]")
            elif line.startswith("✗") or "API Error" in line:
                console.print(f"[red]{safe}[/red]")
            elif line.startswith("[clawper]"):
                console.print(f"[yellow]{safe}[/yellow]")
            else:
                console.print(safe, highlight=False)

    def on_flag(flag: str, src: str) -> None:
        console.print(Panel(f"🚩 FLAG CAPTURED: [bold yellow]{escape(flag)}[/bold yellow]\nSource: {escape(src)}", border_style="green"))

    engine = ClawperEngine(
        config=config,
        on_status_update=on_status,
        on_stream_output=on_stream,
        on_flag_found=on_flag,
    )

    final_state = engine.run()

    # Print final summary table
    summary_table = Table(title="Mission Results", show_header=True, header_style="bold green")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Result", style="bold white")
    summary_table.add_row("Success", "[bold green]YES[/bold green]" if final_state.success else "[bold red]NO[/bold red]")
    summary_table.add_row("Iterations Completed", str(final_state.iterations_completed))
    summary_table.add_row("Flags Captured", f"{len(final_state.captured_flags)}/{config.flags.required_count}")
    for idx, f in enumerate(final_state.captured_flags):
        flag_val = f.get("flag", str(f)) if isinstance(f, dict) else str(f)
        summary_table.add_row(f"Flag #{idx+1}", f"[bold yellow]{flag_val}[/bold yellow]")
    console.print()
    console.print(summary_table)


@main.command()
@click.option("--output", "-o", default="clawper.yaml", help="Destination file path.")
def init(output: str) -> None:
    """Generate a template configuration file."""
    config = ClawperConfig(
        prompt="Root the target box, obtain all flags (user and root), and document your steps.",
        target=TargetConfig(
            ip="10.10.11.X",
            box_name="ExampleBox",
            platform="htb",
            credentials={"admin": "password123"},
            hints=["Web service on port 8080 contains a file upload vulnerability"],
        ),
        flags=FlagConditionConfig(
            required_count=2,
            require_user_flag=True,
            require_root_flag=True,
        ),
        root=RootConditionConfig(
            enabled=True,
        ),
        agent=AgentConfig(
            driver_type="claude_code",
            binary_path="claude",
            cli_flags=["--dangerously-skip-permissions"],
        ),
        execution=ExecutionConfig(
            max_iterations=0,
            loop_delay=2.0,
            writeup_path="WRITEUP.md",
        ),
        workspace_dir="./clawper_workspace",
    )
    config.to_yaml(output)
    console.print(f"[bold green]Created template configuration in {output}[/bold green]")


@main.command()
@click.option("--workspace", "-w", default="./clawper_workspace", help="Workspace directory.")
def status(workspace: str) -> None:
    """Inspect state and captured flags of a workspace."""
    wm = WorkspaceManager(workspace)
    state = wm.load_state()
    if not state:
        console.print(f"[red]No active or saved session found in {workspace}[/red]")
        return

    table = Table(title=f"Session Status ({state.get('session_id', 'unknown')})", show_header=True)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="yellow")
    table.add_row("Success", "[green]YES[/green]" if state.get("success") else "[yellow]IN PROGRESS[/yellow]")
    table.add_row("Iterations Completed", str(state.get("iterations_completed", 0)))
    table.add_row("Phase", state.get("phase", "unknown").upper())
    table.add_row("Captured Flags", str(len(state.get("captured_flags", []))))
    console.print(table)

    flags = state.get("captured_flags", [])
    if flags:
        console.print("\n[bold green]Captured Flags:[/bold green]")
        for f in flags:
            flag_val = f.get("flag", str(f)) if isinstance(f, dict) else str(f)
            console.print(f"  🚩 [bold yellow]{flag_val}[/bold yellow] (Iteration {f.get('iteration', '-')})")


@main.command()
@click.option("--workspace", "-w", default="./clawper_workspace", help="Workspace directory.")
@click.option("--output", "-o", help="Custom output path for the report markdown.")
@click.option("--writeup", is_flag=True, help="Generate the legacy CTF writeup instead of the professional report.")
def report(workspace: str, output: Optional[str], writeup: bool) -> None:
    """Generate the professional engagement report (or --writeup for the legacy format)."""
    wm = WorkspaceManager(workspace)
    state = wm.load_state()
    if not state:
        console.print(f"[red]No saved session state found in {workspace}[/red]")
        return

    # Recover target metadata from the saved report.json if present.
    config = ClawperConfig(workspace_dir=workspace)
    report_json = wm.root_dir / "report.json"
    if report_json.exists():
        try:
            saved = json.loads(report_json.read_text(encoding="utf-8"))
            if isinstance(saved.get("config"), dict):
                config = ClawperConfig.from_dict(saved["config"])
        except Exception:
            pass

    if writeup:
        reporter = CTFReporter(wm.root_dir, config)
        out_path = Path(output) if output else None
        content = reporter.generate_writeup(state, out_path)
        console.print(Panel(content[:4000], title="CTF Writeup Preview", border_style="cyan"))
        return

    from clawper.workspace.pro_report import ProfessionalReportBuilder
    content = ProfessionalReportBuilder(wm.root_dir, config).build(state)
    out_path = Path(output) if output else (wm.root_dir / "REPORT.md")
    out_path.write_text(content, encoding="utf-8")
    console.print(f"[bold green]Professional report written to {out_path}[/bold green]")
    console.print(Panel(content[:4000], title="Report Preview (truncated)", border_style="cyan"))


if __name__ == "__main__":
    main()
