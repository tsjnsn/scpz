"""SCPeasy CLI — optimize and validate AWS SCP policies."""

from __future__ import annotations

import difflib
import json
import shutil
from pathlib import Path  # noqa: TC003  # required at runtime by Typer
from typing import TYPE_CHECKING

import typer
from rich.console import Console
from rich.panel import Panel

from scpeasy import __version__
from scpeasy.config import SUPPORTED_API_VERSION, SUPPORTED_KIND, OptimizerConfig
from scpeasy.optimizer import OptimizationResult, optimize
from scpeasy.splitter import SplitError, split_if_needed
from scpeasy.validator import Severity, ValidationResult, validate_document, validate_file

if TYPE_CHECKING:
    from scpeasy.models import ScpDocument

app = typer.Typer(
    name="scpeasy",
    help="Intelligently optimize AWS SCP JSONs.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console(stderr=True)
out = Console()


def version_callback(value: bool) -> None:
    if value:
        out.print(f"scpeasy {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """SCPeasy — Intelligently optimize AWS SCP JSONs."""


# ── optimize command ─────────────────────────────────────────────────


@app.command()
def optimize_cmd(
    path: Path = typer.Argument(..., help="SCP JSON file or directory of JSON files."),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output path. Defaults to in-place with .bak backup.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show diff + summary without writing.",
    ),
    summary_only: bool = typer.Option(
        False,
        "--summary-only",
        help="Show optimization summary only (no diff).",
    ),
    no_split: bool = typer.Option(
        False,
        "--no-split",
        help="Error instead of splitting into multiple SCPs.",
    ),
) -> None:
    """Optimize SCP JSON file(s) to fit within AWS limits."""
    files = _resolve_files(path)
    if not files:
        console.print("[red]No JSON files found.[/red]")
        raise typer.Exit(code=1)

    exit_code = 0
    for file_path in files:
        try:
            _optimize_file(
                file_path,
                output=output,
                dry_run=dry_run,
                summary_only=summary_only,
                no_split=no_split,
            )
        except (SplitError, typer.Exit) as exc:
            if isinstance(exc, SplitError):
                console.print(f"[red]Error:[/red] {exc}")
                exit_code = 1
            else:
                raise

    if exit_code != 0:
        raise typer.Exit(code=exit_code)


def _optimize_file(
    file_path: Path,
    *,
    output: Path | None,
    dry_run: bool,
    summary_only: bool,
    no_split: bool,
) -> None:
    """Optimize a single SCP file."""
    # Load project config (walks up from file_path; falls back to defaults)
    try:
        cfg = OptimizerConfig.load(file_path)
    except ValueError as exc:
        console.print(f"[red]Config error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    # Validate first
    doc, val_result = validate_file(file_path)
    _print_validation(val_result, file_path)
    if doc is None:
        raise typer.Exit(code=1)

    # Optimize
    result = optimize(doc, config=cfg)

    # --no-split CLI flag overrides config; otherwise honour split pass config
    split_enabled = not no_split and cfg.spec.optimizer.split.enabled and (
        cfg.spec.optimizer.split.strategy == "auto"
    )

    # Check if splitting is needed
    if not result.fits_single_scp and split_enabled:
        try:
            split_result = split_if_needed(result.optimized)
        except SplitError:
            raise
        if split_result.count > 1:
            _handle_split_output(
                file_path,
                result,
                split_result.documents,
                output=output,
                dry_run=dry_run,
                summary_only=summary_only,
            )
            return
    elif not result.fits_single_scp and not split_enabled:
        console.print(f"[red]Error:[/red] {file_path.name} exceeds limits and splitting is disabled.")
        raise typer.Exit(code=1)

    # Single file output
    if dry_run or summary_only:
        _print_summary(result, file_path)
        if dry_run and not summary_only:
            _print_diff(
                doc.to_json(),
                result.optimized.to_json(),
                file_path.name,
            )
    else:
        _write_optimized(file_path, result.optimized, output)
        _print_summary(result, file_path)


def _handle_split_output(
    file_path: Path,
    result: OptimizationResult,
    documents: list[ScpDocument],
    *,
    output: Path | None,
    dry_run: bool,
    summary_only: bool,
) -> None:
    """Handle output when policy is split into multiple files."""
    console.print(f"[yellow]⚠ Splitting {file_path.name} into {len(documents)} SCPs[/yellow]")
    _print_summary(result, file_path)

    for i, doc in enumerate(documents, 1):
        stem = file_path.stem
        suffix = file_path.suffix
        out_name = f"{stem}_{i}{suffix}"

        if dry_run or summary_only:
            console.print(
                f"  → {out_name}: {doc.size_bytes:,} bytes, {len(doc.statement)} statements"
            )
            if dry_run and not summary_only:
                _print_diff("", doc.to_json(), out_name)
        else:
            out_dir = output or file_path.parent
            out_path = out_dir / out_name
            out_path.write_text(doc.to_json() + "\n", encoding="utf-8")
            console.print(f"  → wrote {out_path}")


# ── schema command ───────────────────────────────────────────────────


@app.command("schema")
def schema_cmd(
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write schema to a file instead of stdout.",
    ),
) -> None:
    """Print the JSON Schema for scpeasy.yaml to stdout."""
    schema = OptimizerConfig.model_json_schema()
    # Annotate with $schema and $id so editors (e.g. VS Code YAML extension)
    # can resolve and apply the schema automatically.
    schema.setdefault("$schema", "https://json-schema.org/draft/2020-12/schema")
    schema.setdefault(
        "$id",
        f"https://scpeasy.io/schemas/{SUPPORTED_API_VERSION}/{SUPPORTED_KIND}.json",
    )
    text = json.dumps(schema, indent=2) + "\n"

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        console.print(f"[green]✓ Schema written to {output}[/green]")
    else:
        out.print(text, end="")


# ── validate command ─────────────────────────────────────────────────


@app.command("validate")
def validate_cmd(
    path: Path = typer.Argument(..., help="SCP JSON file or directory of JSON files."),
) -> None:
    """Validate SCP JSON file(s) without modifying them."""
    files = _resolve_files(path)
    if not files:
        console.print("[red]No JSON files found.[/red]")
        raise typer.Exit(code=1)

    has_errors = False
    for file_path in files:
        doc, val_result = validate_file(file_path)
        _print_validation(val_result, file_path)
        if doc is not None:
            doc_result = validate_document(doc)
            _print_validation(doc_result, file_path)
            if not doc_result.is_valid:
                has_errors = True
        if not val_result.is_valid:
            has_errors = True

    if has_errors:
        raise typer.Exit(code=1)

    console.print("[green]✓ All files are valid.[/green]")


# ── helpers ──────────────────────────────────────────────────────────


def _resolve_files(path: Path) -> list[Path]:
    """Resolve a path argument to a list of JSON files."""
    if path.is_file():
        return [path]
    if path.is_dir():
        return sorted(path.glob("*.json"))
    console.print(f"[red]Path not found:[/red] {path}")
    return []


def _print_validation(result: ValidationResult, file_path: Path) -> None:
    """Print validation issues."""
    for issue in result.issues:
        colour = "red" if issue.severity is Severity.ERROR else "yellow"
        label = issue.severity.value.upper()
        loc = f" at {issue.path}" if issue.path else ""
        console.print(f"[{colour}]{label}[/{colour}] {file_path.name}{loc}: {issue.message}")


def _print_summary(result: OptimizationResult, file_path: Path) -> None:
    """Print optimization summary."""
    console.print(
        Panel(
            result.summary(),
            title=f"[bold]{file_path.name}[/bold]",
            border_style="blue",
        )
    )


def _print_diff(original: str, optimized: str, name: str) -> None:
    """Print a unified diff."""
    orig_lines = original.splitlines(keepends=True)
    opt_lines = optimized.splitlines(keepends=True)
    diff = difflib.unified_diff(orig_lines, opt_lines, fromfile=name, tofile=f"{name} (optimized)")
    diff_text = "".join(diff)
    if diff_text:
        out.print(diff_text)
    else:
        console.print("[dim]No changes.[/dim]")


def _write_optimized(file_path: Path, doc: ScpDocument, output: Path | None) -> None:
    """Write optimized SCP, backing up the original if writing in-place."""
    out_path = output or file_path
    if out_path == file_path:
        backup = file_path.with_suffix(file_path.suffix + ".bak")
        shutil.copy2(file_path, backup)
        console.print(f"[dim]Backup: {backup}[/dim]")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(doc.to_json() + "\n", encoding="utf-8")
    console.print(f"[green]\u2713 Wrote {out_path}[/green]")
