"""scpz CLI — optimize and validate AWS SCP policies."""

from __future__ import annotations

import difflib
import json
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich.console import Console
from rich.panel import Panel

from scpz import __version__
from scpz.catalog import ActionCatalog
from scpz.config import SUPPORTED_API_VERSION, SUPPORTED_KIND, OptimizerConfig
from scpz.equivalence import check_permission_equivalence
from scpz.optimizer import OptimizationResult
from scpz.optimizer import optimize as run_optimize
from scpz.splitter import SplitError, split_if_needed
from scpz.validator import Severity, ValidationResult, validate_document, validate_file

if TYPE_CHECKING:
    from scpz.models import ScpDocument

_APP_HELP = "Optimize and validate AWS Service Control Policy (SCP) JSON for Organizations limits."
_EPILOG = "Run `scpz <command> --help` for command-specific options."

app = typer.Typer(
    name="scpz",
    help=_APP_HELP,
    epilog=_EPILOG,
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console(stderr=True)
out = Console()


def version_callback(value: bool) -> None:
    if value:
        out.print(f"scpz {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Print version information and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """Optimize and validate AWS Service Control Policy (SCP) JSON."""


# ── optimize ─────────────────────────────────────────────────────────


@app.command("optimize")
def optimize(
    path: Path = typer.Argument(
        ...,
        help="SCP JSON file or directory containing *.json policies.",
        metavar="PATH",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help=(
            "Destination for optimized JSON. For one policy without splitting, a file path "
            "(in-place when omitted). For split output or when PATH is a directory of policies, "
            "must be a directory; split files are written as <stem>_N.json inside it."
        ),
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print summary and unified diff; do not write files.",
    ),
    summary_only: bool = typer.Option(
        False,
        "--summary-only",
        help="Print optimization summary only; do not write files (no diff).",
    ),
    no_split: bool = typer.Option(
        False,
        "--no-split",
        help="Exit with an error if the policy still exceeds limits after optimization.",
    ),
) -> None:
    """Optimize SCP JSON to fit AWS Organizations size and statement limits."""
    files = _resolve_files(path)
    if not files:
        console.print("[red]No JSON files found.[/red]")
        raise typer.Exit(code=1)

    if len(files) > 1 and output is not None:
        _require_output_directory(
            output,
            reason=f"PATH contains {len(files)} policies",
        )

    exit_code = 0
    for file_path in files:
        file_output = output
        split_output_dir = output
        if len(files) > 1 and output is not None:
            file_output = output / file_path.name
        try:
            _optimize_file(
                file_path,
                output=file_output,
                split_output_dir=split_output_dir,
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
    split_output_dir: Path | None = None,
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
    doc, val_result = validate_file(file_path, config=cfg)
    _print_validation(val_result, file_path)
    if doc is None:
        raise typer.Exit(code=1)
    if not val_result.is_valid:
        raise typer.Exit(code=1)

    # Optimize
    result = run_optimize(doc, config=cfg)

    post_val = validate_document(
        result.optimized, validation=cfg.spec.validation, action_catalog=result.catalog
    )
    _print_validation(post_val, file_path)
    if not post_val.is_valid:
        raise typer.Exit(code=1)

    # --no-split CLI flag overrides config; otherwise honour split pass config
    split_enabled = (
        not no_split
        and cfg.spec.optimizer.split.enabled
        and (cfg.spec.optimizer.split.strategy == "auto")
    )

    # Check if splitting is needed
    if not result.fits_single_scp and split_enabled:
        try:
            split_result = split_if_needed(result.optimized, catalog=result.catalog)
        except SplitError:
            raise
        if split_result.count > 1:
            _handle_split_output(
                file_path,
                result,
                split_result.documents,
                output_dir=split_output_dir if split_output_dir is not None else output,
                dry_run=dry_run,
                summary_only=summary_only,
                cfg=cfg,
            )
            return
    elif not result.fits_single_scp and not split_enabled:
        console.print(
            f"[red]Error:[/red] {file_path.name} exceeds limits and splitting is disabled."
        )
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
        if output is not None:
            _reject_output_directory_for_single_file(output)
        _write_optimized(file_path, result.optimized, output)
        _print_summary(result, file_path)


def _handle_split_output(
    file_path: Path,
    result: OptimizationResult,
    documents: list[ScpDocument],
    *,
    output_dir: Path | None,
    dry_run: bool,
    summary_only: bool,
    cfg: OptimizerConfig,
) -> None:
    """Handle output when policy is split into multiple files."""
    console.print(f"[yellow]⚠ Splitting {file_path.name} into {len(documents)} SCPs[/yellow]")
    _print_summary(result, file_path)

    if not dry_run and not summary_only:
        out_dir = _resolve_split_output_dir(output_dir, file_path)
    else:
        out_dir = None

    for i, doc in enumerate(documents, 1):
        stem = file_path.stem
        suffix = file_path.suffix
        out_name = f"{stem}_{i}{suffix}"

        split_val = validate_document(
            doc, validation=cfg.spec.validation, action_catalog=result.catalog
        )
        _print_validation(split_val, Path(out_name))
        if not split_val.is_valid:
            console.print("[red]Split output failed validation; not writing.[/red]")
            raise typer.Exit(code=1)

        if dry_run or summary_only:
            console.print(
                f"  → {out_name}: {doc.size_bytes:,} bytes, {len(doc.statement)} statements"
            )
            if dry_run and not summary_only:
                _print_diff("", doc.to_json(), out_name)
        else:
            assert out_dir is not None
            out_path = out_dir / out_name
            out_path.write_text(doc.to_json() + "\n", encoding="utf-8")
            console.print(f"  → wrote {out_path}")


# ── print-schema ─────────────────────────────────────────────────────


@app.command("print-schema")
def print_schema(
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write JSON Schema to this file instead of stdout.",
    ),
) -> None:
    """Emit the JSON Schema for scpz.yaml (OptimizerConfig)."""
    schema = OptimizerConfig.model_json_schema()
    # Annotate with $schema and $id so editors (e.g. VS Code YAML extension)
    # can resolve and apply the schema automatically.
    schema.setdefault("$schema", "https://json-schema.org/draft/2020-12/schema")
    schema.setdefault(
        "$id",
        f"https://scpz.io/schemas/{SUPPORTED_API_VERSION}/{SUPPORTED_KIND}.json",
    )
    text = json.dumps(schema, indent=2) + "\n"

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        console.print(f"[green]✓ Schema written to {output}[/green]")
    else:
        sys.stdout.write(text)


# ── validate ───────────────────────────────────────────────────────────


@app.command("validate")
def validate(
    path: Path = typer.Argument(
        ...,
        help="SCP JSON file or directory containing *.json policies.",
        metavar="PATH",
    ),
) -> None:
    """Check SCP JSON against structure, catalog, and configured validation rules."""
    files = _resolve_files(path)
    if not files:
        console.print("[red]No JSON files found.[/red]")
        raise typer.Exit(code=1)

    has_errors = False
    for file_path in files:
        _, val_result = validate_file(file_path)
        _print_validation(val_result, file_path)
        if not val_result.is_valid:
            has_errors = True

    if has_errors:
        raise typer.Exit(code=1)

    console.print("[green]✓ All files are valid.[/green]")


# ── check-equivalence ──────────────────────────────────────────────────


@app.command("check-equivalence")
def check_equivalence(
    before: Path = typer.Argument(
        ...,
        help="Baseline SCP JSON (permissions must not shrink vs this file).",
        metavar="BEFORE",
    ),
    after: Path = typer.Argument(
        ...,
        help="Candidate SCP JSON (must not broaden permissions vs BEFORE).",
        metavar="AFTER",
    ),
) -> None:
    """Verify AFTER did not broaden permissions versus BEFORE (catalog model)."""
    if not before.is_file():
        console.print(f"[red]File not found:[/red] {before}")
        raise typer.Exit(code=1)
    if not after.is_file():
        console.print(f"[red]File not found:[/red] {after}")
        raise typer.Exit(code=1)

    try:
        cfg = OptimizerConfig.load(before)
    except ValueError as exc:
        console.print(f"[red]Config error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    doc_before, val_b = validate_file(before, config=cfg)
    _print_validation(val_b, before)
    if doc_before is None or not val_b.is_valid:
        raise typer.Exit(code=1)

    doc_after, val_a = validate_file(after, config=cfg)
    _print_validation(val_a, after)
    if doc_after is None or not val_a.is_valid:
        raise typer.Exit(code=1)

    catalog = ActionCatalog.load(cfg.spec.catalog)
    eq = check_permission_equivalence(doc_before, doc_after, catalog)
    if eq.ok:
        console.print(
            "[green]✓ Equivalence OK:[/green] after is same or stricter than before "
            "(Deny / Allow catalog model)."
        )
        raise typer.Exit(code=0)

    console.print("[red]Equivalence check failed.[/red]")
    for msg in eq.messages:
        console.print(f"  [red]•[/red] {msg}")
    raise typer.Exit(code=1)


# ── helpers ──────────────────────────────────────────────────────────


def _resolve_files(path: Path) -> list[Path]:
    """Resolve a path argument to a list of JSON files."""
    if path.is_file():
        return [path]
    if path.is_dir():
        return sorted(path.glob("*.json"))
    console.print(f"[red]Path not found:[/red] {path}")
    return []


def _is_existing_directory(path: Path) -> bool:
    return path.exists() and path.is_dir()


def _is_existing_file(path: Path) -> bool:
    return path.exists() and path.is_file()


def _looks_like_new_file_path(path: Path) -> bool:
    """True when a non-existent path clearly names a single output file."""
    return not path.exists() and path.suffix.lower() == ".json"


def _require_output_directory(output: Path, *, reason: str) -> None:
    """Require --output to be a directory (create parents as needed)."""
    if _is_existing_file(output) or _looks_like_new_file_path(output):
        console.print(f"[red]Error:[/red] --output must be a directory when {reason}.")
        raise typer.Exit(code=1)
    output.mkdir(parents=True, exist_ok=True)


def _reject_output_directory_for_single_file(output: Path) -> None:
    """Reject --output when it names a directory but only one SCP will be written."""
    if _is_existing_directory(output):
        console.print(
            "[red]Error:[/red] --output must be a file path when writing a single optimized SCP."
        )
        raise typer.Exit(code=1)


def _resolve_split_output_dir(output: Path | None, file_path: Path) -> Path:
    """Resolve the directory for split SCP output files."""
    if output is None:
        return file_path.parent
    if _is_existing_file(output) or _looks_like_new_file_path(output):
        console.print(
            "[red]Error:[/red] --output must be a directory when splitting into multiple SCPs."
        )
        raise typer.Exit(code=1)
    output.mkdir(parents=True, exist_ok=True)
    return output


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
