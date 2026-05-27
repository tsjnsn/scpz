"""scpz CLI — optimize and validate AWS SCP policies."""

from __future__ import annotations

import difflib
import json
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import typer
from rich.console import Console
from rich.panel import Panel

from scpz import __version__
from scpz.catalog import ActionCatalog
from scpz.config import SUPPORTED_API_VERSION, SUPPORTED_KIND, OptimizerConfig
from scpz.equivalence import check_permission_equivalence
from scpz.machine_output import (
    OutputFormat,
    build_check_equivalence_payload,
    build_validate_payload,
    emit_json,
    file_validation_entry,
)
from scpz.optimizer import OptimizationResult
from scpz.optimizer import optimize as run_optimize
from scpz.splitter import SplitError, split_if_needed
from scpz.validator import (
    Severity,
    ValidationResult,
    parse_scp_file,
    validate_document,
    validate_file,
)

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

FormatOption = Annotated[
    OutputFormat,
    typer.Option(
        "--format",
        "-f",
        help=(
            "Output format: human (Rich text, default) or json "
            "(machine-readable JSON on stdout for CI and automation)."
        ),
        case_sensitive=False,
    ),
]


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
            "Destination for optimized JSON (in-place when omitted). For a single input "
            "file: paths ending in .json name one output file (an existing directory "
            "always uses directory semantics); otherwise --output is a directory and "
            "writes <output>/<input filename> (or <stem>_N.json when splitting). When "
            "PATH is a directory of policies, --output must be a directory."
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

    write_output = not dry_run and not summary_only
    if output is not None:
        _validate_output_path_kind(output)
    is_batch = path.is_dir()
    if is_batch and output is not None:
        _require_output_directory(
            output,
            reason="PATH is a directory",
            create=write_output,
        )

    exit_code = 0
    for file_path in files:
        file_output = output
        split_output_dir = output
        if is_batch and output is not None:
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
        except SplitError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            exit_code = 1
        except typer.Exit as exc:
            code = exc.exit_code if exc.exit_code is not None else 0
            if code != 0:
                exit_code = max(exit_code, code)

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
        write_path = _resolve_single_file_output(output, file_path)
        _write_optimized(file_path, result.optimized, write_path)
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

    write_output = not dry_run and not summary_only
    split_out_dir: Path | None = None
    if write_output:
        split_out_dir = _resolve_split_output_dir(output_dir, file_path)

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

        if not write_output:
            console.print(
                f"  → {out_name}: {doc.size_bytes:,} bytes, {len(doc.statement)} statements"
            )
            if dry_run and not summary_only:
                _print_diff("", doc.to_json(), out_name)
            continue

        if split_out_dir is None:
            console.print("[red]Error:[/red] Split output directory is missing.")
            raise typer.Exit(code=1)
        out_path = split_out_dir / out_name
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
    output_format: FormatOption = OutputFormat.HUMAN,
) -> None:
    """Check SCP JSON against structure, catalog, and configured validation rules.

    When the path is missing, human mode prints a single ``Path not found`` message
    (not ``No JSON files found``). Empty directories still report ``No JSON files found``.
    """
    json_mode = output_format is OutputFormat.JSON
    files = _resolve_files(path, quiet=True)
    if not files:
        if json_mode:
            payload = build_validate_payload(
                files=[],
                status="error",
                exit_code=1,
                error=_no_files_error(path),
            )
            emit_json(payload)
        else:
            _print_no_files_error(path)
        raise typer.Exit(code=1)

    entries: list[dict[str, Any]] = []
    has_errors = False
    for file_path in files:
        _, val_result = validate_file(file_path)
        entries.append(file_validation_entry(file_path, val_result))
        if not json_mode:
            _print_validation(val_result, file_path)
        if not val_result.is_valid:
            has_errors = True

    exit_code = 1 if has_errors else 0
    if json_mode:
        emit_json(
            build_validate_payload(
                files=entries,
                status="error" if has_errors else "ok",
                exit_code=exit_code,
            )
        )
    elif not has_errors:
        console.print("[green]✓ All files are valid.[/green]")

    if has_errors:
        raise typer.Exit(code=1)


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
    output_format: FormatOption = OutputFormat.HUMAN,
) -> None:
    """Verify AFTER did not broaden permissions versus BEFORE (catalog model)."""
    json_mode = output_format is OutputFormat.JSON

    def emit_and_exit(payload: dict[str, Any], *, code: int) -> None:
        if json_mode:
            emit_json(payload)
        raise typer.Exit(code=code)

    if not before.is_file():
        if json_mode:
            emit_and_exit(
                build_check_equivalence_payload(
                    before=before,
                    after=after,
                    status="error",
                    exit_code=1,
                    equivalent=None,
                    messages=[],
                    error=f"File not found: {before}",
                ),
                code=1,
            )
        console.print(f"[red]File not found:[/red] {before}")
        raise typer.Exit(code=1)
    if not after.is_file():
        if json_mode:
            emit_and_exit(
                build_check_equivalence_payload(
                    before=before,
                    after=after,
                    status="error",
                    exit_code=1,
                    equivalent=None,
                    messages=[],
                    error=f"File not found: {after}",
                ),
                code=1,
            )
        console.print(f"[red]File not found:[/red] {after}")
        raise typer.Exit(code=1)

    try:
        cfg = OptimizerConfig.load(before)
    except ValueError as exc:
        if json_mode:
            emit_and_exit(
                build_check_equivalence_payload(
                    before=before,
                    after=after,
                    status="error",
                    exit_code=1,
                    equivalent=None,
                    messages=[],
                    error=f"Config error: {exc}",
                ),
                code=1,
            )
        console.print(f"[red]Config error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    # Parse JSON/model first (no catalog I/O) so syntax errors are not masked.
    doc_before, val_b = parse_scp_file(before)
    if doc_before is None or not val_b.is_valid:
        if json_mode:
            emit_and_exit(
                build_check_equivalence_payload(
                    before=before,
                    after=after,
                    status="error",
                    exit_code=1,
                    equivalent=None,
                    messages=[],
                    before_validation=val_b,
                    error="Validation failed for BEFORE file",
                ),
                code=1,
            )
        _print_validation(val_b, before)
        raise typer.Exit(code=1)

    doc_after, val_a = parse_scp_file(after)
    if doc_after is None or not val_a.is_valid:
        if json_mode:
            emit_and_exit(
                build_check_equivalence_payload(
                    before=before,
                    after=after,
                    status="error",
                    exit_code=1,
                    equivalent=None,
                    messages=[],
                    before_validation=val_b,
                    after_validation=val_a,
                    error="Validation failed for AFTER file",
                ),
                code=1,
            )
        _print_validation(val_a, after)
        raise typer.Exit(code=1)

    try:
        catalog = ActionCatalog.load(cfg.spec.catalog)
    except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError) as exc:
        if json_mode:
            emit_and_exit(
                build_check_equivalence_payload(
                    before=before,
                    after=after,
                    status="error",
                    exit_code=1,
                    equivalent=None,
                    messages=[],
                    before_validation=val_b,
                    after_validation=val_a,
                    error=f"Could not load action catalog ({cfg.spec.catalog.source}): {exc}",
                ),
                code=1,
            )
        console.print(
            f"[red]Could not load action catalog ({cfg.spec.catalog.source}):[/red] {exc}"
        )
        raise typer.Exit(code=1) from exc

    val_b = validate_document(doc_before, validation=cfg.spec.validation, action_catalog=catalog)
    if not json_mode:
        _print_validation(val_b, before)
    if not val_b.is_valid:
        if json_mode:
            emit_and_exit(
                build_check_equivalence_payload(
                    before=before,
                    after=after,
                    status="error",
                    exit_code=1,
                    equivalent=None,
                    messages=[],
                    before_validation=val_b,
                    after_validation=val_a,
                    error="Validation failed for BEFORE file",
                ),
                code=1,
            )
        raise typer.Exit(code=1)

    val_a = validate_document(doc_after, validation=cfg.spec.validation, action_catalog=catalog)
    if not json_mode:
        _print_validation(val_a, after)
    if not val_a.is_valid:
        if json_mode:
            emit_and_exit(
                build_check_equivalence_payload(
                    before=before,
                    after=after,
                    status="error",
                    exit_code=1,
                    equivalent=None,
                    messages=[],
                    before_validation=val_b,
                    after_validation=val_a,
                    error="Validation failed for AFTER file",
                ),
                code=1,
            )
        raise typer.Exit(code=1)

    eq = check_permission_equivalence(doc_before, doc_after, catalog)
    if eq.ok:
        if json_mode:
            emit_and_exit(
                build_check_equivalence_payload(
                    before=before,
                    after=after,
                    status="ok",
                    exit_code=0,
                    equivalent=True,
                    messages=[],
                    before_validation=val_b,
                    after_validation=val_a,
                ),
                code=0,
            )
        console.print(
            "[green]✓ Equivalence OK:[/green] after is same or stricter than before "
            "(Deny / Allow catalog model)."
        )
        raise typer.Exit(code=0)

    if json_mode:
        emit_and_exit(
            build_check_equivalence_payload(
                before=before,
                after=after,
                status="error",
                exit_code=1,
                equivalent=False,
                messages=list(eq.messages),
                before_validation=val_b,
                after_validation=val_a,
            ),
            code=1,
        )

    console.print("[red]Equivalence check failed.[/red]")
    for msg in eq.messages:
        console.print(f"  [red]•[/red] {msg}")
    raise typer.Exit(code=1)


# ── helpers ──────────────────────────────────────────────────────────


def _no_files_error(path: Path) -> str:
    if path.is_file() or path.is_dir():
        return "No JSON files found"
    return f"Path not found: {path}"


def _print_no_files_error(path: Path) -> None:
    """Print a single human-readable error when no JSON files are available."""
    if path.is_file() or path.is_dir():
        console.print("[red]No JSON files found.[/red]")
    else:
        console.print(f"[red]Path not found:[/red] {path}")


def _resolve_files(path: Path, *, quiet: bool = False) -> list[Path]:
    """Resolve a path argument to a list of JSON files."""
    if path.is_file():
        return [path]
    if path.is_dir():
        return sorted(path.glob("*.json"))
    if not quiet:
        console.print(f"[red]Path not found:[/red] {path}")
    return []


def _validate_output_path_kind(path: Path) -> None:
    """Reject --output paths that exist as non-.json files (ambiguous vs directory)."""
    if path.exists() and path.is_file() and path.suffix.lower() != ".json":
        console.print(
            "[red]Error:[/red] --output exists as a file but does not end in .json; "
            "use a .json path for a single output file or a directory path otherwise."
        )
        raise typer.Exit(code=1)


def _is_output_file_path(path: Path) -> bool:
    """True when --output names a single file (only paths ending in .json)."""
    if path.exists() and path.is_dir():
        return False
    return path.suffix.lower() == ".json"


def _resolve_single_file_output(output: Path | None, file_path: Path) -> Path | None:
    """Map --output to the file path for a single optimized SCP write."""
    if output is None:
        return None
    if _is_output_file_path(output):
        return output
    return output / file_path.name


def _validate_output_directory(output: Path, *, reason: str) -> None:
    """Require --output to name a directory, not a single file path."""
    if _is_output_file_path(output):
        console.print(f"[red]Error:[/red] --output must be a directory when {reason}.")
        raise typer.Exit(code=1)


def _ensure_output_directory(output: Path) -> None:
    """Create the output directory and any missing parents."""
    output.mkdir(parents=True, exist_ok=True)


def _require_output_directory(output: Path, *, reason: str, create: bool = True) -> None:
    """Validate --output is a directory; optionally create it on disk."""
    _validate_output_directory(output, reason=reason)
    if create:
        _ensure_output_directory(output)


def _resolve_split_output_dir(output: Path | None, file_path: Path) -> Path:
    """Resolve the directory for split SCP output files."""
    if output is None:
        return file_path.parent
    if _is_output_file_path(output):
        console.print(
            "[red]Error:[/red] --output must be a directory when splitting into multiple SCPs."
        )
        raise typer.Exit(code=1)
    _ensure_output_directory(output)
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
