"""Command-line interface.

Exit codes: 0 success; 1 a check failed (collector error, ``--fail-on`` status present,
package verification failed); 2 usage or configuration error.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from datetime import date
from pathlib import Path
from typing import TextIO

from . import __version__
from .collectors import collector_types
from .crosswalk import build_crosswalk
from .errors import ControlmapError
from .exceptions import load_exceptions
from .library import load_library
from .mockapi import MockGitHub, serve
from .model import EvaluationRun, Status
from .package import build_package, generate_keypair, load_private_key, load_public_key
from .package.verify import VerifyReport, verify_package
from .project import ProjectConfig, collect, evaluate_project, load_config
from .rules import rule_registry
from .timeutil import parse_date, parse_datetime, utc_now

log = logging.getLogger("controlmap")

EXIT_OK, EXIT_CHECK_FAILED, EXIT_USAGE = 0, 1, 2


class CliError(ControlmapError):
    """A usage problem detected by the CLI itself."""


def _as_of(value: str) -> date:
    try:
        return parse_date(value, field="--as-of")
    except ControlmapError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _statuses(value: str) -> set[Status]:
    out = set()
    for part in value.split(","):
        name = part.strip().upper()
        if not name:
            continue
        try:
            out.add(Status(name))
        except ValueError as exc:
            choices = ", ".join(s.value for s in Status)
            raise argparse.ArgumentTypeError(f"unknown status {name!r} ({choices})") from exc
    return out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="controlmap",
        description="SOC 2 evidence automation. Supports an audit; does not replace one.",
    )
    parser.add_argument("--version", action="version", version=f"controlmap {__version__}")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="more logging")
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=Path("controlmap.yaml"),
        help="project configuration file (default: ./controlmap.yaml)",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    sub.add_parser("validate", help="validate config, control library and exception register")

    p = sub.add_parser("collect", help="run collectors and store evidence")
    p.add_argument("--only", action="append", metavar="NAME", help="run only this collector")
    p.add_argument("--fail-fast", action="store_true", help="stop at the first failing collector")

    p = sub.add_parser("evaluate", help="evaluate stored evidence against the control library")
    p.add_argument("--as-of", type=_as_of, help="evaluation date (default: config or today)")
    p.add_argument("--json", action="store_true", help="print the full results as JSON")
    p.add_argument("--details", action="store_true", help="list findings and notes per rule")
    p.add_argument(
        "--fail-on",
        type=_statuses,
        default=set(),
        metavar="STATUSES",
        help="exit 1 if any control has one of these comma-separated statuses",
    )

    p = sub.add_parser("package", help="build the auditor evidence package")
    p.add_argument("--out", type=Path, required=True, help="package directory to create")
    p.add_argument("--as-of", type=_as_of)
    p.add_argument("--archive", type=Path, help="also write a deterministic .tar.gz")
    p.add_argument("--sign-key", type=Path, help="Ed25519 private key (PEM) to sign the manifest")
    p.add_argument("--generated-at", help="timestamp recorded in the package (ISO-8601)")
    p.add_argument("--force", action="store_true", help="replace an existing package directory")

    p = sub.add_parser("verify", help="verify a package directory or archive")
    p.add_argument("path", type=Path)
    p.add_argument("--public-key", type=Path, help="trusted Ed25519 public key (PEM)")
    p.add_argument("--require-signature", action="store_true")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("crosswalk", help="print the TSC <-> ISO 27001:2022 crosswalk")
    p.add_argument("--format", choices=("md", "csv", "json"), default="md")

    p = sub.add_parser("exceptions", help="show the exception register state on a date")
    p.add_argument("--as-of", type=_as_of)
    p.add_argument("--json", action="store_true")

    sub.add_parser("rules", help="list available rules and their parameters")
    sub.add_parser("collectors", help="list available collector types")

    p = sub.add_parser("keygen", help="create an Ed25519 signing key pair")
    p.add_argument("--private", type=Path, required=True)
    p.add_argument("--public", type=Path, required=True)

    p = sub.add_parser("mock-github", help="serve a mock GitHub API from a fixture (localhost)")
    p.add_argument("--fixture", type=Path, required=True)
    p.add_argument("--port", type=int, default=8765)
    return parser


def _config(args: argparse.Namespace) -> ProjectConfig:
    path: Path = args.config
    if not path.is_file():
        raise CliError(f"configuration file {path} not found (use -c PATH)")
    return load_config(path)


def _table(rows: Sequence[Sequence[str]], out: TextIO) -> None:
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    for row in rows:
        cells = [cell.ljust(widths[i]) for i, cell in enumerate(row[:-1])]
        out.write("  ".join([*cells, row[-1]]).rstrip() + "\n")


def cmd_validate(args: argparse.Namespace, out: TextIO) -> int:
    config = _config(args)
    library = load_library(config.library_path)
    register = load_exceptions(config.exceptions_path, library)
    known = collector_types()
    for settings in config.collectors:
        if settings.text("type") not in known:
            raise CliError(f"{settings.where}: unknown collector type {settings.text('type')!r}")
    rule_count = sum(len(c.rules) for c in library.controls)
    out.write(
        f"config OK: {len(config.collectors)} collectors, {len(library.controls)} controls, "
        f"{rule_count} rule bindings, {len(register.entries)} exceptions\n"
    )
    for warning in library.warnings:
        out.write(f"warning: {warning}\n")
    return EXIT_OK


def cmd_collect(args: argparse.Namespace, out: TextIO) -> int:
    config = _config(args)
    only = set(args.only) if args.only else None
    report = collect(config, only=only, fail_fast=args.fail_fast)
    rows = [["COLLECTOR", "TYPE", "RECORDS", "NEW", "RESULT"]]
    for entry in report.collectors:
        rows.append(
            [
                entry.name,
                entry.type,
                str(entry.records),
                str(entry.new),
                "ok" if entry.error is None else f"ERROR: {entry.error}",
            ]
        )
    _table(rows, out)
    out.write(f"{report.total_new} new evidence record(s) stored in {config.store_path}\n")
    return EXIT_OK if report.ok else EXIT_CHECK_FAILED


def _summary_line(run: EvaluationRun) -> str:
    counts = run.counts()
    return " | ".join(f"{status} {counts[status]}" for status in counts if counts[status])


def cmd_evaluate(args: argparse.Namespace, out: TextIO) -> int:
    config = _config(args)
    evaluation = evaluate_project(config, args.as_of)
    run = evaluation.run
    if args.json:
        out.write(json.dumps(run.to_dict(), indent=2, sort_keys=True) + "\n")
    else:
        out.write(f"{run.company}: {len(run.controls)} controls as of {run.as_of.isoformat()}\n\n")
        rows = [["CONTROL", "STATUS", "TSC", "TITLE"]]
        rows += [[c.control_id, c.status.value, ",".join(c.tsc), c.title] for c in run.controls]
        _table(rows, out)
        if args.details:
            _write_details(run, out)
        out.write(f"\n{_summary_line(run)}\n")
        out.write(
            "Automated checks over collected evidence; this supports an audit, not replaces it.\n"
        )
    hits = sorted(c.control_id for c in run.controls if c.status in args.fail_on)
    if hits:
        log.error("controls with a --fail-on status: %s", ", ".join(hits))
        return EXIT_CHECK_FAILED
    return EXIT_OK


def _write_details(run: EvaluationRun, out: TextIO) -> None:
    for control in run.controls:
        if control.status is Status.PASS:
            continue
        out.write(f"\n{control.control_id} {control.title} [{control.status}]\n")
        for note in control.notes:
            out.write(f"  ! {note}\n")
        for result in control.rules:
            out.write(f"  {result.rule}: {result.status} (tested {result.checked})\n")
            for finding in result.findings:
                tag = f"excepted by {finding.excepted_by}" if finding.excepted_by else "open"
                out.write(f"    - {finding.resource}: {finding.message} [{tag}]\n")
            for note in result.notes:
                out.write(f"    note: {note}\n")


def cmd_package(args: argparse.Namespace, out: TextIO) -> int:
    config = _config(args)
    evaluation = evaluate_project(config, args.as_of)
    key = load_private_key(args.sign_key) if args.sign_key else None
    generated = (
        parse_datetime(args.generated_at, field="--generated-at") if args.generated_at else None
    )
    info = build_package(
        args.out,
        run=evaluation.run,
        library=evaluation.library,
        library_source=config.library_path,
        records=evaluation.records,
        store=config.store(),
        generated_at=generated,
        signing_key=key,
        archive=args.archive,
        force=args.force,
    )
    out.write(f"package written to {info.path} ({info.files} files)\n")
    out.write(f"manifest sha256: {info.manifest_sha256}\n")
    out.write(f"signed: {'yes' if info.signed else 'no'}\n")
    if info.archive is not None:
        out.write(f"archive: {info.archive}\n")
    out.write(f"{_summary_line(evaluation.run)}\n")
    return EXIT_OK


def _write_verify(report: VerifyReport, out: TextIO) -> None:
    out.write(f"package: {report.path}\n")
    out.write(f"manifest sha256: {report.manifest_sha256 or '-'}\n")
    out.write(
        f"files checked: {report.files_checked}, evidence records: {report.evidence_records}\n"
    )
    if report.signed:
        state = "valid" if report.signature_valid else "INVALID"
        out.write(f"signature: {state}, signer fingerprint {report.fingerprint or '-'}\n")
        if report.trusted_key_match is not None:
            match = "matches" if report.trusted_key_match else "DOES NOT match"
            out.write(f"signer {match} the trusted public key\n")
    else:
        out.write("signature: none (integrity only, origin not proven)\n")
    for problem in report.problems:
        out.write(f"FAIL: {problem}\n")
    out.write("VERIFIED\n" if report.ok else f"NOT VERIFIED ({len(report.problems)} problems)\n")


def cmd_verify(args: argparse.Namespace, out: TextIO) -> int:
    public = load_public_key(args.public_key) if args.public_key else None
    report = verify_package(args.path, public_key=public, require_signature=args.require_signature)
    if args.json:
        out.write(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n")
    else:
        _write_verify(report, out)
    return EXIT_OK if report.ok else EXIT_CHECK_FAILED


def cmd_crosswalk(args: argparse.Namespace, out: TextIO) -> int:
    config = _config(args)
    crosswalk = build_crosswalk(load_library(config.library_path))
    if args.format == "csv":
        out.write(crosswalk.to_csv())
    elif args.format == "json":
        out.write(json.dumps(crosswalk.to_dict(), indent=2, sort_keys=True) + "\n")
    else:
        rows = [["TSC", "CONTROLS", "ISO 27001:2022 ANNEX A"]]
        for row in crosswalk.criteria:
            rows.append(
                [
                    row.id,
                    ",".join(row.controls) or "-",
                    " ".join(f"A.{i}" for i in row.iso) or "-",
                ]
            )
        _table(rows, out)
        coverage = crosswalk.coverage()
        out.write(
            f"\n{coverage['tsc_covered']}/{coverage['tsc_in_scope']} in-scope criteria covered; "
            f"{coverage['iso_covered']}/{coverage['iso_total']} Annex A controls reached\n"
        )
    return EXIT_OK


def cmd_exceptions(args: argparse.Namespace, out: TextIO) -> int:
    config = _config(args)
    library = load_library(config.library_path)
    register = load_exceptions(config.exceptions_path, library)
    as_of = args.as_of or config.default_as_of or utc_now().date()
    report = register.tracker(as_of).report()
    if args.json:
        out.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
        return EXIT_OK
    if not report["entries"]:
        out.write("no exceptions registered\n")
        return EXIT_OK
    rows = [["ID", "CONTROL", "STATE", "EXPIRES", "DAYS LEFT", "FLAGS"]]
    for entry in report["entries"]:
        flags = [f for f in entry["flags"] if f != "unused"]  # usage needs an evaluation
        rows.append(
            [
                entry["id"],
                entry["control"],
                entry["state"],
                entry["expires_on"],
                str(entry["days_left"]),
                ",".join(flags) or "-",
            ]
        )
    _table(rows, out)
    return EXIT_OK


def cmd_rules(args: argparse.Namespace, out: TextIO) -> int:
    for name, spec in rule_registry().items():
        kinds = spec.requires if isinstance(spec.requires, tuple) else ("(depends on params)",)
        out.write(f"{name}\n  {spec.description}\n  evidence: {', '.join(kinds)}\n")
        for param in spec.params:
            default = "required" if param.required else f"default {param.default!r}"
            out.write(f"  - {param.name} ({param.type}, {default}): {param.help}\n")
    return EXIT_OK


def cmd_collectors(args: argparse.Namespace, out: TextIO) -> int:
    rows = [["TYPE", "DESCRIPTION"]]
    rows += [[name, cls.description] for name, cls in collector_types().items()]
    _table(rows, out)
    return EXIT_OK


def cmd_keygen(args: argparse.Namespace, out: TextIO) -> int:
    fingerprint = generate_keypair(args.private, args.public)
    out.write(f"wrote {args.private} (keep secret) and {args.public}\n")
    out.write(f"public key fingerprint: {fingerprint}\n")
    return EXIT_OK


def cmd_mock_github(args: argparse.Namespace, out: TextIO) -> int:  # pragma: no cover - blocks
    server = serve(MockGitHub.from_file(args.fixture), port=args.port)
    host, port = server.server_address[:2]
    out.write(f"mock GitHub API on http://{host!s}:{port} (Ctrl-C to stop)\n")
    out.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return EXIT_OK


COMMANDS = {
    "validate": cmd_validate,
    "collect": cmd_collect,
    "evaluate": cmd_evaluate,
    "package": cmd_package,
    "verify": cmd_verify,
    "crosswalk": cmd_crosswalk,
    "exceptions": cmd_exceptions,
    "rules": cmd_rules,
    "collectors": cmd_collectors,
    "keygen": cmd_keygen,
    "mock-github": cmd_mock_github,
}


def main(argv: Sequence[str] | None = None, out: TextIO | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    stream = out or sys.stdout
    level = logging.WARNING - 10 * min(args.verbose, 2)
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s", force=True)
    try:
        return COMMANDS[args.command](args, stream)
    except ControlmapError as exc:
        sys.stderr.write(f"controlmap: error: {exc}\n")
        return EXIT_USAGE


__all__ = ["main"]
