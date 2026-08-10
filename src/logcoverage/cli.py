"""Command-line interface.

Exit codes are the contract with CI and cron:

* ``0`` — the run completed, nothing at or above the fail-on threshold
* ``1`` — the run completed, findings at or above the threshold
* ``2`` — the run could not happen, or happened degraded (no rules read, or over
  half the analyses failed)

Keeping "found gaps" (1) distinct from "could not check" (2) matters more here
than in most tools. A pipeline that treats them alike eventually goes green
because the SIEM token expired, and the thing it stopped checking is whether
anything would notice an intrusion.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from . import __version__
from .ai import summarize
from .analysis import registered_analyses
from .catalog import is_known_source
from .config import ALL_ANALYSES, load_config
from .logging_setup import configure_logging
from .models import FACETS, Determination, ScanReport, Severity
from .notify import notify
from .report import FORMATS, render
from .runner import collect, scan, state_scope
from .severity import BASE_SEVERITY, TIER_ADJUSTMENT, Issue, RelianceTier, rate
from .sources.base import SourceError
from .store import SnapshotStore, StateError
from .validation import ValidationError

log = logging.getLogger("logcoverage")

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logcoverage",
        description=(
            "Reports the blind spots between what your detections require, what your SIEM "
            "actually ingests, and what your critical systems emit. Read-only: it runs metadata "
            "searches and reads files, and never writes to a SIEM."
        ),
    )
    parser.add_argument("--version", action="version", version=f"logcoverage {__version__}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-v", "--verbose", action="count", default=0, help="increase log verbosity")
    common.add_argument("-q", "--quiet", action="store_true", help="only log errors")

    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", parents=[common], help="analyse coverage and report the gaps")
    scan_parser.add_argument("-c", "--config", required=True, help="path to the YAML config file")
    scan_parser.add_argument(
        "-o", "--output", default="-", help="write the report here ('-' for stdout, the default)"
    )
    scan_parser.add_argument("-f", "--format", default="markdown", choices=FORMATS)
    scan_parser.add_argument(
        "--no-save", action="store_true", help="do not update the baseline (useful for a dry run)"
    )
    scan_parser.add_argument(
        "--fail-on",
        default=None,
        choices=[s.value for s in Severity],
        help="minimum severity that sets exit code 1; overrides the config",
    )
    scan_parser.add_argument("--no-notify", action="store_true", help="skip all notification delivery")
    scan_parser.add_argument("--no-ai", action="store_true", help="skip LLM summarisation")
    scan_parser.set_defaults(func=cmd_scan)

    coverage_parser = sub.add_parser(
        "coverage",
        parents=[common],
        help="report only what this deployment could and could not establish",
    )
    coverage_parser.add_argument("-c", "--config", required=True)
    coverage_parser.set_defaults(func=cmd_coverage)

    rules_parser = sub.add_parser(
        "rules", parents=[common], help="print what each detection reads, as parsed"
    )
    rules_parser.add_argument("-c", "--config", required=True)
    rules_parser.add_argument(
        "--explain",
        action="store_true",
        help="list every rule and its parsed sources, fields and techniques",
    )
    rules_parser.set_defaults(func=cmd_rules)

    severity_parser = sub.add_parser(
        "severity", parents=[common], help="print the severity table every finding is rated from"
    )
    severity_parser.set_defaults(func=cmd_severity)

    validate_parser = sub.add_parser(
        "validate", parents=[common], help="validate a config file without reading anything"
    )
    validate_parser.add_argument("-c", "--config", required=True)
    validate_parser.set_defaults(func=cmd_validate)

    return parser


# --------------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
    except ValidationError as exc:
        log.error("config error: %s", exc)
        return EXIT_ERROR

    if args.fail_on:
        config.settings.fail_on = Severity.parse(args.fail_on)

    store = SnapshotStore(config.settings.state_path, scope=state_scope(config))
    try:
        store.check_readable()
    except StateError as exc:
        log.error("%s", exc)
        return EXIT_ERROR

    try:
        report = scan(config, store=store, save=not args.no_save)
    except SourceError as exc:
        log.error("collection failed: %s", exc)
        return EXIT_ERROR
    except StateError as exc:
        log.error("state error: %s", exc)
        return EXIT_ERROR

    if config.ai.enabled and not args.no_ai:
        report.ai_summary = summarize(report, config.ai)

    _write_report(report, args.output, args.format)

    if not args.no_notify:
        for error in notify(report, config.notify, user_agent=config.settings.user_agent):
            log.error("%s", error)

    return _exit_code(report, config.settings.fail_on)


def cmd_coverage(args: argparse.Namespace) -> int:
    """Answer "what can this deployment actually see?" without a full report.

    Worth its own subcommand because it is the first question to ask of a new
    deployment and the one an operator will otherwise answer by reading a report
    and assuming a short findings list means good coverage.
    """
    try:
        config = load_config(args.config)
    except ValidationError as exc:
        log.error("config error: %s", exc)
        return EXIT_ERROR

    try:
        state = collect(config)
    except SourceError as exc:
        log.error("collection failed: %s", exc)
        return EXIT_ERROR

    print(f"SIEM:        {state.siem or '(not reported)'}")
    print(f"Rules from:  {state.rules_origin or '(none)'}")
    print(f"Detections:  {state.rule_count} read, {len(state.indeterminate_rules)} unreadable")
    print(f"Log sources: {len(state.ingested)}")
    print(f"Declared:    {len(state.expected)} expected source(s) across critical systems")
    print()
    width = max(len(facet) for facet in FACETS)
    for facet in FACETS:
        determination = state.covers(facet)
        marker = {
            Determination.PRESENT: "established",
            Determination.ABSENT: "confirmed empty",
            Determination.UNKNOWN: "COULD NOT DETERMINE",
        }[determination]
        print(f"  {facet.ljust(width)}  {marker}")

    if state.errors:
        print()
        print("Notes:")
        for error in state.errors[:50]:
            print(f"  - {error}")

    indeterminate = state.indeterminate_facets
    if indeterminate:
        print()
        print(
            f"{len(indeterminate)} facet(s) could not be determined. Nothing is concluded from "
            "them, so a short findings list does not mean good coverage in those areas."
        )
    return EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    """Print what the tool believes each detection reads.

    The first thing to run against a new rule set. A source name that maps to
    something unexpected, or a rule that came back unreadable, is far cheaper to
    find here than in a report that quietly under-counts coverage.
    """
    try:
        config = load_config(args.config)
    except ValidationError as exc:
        log.error("config error: %s", exc)
        return EXIT_ERROR

    from .models import CoverageState
    from .runner import load_rules

    state = CoverageState(collected_at=CoverageState.now_iso())
    try:
        rules = load_rules(config, state)
    except SourceError as exc:
        log.error("%s", exc)
        return EXIT_ERROR

    usable = [rule for rule in rules if rule.parsed.is_present]
    broken = [rule for rule in rules if rule.parsed.is_unknown]

    by_source: dict[str, int] = {}
    for rule in usable:
        if not rule.enabled:
            continue
        for source in rule.sources:
            by_source[source] = by_source.get(source, 0) + 1

    print(f"{len(rules)} rule(s): {len(usable)} parsed, {len(broken)} unreadable")
    print(f"{sum(1 for rule in usable if not rule.enabled)} disabled or deprecated")
    print()
    print("Log sources read by enabled detections:")
    unmapped: list[str] = []
    for source, count in sorted(by_source.items(), key=lambda item: (-item[1], item[0])):
        known = is_known_source(source) or source in config.policy.source_aliases.values()
        marker = "" if known else "   (unmapped)"
        if not known:
            unmapped.append(source)
        print(f"  {count:>5}  {source}{marker}")

    if unmapped:
        # An unmapped name is not an error and is not dropped — it becomes its own
        # key and joins fine against an inventory that spells it the same way.
        # What it loses is the cross-vocabulary translation, and that loss is
        # silent everywhere else, which is why it is printed here.
        print()
        print(
            f"{len(unmapped)} source name(s) matched neither the built-in catalog nor "
            "policy.source_aliases. They still work if your inventory spells them the same "
            "way; if it does not, they will join against nothing:"
        )
        for source in unmapped[:50]:
            print(f"  {source}")
        if len(unmapped) > 50:
            print(f"  …and {len(unmapped) - 50} more")

    if broken:
        print()
        print("Unreadable rule files (their requirements are unknown, not empty):")
        for rule in broken[:50]:
            print(f"  {rule.path}: {rule.parse_error}")
        if len(broken) > 50:
            print(f"  …and {len(broken) - 50} more")

    if args.explain:
        print()
        print("Every parsed rule:")
        for rule in usable:
            flag = "" if rule.enabled else " [disabled]"
            print(f"  {rule.name}{flag}")
            print(f"    path:       {rule.path}")
            print(f"    sources:    {', '.join(rule.sources) or '(none)'}")
            print(f"    fields:     {', '.join(rule.fields[:12]) or '(none)'}")
            print(f"    techniques: {', '.join(rule.techniques) or '(none)'}")

    for error in state.errors[:50]:
        print(f"note: {error}")

    return EXIT_OK


def cmd_severity(args: argparse.Namespace) -> int:
    """Print the table, so a disputed rating can be argued about specifically."""
    print("Base severity per issue, assuming the broad reliance tier:")
    print()
    width = max(len(issue.value) for issue in Issue)
    for issue in Issue:
        print(f"  {issue.value.ljust(width)}  {BASE_SEVERITY[issue].value}")
    print()
    print("Adjustment by reliance tier (rank delta, clamped to the enum):")
    for tier, delta in TIER_ADJUSTMENT.items():
        print(f"  {tier.value:<14} {delta:+d}")
    print()
    print("Reliance is derived from how many enabled detections read the source and the")
    print("highest severity among them, so no call site chooses it.")
    print()
    print("Anything resting on a determination of 'unknown' is capped at low and")
    print("reported as operational, so a source this tool could not query can never")
    print("trip a threshold or read as a source the SIEM does not have.")
    print()
    print("Worked example:")
    example = rate(Issue.SOURCE_LONG_SILENT, tier=RelianceTier.CRITICAL_PATH)
    print(f"  source_long_silent on a critical-path source -> {example.value}")
    quiet = rate(Issue.SOURCE_LONG_SILENT, tier=RelianceTier.NONE)
    print(f"  the same issue where no enabled detection reads it -> {quiet.value}")
    capped = rate(Issue.SOURCE_LONG_SILENT, determination=Determination.UNKNOWN)
    print(f"  the same issue when the fact could not be determined -> {capped.value}")
    return EXIT_OK


def cmd_validate(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
    except ValidationError as exc:
        log.error("config error: %s", exc)
        return EXIT_ERROR

    print("Config is valid.")
    print(f"  rules:      {_rule_origins(config)}")
    print(f"  ingestion:  {config.ingestion.type}")
    print(f"  inventory:  {config.inventory.path or '(none declared)'}")
    print(f"  analyses:   {', '.join(config.settings.analyses)}")
    print(f"  fail_on:    {config.settings.fail_on.value}")
    print(f"  staleness:  {config.policy.staleness_days} days")
    print(f"  aliases:    {len(config.policy.source_aliases)} local source name(s) mapped")

    if not config.inventory.path:
        print()
        print("  NOTE: no inventory.path. A critical system nobody onboarded cannot be detected")
        print("        without one — it produces no ingestion row and breaks no detection.")

    missing: list[str] = []
    if (
        config.ingestion.type == "splunk"
        and config.ingestion.splunk
        and not os.environ.get(config.ingestion.splunk.token_env)
    ):
        missing.append(config.ingestion.splunk.token_env)
    if (
        config.ingestion.type == "sentinel"
        and config.ingestion.sentinel
        and not config.ingestion.sentinel.client_secret()
    ):
        missing.append(config.ingestion.sentinel.client_secret_env)
    if config.notify.slack_webhook_url_env and not config.notify.slack_webhook_url():
        missing.append(config.notify.slack_webhook_url_env)
    if config.notify.webhook_url_env and not config.notify.webhook_url():
        missing.append(config.notify.webhook_url_env)
    if config.ai.enabled and not config.ai.api_key():
        missing.append(config.ai.api_key_env)

    if missing:
        print()
        print("Referenced but unset environment variable(s): " + ", ".join(missing))

    unimplemented = set(config.settings.analyses) - set(registered_analyses())
    if unimplemented:  # pragma: no cover - the invariants job makes this unreachable
        print(f"Analyses with no implementation: {', '.join(sorted(unimplemented))}")
        return EXIT_ERROR

    unknown = set(config.settings.analyses) - set(ALL_ANALYSES)
    if unknown:  # pragma: no cover - config parsing rejects these first
        print(f"Unknown analyses: {', '.join(sorted(unknown))}")
        return EXIT_ERROR

    return EXIT_OK


# --------------------------------------------------------------------------


def _rule_origins(config: object) -> str:
    parts: list[str] = []
    rules = getattr(config, "rules", None)
    if rules is not None:
        if rules.sigma is not None:
            parts.append(f"sigma:{rules.sigma.path}")
        if rules.mapping is not None:
            parts.append(f"mapping:{rules.mapping.path}")
    return ", ".join(parts) or "(none)"


def _write_report(report: ScanReport, output: str, fmt: str) -> None:
    rendered = render(report, fmt)
    if output == "-":
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")
        return

    path = Path(output).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    # 0600, for the same reason the state file is: a report from this tool names
    # the techniques nobody would see and how long that has been true.
    # Inheriting the process umask would leave that world-readable on a shared
    # host or a multi-tenant runner.
    handle = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8")
    with handle:
        handle.write(rendered)
    # O_CREAT leaves the mode of an already-existing file alone, and a report
    # path is usually reused run after run, so set it explicitly too.
    os.chmod(path, 0o600)
    log.info("wrote %s report to %s", fmt, path)


def _exit_code(report: ScanReport, fail_on: Severity) -> int:
    if report.scan_degraded:
        log.error(
            "the run is degraded (%d rules read, %d of %d analyses failed); refusing to report a "
            "clean result",
            report.rules_seen,
            report.analyses_failed,
            report.analyses_run,
        )
        return EXIT_ERROR

    highest = report.max_severity
    if highest is not None and highest >= fail_on:
        log.info("highest severity %s meets the %s threshold", highest.value, fail_on.value)
        return EXIT_FINDINGS
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(getattr(args, "verbose", 0), quiet=getattr(args, "quiet", False))

    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        log.error("interrupted")
        return EXIT_ERROR
    except (ValidationError, SourceError, StateError) as exc:
        log.error("%s", exc)
        return EXIT_ERROR
    except Exception:  # noqa: BLE001 - exit 1 means "findings", never "crashed"
        # Python exits 1 on an unhandled exception, which is indistinguishable
        # from EXIT_FINDINGS. Anything unexpected must surface as EXIT_ERROR.
        log.exception("unexpected error; the run did not complete")
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
