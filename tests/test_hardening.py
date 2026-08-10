"""Regression tests for the hardening pass.

Each corresponds to a specific defect found during adversarial review. Grouped
separately from the behavioural tests so it stays obvious that deleting one
re-opens a known hole.

The recurring adversary is the same throughout: whoever wrote the rule files and
whatever produced the ingestion export. Neither is this tool, neither is the team
reading the report, and a detection repository is usually a public one with a
hundred contributors and a fork somebody maintains locally.
"""

from __future__ import annotations

import json
import re

import pytest

from conftest import ingested, iso, make_config, make_state, rule, run_analysis
from logcoverage import ai, notify
from logcoverage.analysis import registered_analyses
from logcoverage.config import ALL_ANALYSES, AIConfig, NotifyConfig
from logcoverage.logging_setup import redact
from logcoverage.models import (
    Determination,
    Finding,
    FindingKind,
    ScanReport,
    Severity,
    TechniqueCoverage,
    TechniqueStatus,
    _widen,
    parse_iso,
    plural,
)
from logcoverage.notify import _escape, _escape_code, _plain
from logcoverage.report import (
    MAX_RENDERED_FINDINGS,
    _code,
    _md,
    _md_block,
    _md_url,
    _render_findings,
    render,
    render_html,
    render_markdown,
)
from logcoverage.severity import BASE_SEVERITY, Issue, rate
from logcoverage.validation import normalize_key, safe_text, scrub_evidence

HOSTILE_NAME = (
    "Coverage ![](https://evil.example/beacon.png) [Verified](https://evil.example/phish) <img src=x>"
)


def _finding(
    *,
    subject: str = "windows/sysmon",
    title: str = "Source has been silent for 130 days",
    detail: str = "x",
    kind: FindingKind = FindingKind.COVERAGE,
) -> Finding:
    return Finding(
        subject=subject,
        subject_id="source:windows/sysmon",
        analysis="silent_source",
        issue=Issue.SOURCE_SILENT.value,
        kind=kind,
        severity=Severity.HIGH,
        title=title,
        detail=detail,
    )


def _report(**overrides) -> ScanReport:
    kwargs = {
        "started_at": "2026-08-10T00:00:00+00:00",
        "finished_at": "2026-08-10T00:00:05+00:00",
        "tool_version": "0.1.0",
        "siem": "file",
        "estate": "default",
        "rules_seen": 3,
        "sources_seen": 2,
        "analyses_run": 7,
    }
    kwargs.update(overrides)
    return ScanReport(**kwargs)  # type: ignore[arg-type]


class TestMarkdownInjection:
    """Rule titles come from files this tool did not write; reports get read in tickets."""

    def test_link_and_image_syntax_is_neutralised(self) -> None:
        rendered = _md(HOSTILE_NAME)
        assert "](https://evil.example" not in rendered
        assert "\\[" in rendered and "\\!" in rendered

    def test_html_tags_cannot_survive(self) -> None:
        assert "<img" not in _md(HOSTILE_NAME)

    def test_backtick_cannot_break_out_of_a_code_span(self) -> None:
        rendered = _md("Sysmon` is fine **owned**")
        assert "\\`" in rendered
        assert not re.search(r"(?<!\\)`", rendered)
        # Emphasis markers are deliberately left alone: the worst they do is make
        # text bold, and escaping them mangles every `source_required_absent`.
        assert "**owned**" in rendered

    def test_arrows_and_ordinary_text_survive(self) -> None:
        assert _md("live -> paper") == "live -> paper"
        assert _md("WinEventLog:Security") == "WinEventLog:Security"

    def test_a_bare_url_is_quarantined_in_a_code_span(self) -> None:
        """Autolinking needs no metacharacter, so escaping cannot fix it."""
        rendered = _md("Acknowledge at https://evil.example/ack now")
        assert "`https://evil.example/ack`" in rendered

    def test_a_www_prefixed_url_is_quarantined_too(self) -> None:
        assert "`www.evil.example/ack`" in _md("Go to www.evil.example/ack")

    def test_the_quarantine_span_always_closes(self) -> None:
        rendered = _md("see https://evil.example/`backtick")
        assert "`https://evil.example/`" in rendered
        assert "\\`backtick" in rendered

    def test_a_leading_blockquote_is_neutralised(self) -> None:
        assert _md("> coverage confirmed").startswith("&gt;")

    def test_control_characters_cannot_forge_a_line(self) -> None:
        assert "\n" not in _md("Sysmon\n🟢 CRITICAL — full coverage")

    def test_a_trailing_backslash_cannot_open_the_emphasis(self) -> None:
        """The backslash escapes the *renderer's* markup, not the value's.

        A title ending in one lands inside the `**…**` this module wraps a
        finding title in, where `\\**` reads as an escaped asterisk and a stray
        one: the strong emphasis never closes and runs on into the findings
        below it, which is a forged report line reached without a bracket.
        """
        rendered = "\n".join(_render_findings([_finding(title="Coverage verified \\")]))
        line = next(entry for entry in rendered.splitlines() if "Coverage verified" in entry)
        assert line.endswith("**  ")
        assert "\\\\**" in line


class TestToolAuthoredTextIsNotOverEscaped:
    """The escaping is correct; English with brackets in it is not.

    Every finding this tool writes counts something, and "130 day(s)" rendered
    through a correct Markdown escaper is "130 day\\(s\\)" — a report full of
    visible backslashes, which reads as a broken tool rather than a careful one.
    """

    def test_a_rendered_finding_carries_no_stray_backslash(self) -> None:
        state = make_state(
            rules=[rule("r1"), rule("r2", name="B"), rule("r3", name="C")],
            sources=[ingested(last_event=iso(130), event_count=0)],
        )
        findings: list[Finding] = []
        for name in ("required_absent", "silent_source", "technique_coverage"):
            findings += run_analysis(name, state, make_config()).findings
        assert findings
        rendered = "\n".join(_render_findings(findings))
        assert "\\" not in rendered

    def test_the_plural_helper_is_what_writes_the_counts(self) -> None:
        assert plural(1, "day") == "day"
        assert plural(0, "day") == "days"
        assert plural(2, "detection") == "detections"


class TestCodeSpanRendering:
    def test_backslashes_are_not_printed_inside_a_span(self) -> None:
        assert _code("WinEventLog:Security (prod)") == "WinEventLog:Security (prod)"

    def test_a_backtick_cannot_close_the_span(self) -> None:
        assert "`" not in _code("sourcetype`")

    def test_angle_brackets_are_entity_escaped_even_inside_a_span(self) -> None:
        assert _code("<img src=x>") == "&lt;img src=x&gt;"

    def test_the_rendered_finding_line_is_readable_and_inert(self) -> None:
        """Two properties a code-span value has to hold at once.

        Readable: an engineer sees the real source name, not a soup of
        backslashes. Inert: the code span is the only place raw link syntax
        appears, and no CommonMark implementation interprets it there.
        """
        payload = "sysmon ![](https://evil.example/px.png) [Fix](https://evil.example/phish)"
        rendered = "\n".join(_render_findings([_finding(subject=payload)]))
        assert f"`{payload}`" in rendered
        assert "](https://evil.example" not in rendered.replace(f"`{payload}`", "")


class TestSummaryInjection:
    """Model output lands above the deterministic findings and must not restructure them."""

    @pytest.mark.parametrize("marker", ["#", ">", "-", "+", "=", "*", "_", "|", "~"])
    def test_a_line_leading_marker_is_escaped(self, marker: str) -> None:
        assert _md_block(f"{marker} Coverage is complete").startswith("\\")

    def test_a_forged_table_cannot_open(self) -> None:
        """A fake coverage table in the Summary is the one thing a reader acts on."""
        rendered = _md_block("| Live | Paper |\n| --- | --- |\n| 400 | 0 |")
        assert not any(line.startswith("|") for line in rendered.splitlines())

    def test_an_ordered_list_marker_is_escaped_without_a_stray_backslash(self) -> None:
        rendered = _md_block("1. Everything is covered")
        assert rendered.startswith("1\\.")

    def test_a_tilde_fence_cannot_swallow_the_report(self) -> None:
        assert _md_block("~~~").startswith("\\")

    def test_paragraph_breaks_survive(self) -> None:
        assert "\n\n" in _md_block("first\n\nsecond")

    def test_runs_of_blank_lines_collapse(self) -> None:
        assert "\n\n\n" not in _md_block("a\n\n\n\n\nb")

    def test_a_url_in_the_summary_is_quarantined(self) -> None:
        assert "`https://evil.example`" in _md_block("see https://evil.example")


class TestReferenceUrls:
    def test_an_attack_link_survives(self) -> None:
        assert _md_url("https://attack.mitre.org/techniques/T1021/002/").startswith("https://")

    def test_a_url_with_a_closing_paren_is_dropped(self) -> None:
        assert _md_url("https://evil.example/x)malicious") == ""

    def test_a_non_http_scheme_is_dropped(self) -> None:
        assert _md_url("javascript:alert(1)") == ""

    def test_a_url_with_a_space_is_dropped(self) -> None:
        assert _md_url("https://evil.example/a b") == ""


class TestHtmlEscaping:
    def test_a_hostile_subject_cannot_inject_a_tag(self) -> None:
        html_out = render_html(_report(findings=[_finding(subject=HOSTILE_NAME)]))
        assert "<img src=x>" not in html_out
        assert "&lt;img src=x&gt;" in html_out

    def test_a_hostile_technique_id_is_escaped(self) -> None:
        entry = TechniqueCoverage(
            technique="<script>alert(1)</script>",
            status=TechniqueStatus.PAPER,
            rules_total=1,
            blocking_sources=("<b>x</b>",),
        )
        html_out = render_html(_report(techniques=[entry]))
        assert "<script>" not in html_out
        assert "&lt;b&gt;x&lt;/b&gt;" in html_out

    def test_coverage_notes_appear_in_html_too(self) -> None:
        """An incomplete run must not look like a clean one in any format."""
        html_out = render_html(_report(indeterminate_facets=["ingestion_recency"]))
        assert "ingestion_recency" in html_out
        assert "Coverage and collection notes" in html_out

    def test_the_missing_baseline_is_stated_in_html(self) -> None:
        assert "No baseline" in render_html(_report(baseline_available=False))

    def test_the_summary_is_escaped(self) -> None:
        html_out = render_html(_report(ai_summary="<script>alert(1)</script>"))
        assert "<script>alert" not in html_out

    def test_there_is_no_javascript_or_external_asset(self) -> None:
        html_out = render_html(_report(findings=[_finding()]))
        assert "<script" not in html_out
        assert "http://" not in html_out


class TestMarkdownReport:
    def test_the_technique_table_leads_the_report(self) -> None:
        entry = TechniqueCoverage(technique="T1059.001", status=TechniqueStatus.PAPER, rules_total=2)
        rendered = render_markdown(_report(techniques=[entry], findings=[_finding()]))
        assert rendered.index("Coverage by ATT&CK technique") < rendered.index("Coverage gaps")

    def test_paper_techniques_are_listed_in_full(self) -> None:
        entry = TechniqueCoverage(technique="T1059.001", status=TechniqueStatus.PAPER, rules_total=2)
        assert "T1059.001" in render_markdown(_report(techniques=[entry]))

    def test_live_techniques_are_counted_not_enumerated(self) -> None:
        entry = TechniqueCoverage(technique="T1021.002", status=TechniqueStatus.LIVE, rules_total=1)
        rendered = render_markdown(_report(techniques=[entry]))
        assert "T1021.002" not in rendered

    def test_drift_findings_get_their_own_section(self) -> None:
        rendered = render_markdown(_report(findings=[_finding(kind=FindingKind.DRIFT)]))
        assert "Coverage lost since the last run" in rendered

    def test_the_determination_split_is_always_published(self) -> None:
        assert "rest on an observed fact" in render_markdown(_report())

    def test_an_empty_report_says_so(self) -> None:
        assert "No findings" in render_markdown(_report())

    def test_rendering_is_bounded(self) -> None:
        report = _report(findings=[_finding() for _ in range(MAX_RENDERED_FINDINGS + 50)])
        rendered = render_markdown(report)
        assert "further finding(s) were not rendered" in rendered

    def test_an_unknown_format_raises_cleanly(self) -> None:
        with pytest.raises(ValueError, match="unknown output format"):
            render(_report(), "pdf")

    def test_json_is_valid_and_bounded(self) -> None:
        report = _report(findings=[_finding() for _ in range(600)])
        payload = json.loads(render(report, "json"))
        assert payload["findings_truncated"] is True
        assert len(payload["findings"]) <= 500


class TestSlackInjection:
    def test_mrkdwn_entities_are_escaped(self) -> None:
        assert _escape("<https://evil.example|click>") == "&lt;https://evil.example|click&gt;"

    def test_a_newline_cannot_forge_a_line(self) -> None:
        assert "\n" not in _escape("sysmon\n:white_circle: coverage confirmed")

    def test_a_backtick_cannot_close_a_code_span(self) -> None:
        assert "`" not in _escape_code("silent_source`")

    def test_plain_text_is_not_entity_escaped(self) -> None:
        """Entity-escaping a plain_text field prints a literal &lt; to the channel."""
        assert _plain("a < b") == "a < b"

    def test_plain_text_still_collapses_control_characters(self) -> None:
        assert "\n" not in _plain("a\nb")

    def test_the_detail_is_emitted_as_plain_text(self) -> None:
        """Slack mrkdwn has no backslash escape, so the only defence is a context
        where markup is not interpreted."""
        sent: dict = {}

        def fake(method, url, **kwargs):
            sent.update(kwargs.get("json_body") or {})

            class R:
                status_code = 200

            return R()

        original = notify.safe_request
        notify.safe_request = fake  # type: ignore[assignment]
        try:
            notify._post_slack(
                "https://hooks.slack.com/services/x",
                _report(),
                [_finding(title=":white_check_mark: all clear")],
                limit=10,
                user_agent="t",
            )
        finally:
            notify.safe_request = original  # type: ignore[assignment]

        detail_blocks = [b for b in sent["blocks"] if b.get("text", {}).get("type") == "plain_text"]
        assert detail_blocks
        assert all(block["text"]["emoji"] is False for block in detail_blocks)


class TestWebhookBounds:
    def test_the_payload_is_capped_but_the_total_is_honest(self) -> None:
        sent: dict = {}

        def fake(method, url, **kwargs):
            sent.update(kwargs.get("json_body") or {})

            class R:
                status_code = 200

            return R()

        original = notify.safe_request
        notify.safe_request = fake  # type: ignore[assignment]
        try:
            notify._post_generic(
                "https://example.com/hook",
                _report(),
                [_finding() for _ in range(100)],
                limit=5,
                user_agent="t",
            )
        finally:
            notify.safe_request = original  # type: ignore[assignment]

        assert len(sent["findings"]) == 5
        assert sent["findings_total"] == 100
        assert sent["findings_truncated"] is True

    def test_nothing_is_sent_below_the_threshold(self) -> None:
        config = NotifyConfig()
        report = _report(findings=[_finding()])
        report.findings[0] = Finding(
            subject="x",
            subject_id="x",
            analysis="a",
            issue="i",
            kind=FindingKind.COVERAGE,
            severity=Severity.LOW,
            title="t",
            detail="d",
        )
        assert notify.notify(report, config) == []


class TestEvidenceRedaction:
    def test_a_finding_never_holds_a_secret(self) -> None:
        finding = Finding(
            subject="x",
            subject_id="x",
            analysis="a",
            issue="i",
            kind=FindingKind.COVERAGE,
            severity=Severity.HIGH,
            title="t",
            detail="d",
            evidence={"sessionKey": "abc", "index": "wineventlog"},
        )
        assert finding.evidence["sessionKey"] == "<redacted>"
        assert json.dumps(finding.to_dict())

    def test_redaction_happens_at_construction_not_at_the_sink(self) -> None:
        """There are four sinks today and the fifth will not remember."""
        finding = Finding(
            subject="x",
            subject_id="x",
            analysis="a",
            issue="i",
            kind=FindingKind.COVERAGE,
            severity=Severity.HIGH,
            title="t",
            detail="d",
            evidence={"token": "abc"},
        )
        for fmt in ("markdown", "json", "html"):
            assert "abc" not in render(_report(findings=[finding]), fmt)

    def test_the_fingerprint_ignores_detail_and_evidence(self) -> None:
        """Rewording a finding, or a silence age ticking upward, must not
        resurface something somebody already triaged."""
        first = _finding(detail="silent for 3 days")
        second = _finding(detail="silent for 4 days")
        assert first.fingerprint == second.fingerprint

    def test_a_hostile_name_survives_serialisation(self) -> None:
        finding = _finding(subject=safe_text("rule\ud800name"))
        json.dumps(finding.to_dict())


class TestLogRedaction:
    @pytest.mark.parametrize(
        "text",
        [
            "Authorization: Splunk 8a7c9e0f1b2d3e4f",
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.signature",
            "https://hooks.slack.com/services/T000/B000/xxxxxxxxxxxx",
            "api_key=abcdefghijklmnop",
            "token: 0123456789abcdef",
        ],
    )
    def test_credential_shapes_are_redacted(self, text: str) -> None:
        assert "redacted" in redact(text).lower()

    def test_an_ordinary_message_is_untouched(self) -> None:
        message = "windows/sysmon has produced nothing for 130 days"
        assert redact(message) == message


class TestAiBoundary:
    def test_it_is_off_by_default(self) -> None:
        assert AIConfig().enabled is False

    def test_a_disabled_summariser_returns_nothing(self) -> None:
        assert ai.summarize(_report(findings=[_finding()]), AIConfig()) is None

    def test_it_cannot_create_a_finding(self) -> None:
        """The property worth more than any convenience: deterministic output is
        identical with the module deleted."""
        report = _report(findings=[_finding()])
        before = [f.to_dict() for f in report.findings]
        report.ai_summary = "the model said something"
        assert [f.to_dict() for f in report.findings] == before

    def test_the_summary_never_carries_evidence_or_detail(self) -> None:
        """Evidence holds rule paths and per-source volumes, which describe the
        estate rather than the problem."""
        keys = set(ai.summary_context_keys())
        assert "evidence" not in keys
        assert "detail" not in keys
        assert "remediation" not in keys

    def test_the_payload_matches_the_declared_key_list(self) -> None:
        captured: dict = {}

        def fake(config, *, system, user, max_tokens):
            captured["user"] = user
            return "summary"

        original = ai._call
        ai._call = fake  # type: ignore[assignment]
        try:
            config = AIConfig(enabled=True, summarize=True)
            ai.summarize(_report(findings=[_finding()]), config)
        finally:
            ai._call = original  # type: ignore[assignment]

        payload = json.loads(
            captured["user"].split("<coverage_results>\n")[1].split("\n</coverage_results>")[0]
        )
        assert set(payload["findings"][0]) == set(ai.summary_context_keys())

    def test_the_input_is_fenced_and_framed_as_untrusted(self) -> None:
        captured: dict = {}

        def fake(config, *, system, user, max_tokens):
            captured["user"] = user
            captured["system"] = system
            return "s"

        original = ai._call
        ai._call = fake  # type: ignore[assignment]
        try:
            ai.summarize(_report(findings=[_finding()]), AIConfig(enabled=True))
        finally:
            ai._call = original  # type: ignore[assignment]

        assert "<coverage_results>" in captured["user"]
        assert "untrusted" in captured["user"]
        assert "untrusted data" in captured["system"]

    def test_the_summary_length_is_bounded(self) -> None:
        def fake(config, *, system, user, max_tokens):
            return "x" * 10_000

        original = ai._call
        ai._call = fake  # type: ignore[assignment]
        try:
            summary = ai.summarize(_report(findings=[_finding()]), AIConfig(enabled=True))
        finally:
            ai._call = original  # type: ignore[assignment]
        assert summary is not None and len(summary) <= 4000

    def test_the_endpoint_is_fixed(self) -> None:
        assert ai.ANTHROPIC_ENDPOINT == "https://api.anthropic.com/v1/messages"


class TestRegistryInvariants:
    def test_every_declared_analysis_is_implemented(self) -> None:
        """An analysis an operator can select and no code implements is a
        permanently green, permanently blind run."""
        assert set(ALL_ANALYSES) <= set(registered_analyses())

    def test_no_analysis_is_implemented_without_being_declared(self) -> None:
        assert set(registered_analyses()) == set(ALL_ANALYSES)

    def test_every_issue_is_rated_at_every_tier_without_raising(self) -> None:
        from logcoverage.severity import RelianceTier

        for issue in Issue:
            for tier in RelianceTier:
                for determination in Determination:
                    assert rate(issue, tier=tier, determination=determination) in list(Severity)

    def test_no_issue_is_missing_from_the_table(self) -> None:
        assert all(issue in BASE_SEVERITY for issue in Issue)


class TestSafeTextAtIngestion:
    def test_a_hostile_rule_title_is_sanitised_by_the_builder(self) -> None:
        state = make_state(rules=[rule(name=safe_text("Coverage\nconfirmed"))])
        assert "\n" not in state.rules[0].name

    def test_a_hostile_source_name_normalises_without_collapsing(self) -> None:
        assert normalize_key("‮nomsys") != ""

    def test_scrubbing_bounds_a_hostile_evidence_blob(self) -> None:
        blob = {"rules": [f"rule-{i}" for i in range(5000)]}
        assert len(scrub_evidence(blob)["rules"]) <= 51


class TestReportDegradation:
    def test_no_rules_means_the_run_is_degraded(self) -> None:
        """A tool that reports full coverage because its token expired is worse
        than one that fails loudly."""
        assert _report(rules_seen=0).scan_degraded

    def test_most_analyses_failing_means_degraded(self) -> None:
        assert _report(analyses_run=7, analyses_failed=5).scan_degraded

    def test_one_failure_out_of_seven_is_not_degraded(self) -> None:
        assert not _report(analyses_run=7, analyses_failed=1).scan_degraded

    def test_a_single_analysis_failing_does_not_trip_the_floor(self) -> None:
        assert not _report(analyses_run=2, analyses_failed=2).scan_degraded

    def test_the_technique_status_counts_are_complete(self) -> None:
        counts = _report().counts_by_technique_status()
        assert set(counts) == {status.value for status in TechniqueStatus}


class TestIngestedSourceModel:
    def test_events_per_day_is_none_when_volume_is_unknown(self) -> None:
        source = ingested(volume_known=Determination.UNKNOWN)
        assert source.events_per_day is None

    def test_events_per_day_divides_by_the_window(self) -> None:
        assert ingested(event_count=70, window_days=7).events_per_day == 10

    def test_a_zero_window_does_not_divide_by_zero(self) -> None:
        assert ingested(window_days=0).events_per_day is None

    def test_determination_parses_unknown_values_as_unknown(self) -> None:
        """Defaulting the other way would make an older state file read as
        "definitively absent" for every source in the estate."""
        assert Determination.parse("nonsense") is Determination.UNKNOWN
        assert Determination.parse(None) is Determination.UNKNOWN

    def test_from_optional_maps_the_tri_state(self) -> None:
        assert Determination.from_optional(None) is Determination.UNKNOWN
        assert Determination.from_optional(True) is Determination.PRESENT
        assert Determination.from_optional(False) is Determination.ABSENT


class TestTimestampParsing:
    """The shapes the tool's own sources produce, not the shape Python writes.

    Both of these are refused by ``datetime.fromisoformat`` before 3.11, which is
    inside the range this package declares support for. Unparsed, every source
    comes back with no usable recency and the whole facet degrades to "could not
    determine" against a real search head — while a test suite written with
    Python-shaped timestamps stays green.
    """

    @pytest.mark.parametrize(
        ("raw", "expected_hour"),
        [
            ("2026-08-10T05:58:12+0000", 5),  # Splunk strftime %z
            ("2026-08-10T05:58:12-0700", 12),
            ("2026-08-10T05:58:12.1234567Z", 5),  # Log Analytics ticks
            ("2026-08-10T05:58:12.1234567+0000", 5),
            ("2026-08-10T05:58:12+00:00", 5),
            ("2026-08-10T05:58:12Z", 5),
        ],
    )
    def test_a_real_siem_timestamp_parses_to_utc(self, raw: str, expected_hour: int) -> None:
        parsed = parse_iso(raw)
        assert parsed is not None
        assert parsed.tzinfo is not None
        assert parsed.hour == expected_hour

    @pytest.mark.parametrize(
        ("raw", "normalised"),
        [
            ("2026-08-10T05:58:12+0000", "2026-08-10T05:58:12+00:00"),
            ("2026-08-10T05:58:12.1234567+00:00", "2026-08-10T05:58:12.123456+00:00"),
            ("2026-08-10T05:58:12.1+00:00", "2026-08-10T05:58:12.100000+00:00"),
            ("2026-08-10T05:58:12+00:00", "2026-08-10T05:58:12+00:00"),
            ("not a timestamp", "not a timestamp"),
        ],
    )
    def test_the_normalised_form_is_what_every_interpreter_accepts(self, raw: str, normalised: str) -> None:
        """Pinned as a string, not as a parse.

        3.11 widened ``fromisoformat`` enough to swallow both spellings, so a
        test that only parses passes on a new interpreter whatever the code does
        — which is exactly how this survived. The output shape is the contract:
        microsecond precision and a colon in the offset, which is what
        ``datetime.isoformat()`` emits and what 3.10 will accept.
        """
        assert _widen(raw) == normalised

    def test_sub_microsecond_precision_is_truncated_not_rejected(self) -> None:
        parsed = parse_iso("2026-08-10T05:58:12.1234567Z")
        assert parsed is not None
        assert parsed.microsecond == 123456

    def test_something_that_is_not_a_timestamp_is_still_none(self) -> None:
        """Guessing would make every malformed date read as silent since 1970."""
        assert parse_iso("last tuesday") is None
        assert parse_iso("") is None
        assert parse_iso("2026-13-45T99:99:99+0000") is None
