"""Rule inputs: the bounded traversal, the Sigma parser, the mapping parser.

A rule directory is the least trustworthy input this tool has — usually a clone
of somebody else's repository — so most of what is tested here is what happens
when it is not what it claims to be.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from logcoverage.models import Determination, RuleFormat
from logcoverage.rules import (
    LoadedFile,
    RuleLoadError,
    parse_mapping_file,
    parse_sigma_documents,
    read_file,
    walk_rule_tree,
)
from logcoverage.validation import ValidationError

SIGMA = """
title: PsExec Service Installation
id: 42c575ea-e01e-4a44-9a1a-0d16e1b1e3f1
status: stable
tags:
    - attack.lateral_movement
    - attack.t1021.002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 7045
        ServiceName|contains: 'PSEXESVC'
    condition: selection
level: high
"""


def loaded(text: str, path: str = "rule.yml") -> LoadedFile:
    return LoadedFile(path=path, data=text.encode("utf-8"))


def walk(root: Path, **overrides: int):
    kwargs = {
        "max_files": 1000,
        "max_file_bytes": 1024 * 1024,
        "max_total_bytes": 10 * 1024 * 1024,
        "max_depth": 8,
    }
    kwargs.update(overrides)
    return walk_rule_tree(root, **kwargs)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# traversal
# --------------------------------------------------------------------------


class TestTraversalHardening:
    def test_a_symlinked_file_is_skipped_and_named(self, tmp_path: Path) -> None:
        """Not "no escaping symlinks" — no symlinks.

        Escape detection by path comparison is a race: the check and the open are
        two lookups of the same name.
        """
        (tmp_path / "real.yml").write_text(SIGMA)
        secret = tmp_path.parent / "secret.yml"
        secret.write_text("title: secret\n")
        os.symlink(secret, tmp_path / "link.yml")

        result = walk(tmp_path)
        assert [f.path for f in result.files] == ["real.yml"]
        assert any("link.yml" in note and "symlink" in note for note in result.skipped)

    def test_a_symlink_inside_the_root_is_still_refused(self, tmp_path: Path) -> None:
        (tmp_path / "real.yml").write_text(SIGMA)
        os.symlink(tmp_path / "real.yml", tmp_path / "copy.yml")
        result = walk(tmp_path)
        assert [f.path for f in result.files] == ["real.yml"]

    def test_a_symlinked_directory_is_not_descended(self, tmp_path: Path) -> None:
        elsewhere = tmp_path.parent / "elsewhere"
        elsewhere.mkdir(exist_ok=True)
        (elsewhere / "other.yml").write_text(SIGMA)
        (tmp_path / "keep.yml").write_text(SIGMA)
        os.symlink(elsewhere, tmp_path / "linked")

        result = walk(tmp_path)
        assert [f.path for f in result.files] == ["keep.yml"]

    def test_a_symlinked_root_is_refused_outright(self, tmp_path: Path) -> None:
        real = tmp_path / "real"
        real.mkdir()
        (real / "a.yml").write_text(SIGMA)
        link = tmp_path / "link"
        os.symlink(real, link)
        with pytest.raises(RuleLoadError, match="symlink"):
            walk(link)

    def test_a_fifo_is_refused_rather_than_blocking(self, tmp_path: Path) -> None:
        """O_NONBLOCK matters: opening a FIFO for reading blocks inside os.open,
        before any regular-file check can refuse it."""
        fifo = tmp_path / "pipe.yml"
        os.mkfifo(fifo)
        result = walk(tmp_path)
        assert result.files == []
        assert any("pipe.yml" in note for note in result.skipped)

    def test_reading_a_fifo_directly_raises(self, tmp_path: Path) -> None:
        fifo = tmp_path / "pipe"
        os.mkfifo(fifo)
        with pytest.raises(RuleLoadError, match="not a regular file"):
            read_file(fifo, max_bytes=1024)

    def test_reading_a_symlink_directly_raises(self, tmp_path: Path) -> None:
        target = tmp_path / "target"
        target.write_text("x")
        link = tmp_path / "link"
        os.symlink(target, link)
        with pytest.raises(RuleLoadError):
            read_file(link, max_bytes=1024)

    def test_a_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(RuleLoadError, match="not found"):
            read_file(tmp_path / "nope", max_bytes=1024)

    def test_a_missing_root_raises(self, tmp_path: Path) -> None:
        with pytest.raises(RuleLoadError, match="not found"):
            walk(tmp_path / "nope")


class TestTraversalBounds:
    def test_file_count_is_capped_and_marked_truncated(self, tmp_path: Path) -> None:
        for i in range(10):
            (tmp_path / f"r{i}.yml").write_text(SIGMA)
        result = walk(tmp_path, max_files=3)
        assert len(result.files) == 3
        assert result.truncated

    def test_an_oversized_file_is_skipped_not_fatal(self, tmp_path: Path) -> None:
        (tmp_path / "big.yml").write_text("x" * 5000)
        (tmp_path / "small.yml").write_text(SIGMA)
        result = walk(tmp_path, max_file_bytes=1000)
        assert [f.path for f in result.files] == ["small.yml"]
        assert any("big.yml" in note for note in result.skipped)

    def test_total_bytes_are_capped(self, tmp_path: Path) -> None:
        for i in range(5):
            (tmp_path / f"r{i}.yml").write_text("y" * 900)
        result = walk(tmp_path, max_total_bytes=2000)
        assert len(result.files) < 5
        assert result.truncated

    def test_depth_is_capped(self, tmp_path: Path) -> None:
        deep = tmp_path
        for level in range(6):
            deep = deep / f"l{level}"
            deep.mkdir()
            (deep / "r.yml").write_text(SIGMA)
        result = walk(tmp_path, max_depth=2)
        assert len(result.files) == 2
        assert result.truncated

    def test_non_yaml_files_are_ignored_silently(self, tmp_path: Path) -> None:
        (tmp_path / "README.md").write_text("# hello")
        (tmp_path / "r.yml").write_text(SIGMA)
        result = walk(tmp_path)
        assert [f.path for f in result.files] == ["r.yml"]
        assert result.skipped == []

    def test_yaml_suffix_is_accepted(self, tmp_path: Path) -> None:
        (tmp_path / "r.yaml").write_text(SIGMA)
        assert [f.path for f in walk(tmp_path).files] == ["r.yaml"]

    def test_ordering_is_deterministic(self, tmp_path: Path) -> None:
        """These paths become rule keys, and the keys are persisted and compared
        between runs. Filesystem order differs between machines."""
        sub = tmp_path / "b"
        sub.mkdir()
        for name in ("z.yml", "a.yml"):
            (tmp_path / name).write_text(SIGMA)
            (sub / name).write_text(SIGMA)
        paths = [f.path for f in walk(tmp_path).files]
        assert paths == sorted(paths)

    def test_a_single_file_root_is_read(self, tmp_path: Path) -> None:
        target = tmp_path / "only.yml"
        target.write_text(SIGMA)
        assert [f.path for f in walk(target).files] == ["only.yml"]


# --------------------------------------------------------------------------
# Sigma
# --------------------------------------------------------------------------


class TestSigmaParsing:
    def test_the_basics_are_extracted(self) -> None:
        (rule,) = parse_sigma_documents(loaded(SIGMA))
        assert rule.rule_id == "42c575ea-e01e-4a44-9a1a-0d16e1b1e3f1"
        assert rule.sources == ("windows/security",)
        assert rule.techniques == ("T1021.002",)
        assert rule.level == "high"
        assert rule.enabled
        assert rule.parsed.is_present
        assert rule.fmt is RuleFormat.SIGMA

    def test_field_modifiers_are_stripped_for_matching(self) -> None:
        (rule,) = parse_sigma_documents(loaded(SIGMA))
        assert "servicename" in rule.fields
        assert "servicename|contains" not in rule.fields

    def test_the_original_field_spelling_is_kept_for_display(self) -> None:
        (rule,) = parse_sigma_documents(loaded(SIGMA))
        assert "ServiceName" in rule.field_labels
        assert rule.label_for("servicename") == "ServiceName"

    def test_the_condition_key_is_not_a_field(self) -> None:
        (rule,) = parse_sigma_documents(loaded(SIGMA))
        assert "condition" not in rule.fields

    def test_a_null_valued_field_is_not_a_requirement(self) -> None:
        """`ParentImage: null` matches events where the field is *absent*.

        Counted as a requirement it inverts the rule: a source that does not
        carry the field satisfies the condition, and the tool would report a
        field gap against exactly the telemetry the rule was written for — and
        mark the rule blind, and its technique paper, if every selection is one.
        """
        text = """
title: t
logsource: {product: windows, service: security}
detection:
    selection:
        Image|endswith: rundll32.exe
        ParentImage: null
    condition: selection
"""
        (rule,) = parse_sigma_documents(loaded(text))
        assert rule.fields == ("image",)
        assert rule.field_labels == ("Image",)

    def test_a_field_with_a_value_elsewhere_is_still_a_requirement(self) -> None:
        text = """
title: t
logsource: {product: windows, service: security}
detection:
    absent: {ParentImage: null}
    named: {ParentImage|contains: cmd.exe}
    condition: absent or named
"""
        (rule,) = parse_sigma_documents(loaded(text))
        assert rule.fields == ("parentimage",)

    def test_a_list_of_selections_contributes_its_fields(self) -> None:
        text = """
title: t
logsource: {product: windows, service: security}
detection:
    selection:
        - EventID: 1
        - Image: x
    condition: selection
"""
        (rule,) = parse_sigma_documents(loaded(text))
        assert set(rule.fields) == {"eventid", "image"}

    def test_a_keyword_search_contributes_no_fields(self) -> None:
        """A keyword search reads the raw event, so no specific field's absence
        would stop it firing. Claiming otherwise would invent a gap."""
        text = """
title: t
logsource: {product: windows, service: security}
detection:
    keywords:
        - 'mimikatz'
    condition: keywords
"""
        (rule,) = parse_sigma_documents(loaded(text))
        assert rule.fields == ()

    def test_top_level_fields_are_merged(self) -> None:
        text = """
title: t
logsource: {product: windows, service: security}
detection:
    selection: {EventID: 1}
    condition: selection
fields:
    - ParentImage
"""
        (rule,) = parse_sigma_documents(loaded(text))
        assert "parentimage" in rule.fields

    def test_a_deprecated_rule_is_disabled(self) -> None:
        (rule,) = parse_sigma_documents(loaded(SIGMA.replace("status: stable", "status: deprecated")))
        assert not rule.enabled
        assert rule.parsed.is_present

    @pytest.mark.parametrize("status", ["unsupported", "disabled", "retired"])
    def test_other_dead_statuses_are_disabled(self, status: str) -> None:
        (rule,) = parse_sigma_documents(loaded(SIGMA.replace("status: stable", f"status: {status}")))
        assert not rule.enabled

    def test_an_unknown_level_falls_back_to_medium(self) -> None:
        (rule,) = parse_sigma_documents(loaded(SIGMA.replace("level: high", "level: catastrophic")))
        assert rule.level == "medium"

    def test_unknown_keys_are_ignored_rather_than_rejected(self) -> None:
        """A Sigma file is somebody else's, and the spec gains keys between
        releases. Rejecting unknown keys would refuse most real rule sets."""
        (rule,) = parse_sigma_documents(loaded(SIGMA + "\ncorrelation:\n  type: value_count\n"))
        assert rule.parsed.is_present

    def test_multiple_documents_produce_multiple_rules(self) -> None:
        (first, second) = parse_sigma_documents(loaded(SIGMA + "\n---\n" + SIGMA))
        assert first.path != second.path

    def test_a_global_document_is_skipped_without_complaint(self) -> None:
        text = "action: global\nlogsource:\n  product: windows\n---\n" + SIGMA
        rules = parse_sigma_documents(loaded(text))
        assert len(rules) == 1

    def test_a_non_rule_yaml_file_produces_nothing(self) -> None:
        """A CI config in the rule directory is not a broken detection."""
        assert parse_sigma_documents(loaded("name: ci\non: push\n")) == []


class TestSigmaDegradation:
    """A malformed rule becomes indeterminate, never skipped and never crashing."""

    def test_invalid_yaml_becomes_an_indeterminate_rule(self) -> None:
        (rule,) = parse_sigma_documents(loaded("title: x\n  bad: [unclosed\n"))
        assert rule.parsed.is_unknown
        assert rule.parse_error

    def test_an_indeterminate_rule_claims_no_sources(self) -> None:
        """It must not count as backed, and its sources must not be reported as
        missing. We do not know what it reads."""
        (rule,) = parse_sigma_documents(loaded("title: x\n  bad: [unclosed\n"))
        assert rule.sources == ()
        assert rule.techniques == ()
        assert not rule.enabled

    def test_invalid_utf8_becomes_indeterminate(self) -> None:
        (rule,) = parse_sigma_documents(LoadedFile(path="r.yml", data=b"\xff\xfe\x00title"))
        assert rule.parsed.is_unknown

    def test_a_document_that_is_not_a_mapping_becomes_indeterminate(self) -> None:
        (rule,) = parse_sigma_documents(loaded("- just\n- a\n- list\n"))
        assert rule.parsed.is_unknown

    def test_a_missing_logsource_becomes_indeterminate(self) -> None:
        text = "title: t\ndetection:\n  selection: {EventID: 1}\n  condition: selection\n"
        (rule,) = parse_sigma_documents(loaded(text))
        assert rule.parsed.is_unknown
        assert "logsource" in rule.parse_error

    def test_an_empty_logsource_becomes_indeterminate(self) -> None:
        """A rule reads *something*; treating it as reading nothing would let it
        count as backed by telemetry it never named."""
        text = "title: t\nlogsource: {definition: needs an agent}\ndetection:\n  condition: x\n"
        (rule,) = parse_sigma_documents(loaded(text))
        assert rule.parsed.is_unknown

    def test_a_non_mapping_logsource_becomes_indeterminate(self) -> None:
        text = "title: t\nlogsource: windows\ndetection:\n  condition: x\n"
        (rule,) = parse_sigma_documents(loaded(text))
        assert rule.parsed.is_unknown

    def test_yaml_cannot_construct_a_python_object(self) -> None:
        text = "title: !!python/object/apply:os.system ['echo pwned']\n"
        (rule,) = parse_sigma_documents(loaded(text))
        assert rule.parsed.is_unknown

    def test_documents_per_file_are_bounded(self) -> None:
        rules = parse_sigma_documents(loaded("\n---\n".join([SIGMA] * 200)))
        assert len(rules) <= 50

    def test_fields_per_rule_are_bounded(self) -> None:
        selection = "\n".join(f"        F{i}: {i}" for i in range(500))
        text = f"title: t\nlogsource: {{product: windows, service: security}}\ndetection:\n    selection:\n{selection}\n    condition: selection\n"
        (rule,) = parse_sigma_documents(loaded(text))
        assert len(rule.fields) <= 120

    def test_the_document_index_is_part_of_the_identity(self) -> None:
        """Two rules sharing an identity would let one stand in for the other in
        every count this tool produces."""
        rules = parse_sigma_documents(loaded(SIGMA.replace("id: 42c", "id2: 42c") + "\n---\n" + SIGMA))
        assert len({r.path for r in rules}) == len(rules)


# --------------------------------------------------------------------------
# the mapping file
# --------------------------------------------------------------------------

MAPPING = """
rules:
  - id: spl-1
    name: "PsExec on a server VLAN"
    query_language: spl
    level: high
    sources: [WinEventLog:Security]
    fields: [EventCode, ServiceName]
    techniques: [T1021.002]
"""


class TestMappingParsing:
    def test_a_rule_is_parsed(self) -> None:
        (rule,) = parse_mapping_file(MAPPING.encode())
        assert rule.rule_id == "spl-1"
        assert rule.sources == ("windows/security",)
        assert rule.fields == ("eventcode", "servicename")
        assert rule.techniques == ("T1021.002",)
        assert rule.fmt is RuleFormat.MAPPING
        assert rule.parsed is Determination.PRESENT

    def test_field_labels_keep_the_operator_spelling(self) -> None:
        (rule,) = parse_mapping_file(MAPPING.encode())
        assert rule.label_for("eventcode") == "EventCode"

    def test_an_empty_file_is_no_rules(self) -> None:
        assert parse_mapping_file(b"") == []
        assert parse_mapping_file(b"rules:\n") == []

    def test_unknown_top_level_keys_are_rejected(self) -> None:
        """The operator's own file, so a typo is a mistake worth failing on."""
        with pytest.raises(ValidationError, match="unknown key"):
            parse_mapping_file(b"ruels: []\n")

    def test_unknown_rule_keys_are_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unknown key"):
            parse_mapping_file(b"rules:\n  - id: a\n    sources: [x]\n    feilds: [y]\n")

    def test_a_rule_with_no_sources_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="sources"):
            parse_mapping_file(b"rules:\n  - id: a\n    name: n\n")

    def test_a_rule_with_no_identity_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="id or a name"):
            parse_mapping_file(b"rules:\n  - sources: [x]\n")

    def test_a_bad_query_language_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="query_language"):
            parse_mapping_file(b"rules:\n  - id: a\n    sources: [x]\n    query_language: sqlish\n")

    def test_a_bad_level_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="level"):
            parse_mapping_file(b"rules:\n  - id: a\n    sources: [x]\n    level: urgent\n")

    def test_a_non_boolean_enabled_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="true or false"):
            parse_mapping_file(b"rules:\n  - id: a\n    sources: [x]\n    enabled: yes-please\n")

    def test_duplicate_identities_are_rejected(self) -> None:
        text = b"rules:\n  - id: a\n    sources: [x]\n  - id: a\n    sources: [y]\n"
        with pytest.raises(ValidationError, match="share the identity"):
            parse_mapping_file(text)

    def test_invalid_yaml_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="not valid YAML"):
            parse_mapping_file(b"rules: [unclosed\n")

    def test_a_non_mapping_root_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="mapping at the top level"):
            parse_mapping_file(b"- a\n- b\n")

    def test_the_rule_count_is_bounded(self) -> None:
        text = "rules:\n" + "".join(f"  - id: r{i}\n    sources: [x]\n" for i in range(10))
        with pytest.raises(ValidationError, match="above the limit"):
            parse_mapping_file(text.encode(), max_rules=5)

    def test_disabled_rules_are_carried_through(self) -> None:
        (rule,) = parse_mapping_file(b"rules:\n  - id: a\n    sources: [x]\n    enabled: false\n")
        assert not rule.enabled

    def test_operator_aliases_apply(self) -> None:
        from logcoverage.validation import normalize_key

        aliases = {normalize_key("net_prod_03"): "network/zeek_conn"}
        (rule,) = parse_mapping_file(b"rules:\n  - id: a\n    sources: [net_prod_03]\n", aliases=aliases)
        assert rule.sources == ("network/zeek_conn",)
