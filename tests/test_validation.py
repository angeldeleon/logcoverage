"""The trust boundary: sanitisation, normalisation and the address guard."""

from __future__ import annotations

import ipaddress

import pytest

from logcoverage.validation import (
    REDACTED,
    ValidationError,
    assert_http_url,
    assert_public_http_url,
    is_public_address,
    normalize_field,
    normalize_key,
    safe_text,
    scrub_evidence,
    validate_env_var_name,
)


class TestSafeText:
    def test_control_characters_become_spaces(self) -> None:
        assert safe_text("Sysmon\nrule") == "Sysmon rule"

    def test_tabs_and_nulls_go(self) -> None:
        assert safe_text("a\tb\x00c") == "a b c"

    def test_whitespace_is_collapsed(self) -> None:
        assert safe_text("  a    b  ") == "a b"

    def test_bidi_override_is_dropped(self) -> None:
        """The Trojan Source trick: a name that renders as something else."""
        assert "‮" not in safe_text("rule‮nimda")

    def test_zero_width_characters_are_dropped(self) -> None:
        assert safe_text("sys​mon") == "sysmon"

    def test_soft_hyphen_is_dropped(self) -> None:
        assert safe_text("wind­ows") == "windows"

    def test_lone_surrogates_are_replaced(self) -> None:
        cleaned = safe_text("rule\ud800name")
        cleaned.encode("utf-8")  # must not raise
        assert "\ud800" not in cleaned

    def test_length_is_capped_with_an_ellipsis(self) -> None:
        assert safe_text("x" * 500, limit=32) == "x" * 31 + "…"

    def test_non_strings_are_accepted(self) -> None:
        assert safe_text(4625) == "4625"
        assert safe_text(None) == "None"

    def test_ordinary_text_is_unchanged(self) -> None:
        assert safe_text("WinEventLog:Security") == "WinEventLog:Security"


class TestNormalizeKey:
    def test_case_and_punctuation_fold(self) -> None:
        assert normalize_key("Windows/Security") == normalize_key("windows security")
        assert normalize_key("AWS::CloudTrail") == normalize_key("aws cloud trail")

    def test_camel_case_is_split(self) -> None:
        assert normalize_key("SigninLogs") == "signin logs"

    def test_underscores_read_as_separators(self) -> None:
        assert normalize_key("aws_cloud_trail") == "aws cloud trail"

    def test_a_non_latin_name_does_not_collapse_to_empty(self) -> None:
        """The failure this guards: an empty key is skipped everywhere, so a
        one-character rename would buy total invisibility."""
        assert normalize_key("журнал") != ""

    def test_a_punctuation_only_name_survives(self) -> None:
        assert normalize_key("!!!") != ""

    def test_fullwidth_spelling_normalises_the_same(self) -> None:
        assert normalize_key("ＳＹＳＭＯＮ") == normalize_key("sysmon")

    def test_empty_input_is_empty(self) -> None:
        assert normalize_key("") == ""
        assert normalize_key("   ") == ""

    def test_none_is_the_empty_key_not_the_string_none(self) -> None:
        """An exported row with a null name must not become a source called "none",
        joining against every other null row in the file."""
        assert normalize_key(None) == ""


class TestNormalizeField:
    def test_sigma_modifiers_are_stripped(self) -> None:
        assert normalize_field("Image|endswith") == normalize_field("Image")

    def test_chained_modifiers_are_stripped(self) -> None:
        assert normalize_field("CommandLine|contains|all") == normalize_field("commandline")

    def test_separator_spellings_agree(self) -> None:
        """EventCode, event_code and eventcode are one field.

        The third is the one a space-folding normaliser gets wrong, and the one a
        SIEM is most likely to report.
        """
        assert normalize_field("EventCode") == normalize_field("event_code") == normalize_field("eventcode")

    def test_dotted_names_fold(self) -> None:
        assert normalize_field("id.orig_h") == normalize_field("idOrigH")

    def test_the_matching_form_has_no_spaces(self) -> None:
        assert " " not in normalize_field("Original File Name")


class TestScrubEvidence:
    def test_secret_shaped_keys_lose_their_value(self) -> None:
        scrubbed = scrub_evidence({"sessionKey": "abc123", "index": "wineventlog"})
        assert scrubbed["sessionKey"] == REDACTED
        assert scrubbed["index"] == "wineventlog"

    @pytest.mark.parametrize(
        "key",
        ["token", "api_key", "password", "authorization", "cookie", "clientSecret", "private_key"],
    )
    def test_every_credential_shape_is_caught(self, key: str) -> None:
        assert scrub_evidence({key: "value"})[key] == REDACTED

    def test_the_key_name_is_kept(self) -> None:
        """ "There is a session key in this response" is the fact worth reporting."""
        assert "sessionKey" in scrub_evidence({"sessionKey": "abc"})

    def test_nesting_is_scrubbed(self) -> None:
        scrubbed = scrub_evidence({"outer": {"token": "abc"}})
        assert scrubbed["outer"]["token"] == REDACTED

    def test_depth_is_bounded(self) -> None:
        deep: dict = {"a": {}}
        node = deep["a"]
        for _ in range(20):
            node["a"] = {}
            node = node["a"]
        assert "<truncated>" in str(scrub_evidence(deep))

    def test_keys_are_bounded(self) -> None:
        scrubbed = scrub_evidence({f"k{i}": i for i in range(500)})
        assert "_truncated" in scrubbed
        assert len(scrubbed) <= 41

    def test_lists_are_bounded(self) -> None:
        scrubbed = scrub_evidence(list(range(500)))
        assert len(scrubbed) == 51
        assert "more" in scrubbed[-1]

    def test_numbers_and_booleans_survive(self) -> None:
        assert scrub_evidence({"count": 12, "ok": True, "none": None}) == {
            "count": 12,
            "ok": True,
            "none": None,
        }

    def test_strings_are_sanitised(self) -> None:
        assert scrub_evidence({"name": "a\nb"})["name"] == "a b"


class TestEnvVarNames:
    def test_a_plain_name_is_accepted(self) -> None:
        assert validate_env_var_name("SPLUNK_TOKEN", where="x") == "SPLUNK_TOKEN"

    def test_a_url_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="NAME of an environment variable"):
            validate_env_var_name("https://hooks.example/abc", where="x")

    def test_a_path_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_env_var_name("/etc/secret", where="x")

    def test_an_empty_name_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_env_var_name("", where="x")

    def test_a_name_starting_with_a_digit_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_env_var_name("1TOKEN", where="x")


class TestPublicAddresses:
    @pytest.mark.parametrize(
        "address",
        [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:169.254.169.254",
            "2002:a9fe:a9fe::",
        ],
    )
    def test_non_public_addresses_are_refused(self, address: str) -> None:
        assert not is_public_address(ipaddress.ip_address(address))

    @pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
    def test_public_addresses_are_allowed(self, address: str) -> None:
        assert is_public_address(ipaddress.ip_address(address))


class TestUrlValidation:
    def test_http_is_refused_by_default(self) -> None:
        with pytest.raises(ValidationError, match="scheme"):
            assert_public_http_url("http://example.com/")

    def test_a_non_http_scheme_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            assert_public_http_url("file:///etc/passwd")

    def test_embedded_credentials_are_refused(self) -> None:
        with pytest.raises(ValidationError, match="credentials"):
            assert_public_http_url("https://user:pass@example.com/")

    def test_a_literal_private_address_is_refused_without_dns(self) -> None:
        with pytest.raises(ValidationError, match="non-public"):
            assert_http_url("https://10.0.0.5/", resolve=False)

    def test_the_metadata_address_is_refused_without_dns(self) -> None:
        with pytest.raises(ValidationError):
            assert_http_url("http://169.254.169.254/latest/", require_https=False, resolve=False)

    def test_shape_only_mode_does_not_resolve(self) -> None:
        """`logcoverage validate` has to work offline."""
        assert assert_http_url("https://nonexistent.invalid/x", resolve=False).endswith("/x")

    def test_allow_internal_permits_a_private_search_head(self) -> None:
        assert assert_http_url("https://10.0.0.5:8089", allow_internal=True) == "https://10.0.0.5:8089"

    def test_an_invalid_port_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="port"):
            assert_http_url("https://example.com:99999/", resolve=False)

    def test_an_empty_url_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="empty"):
            assert_http_url("   ")

    def test_a_url_with_no_host_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="no host"):
            assert_http_url("https:///path", resolve=False)
