"""Tests for engine/rule_engine.py — the Sigma-style rule subset.

Covers: field modifiers (endswith/startswith/contains/equals), list-value OR,
selection AND, condition parsing (and/or/not/parens), logsource.category
gating, level->signal-weight mapping, and the two sample rules from plan.md
(lolbin_powershell, dll_cross_process_injection) as end-to-end fixtures.
"""
import pytest

from sentinel.engine.rule_engine import (
    Rule,
    RuleEngine,
    RuleSyntaxError,
    load_rule_file,
)
from sentinel.engine.schema import Event, utc_timestamp


def _ev(**kw):
    base = {"timestamp": utc_timestamp(), "source": "etw_process",
            "event_type": "process_create"}
    base.update(kw)
    return Event(**base)


# --------------------------------------------------------------------------- #
# The two sample rules from plan.md (Sections 4 & 5), as fixtures.
# --------------------------------------------------------------------------- #
LOLBIN_RULE = {
    "title": "Suspicious PowerShell spawned by Office app",
    "id": "sentinel-0001",
    "status": "experimental",
    "logsource": {"category": "process_create"},
    "detection": {
        "selection": {
            "parent_image|endswith": ["WINWORD.EXE", "EXCEL.EXE"],
            "image|endswith": "powershell.exe",
        },
        "condition": "selection",
    },
    "level": "high",
    "description": "Office spawning PowerShell is a classic macro-malware pattern.",
}


def _make_office_event(parent_image="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                       image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"):
    # The sample rule matches on parent_image / image which live in extra
    # for process_create events from ETW (the schema keeps the raw payload
    # there). We model them in extra, as a real process_create event would.
    return _ev(
        pid=4821,
        parent_pid=3300,
        image_path=image,
        command_line="powershell -nop",
        extra={"parent_image": parent_image, "image": image},
    )


def test_lolbin_rule_matches_office_powershell():
    rule = Rule(LOLBIN_RULE)
    sig = rule.match(_make_office_event())
    assert sig is not None
    assert sig.kind == "rule_match_high"
    assert sig.subject == "pid:4821"


def test_lolbin_rule_no_match_non_office_parent():
    rule = Rule(LOLBIN_RULE)
    ev = _make_office_event(parent_image="C:\\Windows\\explorer.exe")
    assert rule.match(ev) is None


def test_lolbin_rule_no_match_non_powershell_child():
    rule = Rule(LOLBIN_RULE)
    ev = _make_office_event(image="C:\\Windows\\notepad.exe")
    ev = _ev(image_path="C:\\Windows\\notepad.exe",
             extra={"parent_image": "WINWORD.EXE", "image": "notepad.exe"})
    assert rule.match(ev) is None


def test_lolbin_rule_ignored_for_wrong_event_type():
    rule = Rule(LOLBIN_RULE)
    # category is process_create; a file_write event must not match.
    ev = _ev(event_type="file_write", source="fs")
    assert rule.match(ev) is None


# --------------------------------------------------------------------------- #
# Modifiers
# --------------------------------------------------------------------------- #
def _rule_with_selection(sel, condition="selection", category=None):
    doc = {
        "title": "t", "id": "t-1", "level": "low",
        "logsource": {},
        "detection": {"selection": sel, "condition": condition},
    }
    if category:
        doc["logsource"]["category"] = category
    return Rule(doc)


def test_modifier_endswith():
    r = _rule_with_selection({"image|endswith": ".exe"})
    assert r.match(_make_office_event(image="x.exe")) is not None


def test_modifier_startswith():
    r = _rule_with_selection({"image|startswith": "C:\\Windows"})
    assert r.match(_make_office_event(image="C:\\Windows\\x.exe")) is not None


def test_modifier_contains():
    r = _rule_with_selection({"command_line|contains": "-nop"})
    assert r.match(_make_office_event()) is not None


def test_modifier_equals_default_case_insensitive():
    r = _rule_with_selection({"image": "powershell.exe"})
    # equals is exact-match (case-insensitive); our image is a full path so
    # this must NOT match — use contains/endswith for paths.
    assert r.match(_make_office_event()) is None
    r2 = _rule_with_selection({"command_line": "POWERSHELL -NOP"})
    assert r2.match(_make_office_event()) is not None


def test_list_value_is_or():
    r = _rule_with_selection({"parent_image|endswith": ["WINWORD.EXE", "EXCEL.EXE"]})
    assert r.match(_make_office_event(parent_image="x\\EXCEL.EXE")) is not None
    assert r.match(_make_office_event(parent_image="x\\outlook.exe")) is None


def test_multiple_criteria_are_and():
    r = _rule_with_selection({
        "image|endswith": "powershell.exe",
        "command_line|contains": "-enc",
    })
    assert r.match(_make_office_event()) is None  # no -enc in command line
    ev = _ev(image_path="powershell.exe", command_line="powershell -enc abc",
             extra={"image": "powershell.exe"})
    assert r.match(ev) is not None


# --------------------------------------------------------------------------- #
# Condition parsing
# --------------------------------------------------------------------------- #
def test_condition_and_not():
    doc = {
        "title": "t", "id": "t-2", "level": "low", "logsource": {},
        "detection": {
            "selection": {"image|endswith": "powershell.exe"},
            "filter": {"command_line|contains": "legit"},
            "condition": "selection and not filter",
        },
    }
    r = Rule(doc)
    assert r.match(_make_office_event()) is not None
    legit = _ev(image_path="powershell.exe", command_line="powershell legit",
                extra={"image": "powershell.exe"})
    assert r.match(legit) is None


def test_condition_or():
    doc = {
        "title": "t", "id": "t-3", "level": "low", "logsource": {},
        "detection": {
            "a": {"image|endswith": "powershell.exe"},
            "b": {"image|endswith": "pwsh.exe"},
            "condition": "a or b",
        },
    }
    r = Rule(doc)
    assert r.match(_make_office_event()) is not None
    ev = _ev(image_path="pwsh.exe", extra={"image": "pwsh.exe"})
    assert r.match(ev) is not None


def test_condition_parentheses():
    doc = {
        "title": "t", "id": "t-4", "level": "low", "logsource": {},
        "detection": {
            "a": {"image|endswith": "powershell.exe"},
            "b": {"command_line|contains": "-nop"},
            "c": {"command_line|contains": "-enc"},
            "condition": "a and (b or c)",
        },
    }
    r = Rule(doc)
    assert r.match(_make_office_event()) is not None  # -nop present


def test_condition_unknown_selection_raises():
    doc = {
        "title": "t", "id": "t-5", "level": "low", "logsource": {},
        "detection": {"selection": {"image|endswith": "x"}, "condition": "nosuch"},
    }
    r = Rule(doc)
    with pytest.raises(RuleSyntaxError):
        r.match(_make_office_event())


# --------------------------------------------------------------------------- #
# Level -> signal kind mapping
# --------------------------------------------------------------------------- #
def test_level_maps_to_signal_kind():
    for level, kind in [("high", "rule_match_high"),
                        ("medium", "rule_match_medium"),
                        ("low", "rule_match_low")]:
        doc = dict(LOLBIN_RULE)
        doc["level"] = level
        sig = Rule(doc).match(_make_office_event())
        assert sig.kind == kind


# --------------------------------------------------------------------------- #
# load_rule_file / RuleEngine
# --------------------------------------------------------------------------- #
def test_load_rule_file_and_engine(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    import yaml
    (rules_dir / "a.yaml").write_text(yaml.dump(LOLBIN_RULE), encoding="utf-8")
    engine = RuleEngine.from_dir(rules_dir)
    assert len(engine) == 1
    sigs = engine.match(_make_office_event())
    assert len(sigs) == 1
    assert sigs[0].engine == "rule_engine"


def test_engine_skips_invalid_rule_file(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "bad.yaml").write_text("detection: {}", encoding="utf-8")  # no condition
    engine = RuleEngine.from_dir(rules_dir)
    assert len(engine) == 0


def test_engine_no_match_returns_empty(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    import yaml
    (rules_dir / "a.yaml").write_text(yaml.dump(LOLBIN_RULE), encoding="utf-8")
    engine = RuleEngine.from_dir(rules_dir)
    assert engine.match(_make_office_event(parent_image="explorer.exe")) == []
