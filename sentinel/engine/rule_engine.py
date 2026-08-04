"""Rule engine — loads Sigma-style YAML detection rules and matches them
live against the event stream.

Implements architecture.md Section 5.3 ("Rule engine — Sigma-style YAML
rules matched against the live event stream (LOLBin patterns, known attack
chains)") and the rule format shown in plan.md Sections 4-5.

Scope: a deliberately small Sigma subset, enough for Sentinel's rules. It is
NOT a full Sigma implementation. Supported:
- `logsource.category` selects which `event_type` a rule applies to
  (e.g. `process_create`, `image_load`)
- `detection.selection` — a mapping of `field|modifier` -> value(s). The
  supported modifiers are the ones the sample rules use:
  `endswith`, `startswith`, `contains`, `equals` (default if no modifier).
  All keys in a selection are ANDed; a value may be a list (ORed).
- `detection.condition` — a simple boolean expression over named selections,
  e.g. `selection`, `selection and not filter`, `selection1 or selection2`.
- `level` -> signal weight (high/medium/low), per architecture.md the main
  false-positive lever.

Events are the shared-schema `Event`s from the event bus; fields are looked
up from the event (top-level fields first, then `extra`). A match produces a
`Signal` (engine/rule_engine.py feeds `engine/scoring.py`) — the rule engine
never decides a response by itself.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from sentinel.engine.schema import Event
from sentinel.engine.scoring import Signal

logger = logging.getLogger(__name__)

_LEVEL_TO_KIND = {
    "high": "rule_match_high",
    "medium": "rule_match_medium",
    "low": "rule_match_low",
}


class RuleSyntaxError(ValueError):
    pass


def _lookup_field(event: Event, field: str) -> Any:
    """Look up a field on the shared-schema Event. Top-level schema fields
    first, then `extra`. Field names map to schema/extra keys 1:1.

    Special handling: the rule samples use `parent_image` and `image`; the
    schema has `parent_pid`, `image_path`, `command_line`. We accept a few
    common aliases so rules read naturally.
    """
    aliases = {
        "image": ("image_path",),
        "parent_image": ("parent_image", "parent_image_path"),
        "command_line": ("command_line",),
    }
    # Direct top-level schema attribute.
    if hasattr(event, field):
        return getattr(event, field)
    # Aliases that point at schema attributes.
    for alias in aliases.get(field, ()):
        if hasattr(event, alias):
            return getattr(event, alias)
    # extra payload.
    return event.extra.get(field)


def _match_value(actual: Any, expected: Any, modifier: str) -> bool:
    if actual is None:
        return False
    a = str(actual)
    e = str(expected)
    if modifier == "equals":
        return a.lower() == e.lower()
    if modifier == "endswith":
        return a.lower().endswith(e.lower())
    if modifier == "startswith":
        return a.lower().startswith(e.lower())
    if modifier == "contains":
        return e.lower() in a.lower()
    raise RuleSyntaxError(f"unsupported modifier: {modifier!r}")


def _parse_key(key: str) -> tuple[str, str]:
    """Split 'field|modifier' -> (field, modifier). No modifier -> equals."""
    if "|" in key:
        field, modifier = key.split("|", 1)
        return field.strip(), modifier.strip()
    return key.strip(), "equals"


class _Selection:
    """One named detection.selection: a dict of field|modifier -> value(s)."""

    def __init__(self, definition: dict[str, Any]):
        self.criteria: list[tuple[str, str, Any]] = []
        for k, v in (definition or {}).items():
            field, modifier = _parse_key(k)
            self.criteria.append((field, modifier, v))

    def matches(self, event: Event) -> bool:
        # External-hook selections always evaluate False here; their real
        # logic lives in engine/scoring.py (see Rule.__init__).
        if getattr(self, "_always_false", False):
            return False
        # Every criterion is ANDed. A list value is ORed (any value matches).
        for field, modifier, expected in self.criteria:
            actual = _lookup_field(event, field)
            if isinstance(expected, (list, tuple)):
                if not any(_match_value(actual, e, modifier) for e in expected):
                    return False
            else:
                if not _match_value(actual, expected, modifier):
                    return False
        return True


class _Condition:
    """A tiny boolean-expression evaluator over named selections.

    Supports: identifiers, `and`, `or`, `not`, parentheses. This is a safe
    recursive-descent parser (no eval).
    """

    _token_re = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z_][A-Za-z0-9_]*")

    def __init__(self, expression: str, selections: dict[str, _Selection]):
        self._selections = selections
        self._tokens = self._token_re.findall(expression or "selection")
        self._pos = 0

    def _peek(self) -> str | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _next(self) -> str | None:
        tok = self._peek()
        self._pos += 1
        return tok

    def _expect(self, tok: str) -> None:
        if self._next() != tok:
            raise RuleSyntaxError(f"expected {tok!r} in condition")

    def eval(self, event: Event) -> bool:
        self._pos = 0  # reset: a Condition object is reused across many events
        val = self._parse_or(event)
        if self._pos != len(self._tokens):
            raise RuleSyntaxError("trailing tokens in condition")
        return val

    def _parse_or(self, event: Event) -> bool:
        val = self._parse_and(event)
        while self._peek() == "or":
            self._next()
            rhs = self._parse_and(event)
            val = val or rhs
        return val

    def _parse_and(self, event: Event) -> bool:
        val = self._parse_not(event)
        while self._peek() == "and":
            self._next()
            rhs = self._parse_not(event)
            val = val and rhs
        return val

    def _parse_not(self, event: Event) -> bool:
        if self._peek() == "not":
            self._next()
            return not self._parse_not(event)
        return self._parse_atom(event)

    def _parse_atom(self, event: Event) -> bool:
        tok = self._peek()
        if tok == "(":
            self._next()
            val = self._parse_or(event)
            self._expect(")")
            return val
        ident = self._next()
        if ident is None:
            raise RuleSyntaxError("unexpected end of condition")
        sel = self._selections.get(ident)
        if sel is None:
            raise RuleSyntaxError(f"unknown selection name in condition: {ident!r}")
        return sel.matches(event)


class Rule:
    """One parsed Sigma-style rule."""

    def __init__(self, doc: dict[str, Any], source_path: str = "<memory>") -> None:
        self.source_path = source_path
        self.title = doc.get("title", "untitled rule")
        self.id = doc.get("id", "sentinel-unknown")
        self.status = doc.get("status", "experimental")
        self.level = doc.get("level", "low")
        self.description = doc.get("description", "")
        logsource = doc.get("logsource", {})
        self.category = logsource.get("category")
        detection = doc.get("detection", {})
        if "condition" not in detection:
            raise RuleSyntaxError(f"rule {self.id} missing detection.condition")
        # Build named selections from dict-valued detection keys. Non-dict
        # detection keys (e.g. `publisher_allowlist_check: true` in the sample
        # DLL rule) are EXTERNAL HOOKS, not event-field selections: the real
        # logic for them lives in engine/scoring.py per architecture.md
        # Section 5.3. We register them as always-False so a condition like
        # `selection and not publisher_allowlist_check` reduces to `selection`
        # here (the field match), and scoring.py applies the actual hook
        # (allowlist/reputation) on top. We never silently weaken detection.
        self._selections: dict[str, _Selection] = {}
        self.external_hooks: list[str] = []
        for name, defn in detection.items():
            if name == "condition":
                continue
            if isinstance(defn, dict):
                self._selections[name] = _Selection(defn)
            else:
                self.external_hooks.append(name)
                # Register a selection that always evaluates False so the hook
                # name resolves in the condition without firing here.
                self._selections[name] = _Selection({})
                self._selections[name]._always_false = True  # type: ignore[attr-defined]
        self._condition = _Condition(str(detection["condition"]), self._selections)

    @property
    def signal_kind(self) -> str:
        return _LEVEL_TO_KIND.get(str(self.level).lower(), "rule_match_low")

    def applies_to(self, event: Event) -> bool:
        # logsource.category selects the event_type. If the rule has no
        # category, it applies to all events.
        if self.category is None:
            return True
        return event.event_type == self.category

    def match(self, event: Event) -> Signal | None:
        if not self.applies_to(event):
            return None
        try:
            if not self._condition.eval(event):
                return None
        except RuleSyntaxError:
            raise
        except Exception:
            logger.exception("rule %s match error on event %s", self.id, event)
            return None
        subject = self._subject_of(event)
        return Signal(
            kind=self.signal_kind,
            subject=subject,
            engine="rule_engine",
            reason=f"{self.title} [{self.id}] (level={self.level})",
        )

    @staticmethod
    def _subject_of(event: Event) -> str:
        if event.pid is not None:
            return f"pid:{event.pid}"
        if event.image_path:
            return f"path:{event.image_path}"
        return "unknown"


def load_rule_file(path: str | Path) -> list[Rule]:
    """Load rules from a YAML file. Supports a single doc or a list of docs."""
    import yaml

    p = Path(path)
    docs = list(yaml.safe_load_all(p.read_text(encoding="utf-8")))
    rules: list[Rule] = []
    for doc in docs:
        if not doc:
            continue
        if isinstance(doc, list):
            for d in doc:
                if d:
                    rules.append(Rule(d, str(p)))
        else:
            rules.append(Rule(doc, str(p)))
    return rules


class RuleEngine:
    """Loads all rules from a directory and matches events against them."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules or []

    @classmethod
    def from_dir(cls, rules_dir: str | Path) -> "RuleEngine":
        rules: list[Rule] = []
        d = Path(rules_dir)
        if d.exists():
            for f in sorted(d.glob("*.yaml")) + sorted(d.glob("*.yml")):
                try:
                    rules.extend(load_rule_file(f))
                except RuleSyntaxError:
                    logger.exception("skipping invalid rule file: %s", f)
        else:
            logger.warning("rules dir does not exist: %s", d)
        return cls(rules)

    def match(self, event: Event) -> list[Signal]:
        """Return the Signals for all rules that match `event`."""
        out: list[Signal] = []
        for rule in self.rules:
            try:
                sig = rule.match(event)
                if sig is not None:
                    out.append(sig)
            except RuleSyntaxError:
                logger.exception("invalid rule %s skipped during match", rule.id)
        return out

    def __len__(self) -> int:
        return len(self.rules)
