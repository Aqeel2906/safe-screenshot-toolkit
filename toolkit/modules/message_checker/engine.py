"""Message Checker analysis engine.

Pure functions with no Flask imports, so they can be unit-tested directly and
reused by the Screenshot Text Reader (Module 3) and the Combined Workspace (Module 6).
"""
import re
from dataclasses import asdict, dataclass, field

from .normalise import de_leet, normalise
from .rules import CATEGORIES, COMBOS, Category

MAX_INPUT_LENGTH = 10_000      # guards against huge or pathological input
MAX_HITS_PER_CATEGORY = 10
REPEAT_BONUS = 3               # per extra matched phrase in the same category
REPEAT_CAP = 9

SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}
NEGATION_BEFORE = re.compile(r"(?:\bnever|\bnot|n'?t|\bdont)\s+$")

_COMPILED = {c.id: [re.compile(p, re.IGNORECASE) for p in c.patterns] for c in CATEGORIES}


@dataclass
class Match:
    start: int
    end: int
    text: str


@dataclass
class Finding:
    id: str
    label: str
    severity: str
    explain: str
    advice: str
    points: int
    matches: list[Match] = field(default_factory=list)


@dataclass
class Report:
    score: int
    level: str  # none | low | medium | high
    findings: list[Finding]
    combos: list[dict]
    truncated: bool

    def to_dict(self) -> dict:
        return asdict(self)


def analyse_message(text: str | None) -> Report:
    """Analyse a message for common scam tactics."""
    raw = text if isinstance(text, str) else ""
    truncated = len(raw) > MAX_INPUT_LENGTH
    original = raw[:MAX_INPUT_LENGTH]

    norm, index_map = normalise(original)
    leet = de_leet(norm)

    findings: list[Finding] = []
    for cat in CATEGORIES:
        if cat.suppressed_by and any(f.id == cat.suppressed_by for f in findings):
            continue
        hits = _collect_matches(cat, norm, leet, index_map, original)
        if not hits:
            continue
        extra = min((len(hits) - 1) * REPEAT_BONUS, REPEAT_CAP)
        findings.append(Finding(
            id=cat.id, label=cat.label, severity=cat.severity, explain=cat.explain,
            advice=cat.advice, points=cat.weight + extra, matches=hits,
        ))

    found = {f.id for f in findings}
    combos = [{"reason": c.reason, "bonus": c.bonus} for c in COMBOS if all(i in found for i in c.ids)]
    score = min(100, sum(f.points for f in findings) + sum(c["bonus"] for c in combos))
    return Report(score=score, level=_level_for(score, findings), findings=findings,
                  combos=combos, truncated=truncated)


def _level_for(score: int, findings: list[Finding]) -> str:
    if not findings:
        return "none"
    if score >= 50:
        return "high"
    # A high-severity tactic on its own is never just "low".
    if score >= 25 or any(f.severity == "high" for f in findings):
        return "medium"
    return "low"


def _collect_matches(cat: Category, norm: str, leet: str, index_map: list[int], original: str) -> list[Match]:
    sources = (norm, leet) if cat.leet else (norm,)
    spans: list[tuple[int, int]] = []
    for pattern in _COMPILED[cat.id]:
        for src in sources:
            for m in pattern.finditer(src):
                if m.end() == m.start():
                    continue
                if cat.skip_if_negated and NEGATION_BEFORE.search(src[max(0, m.start() - 12):m.start()]):
                    continue
                spans.append((m.start(), m.end()))
                if len(spans) > MAX_HITS_PER_CATEGORY * 4:
                    break

    matches = []
    for s, e in merge_spans(spans)[:MAX_HITS_PER_CATEGORY]:
        start, end = index_map[s], index_map[e - 1] + 1  # map back to the original text
        matches.append(Match(start, end, original[start:end]))
    return matches


def merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Sort and merge overlapping [start, end) spans."""
    out: list[list[int]] = []
    for s, e in sorted(spans, key=lambda x: (x[0], -x[1])):
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return [(s, e) for s, e in out]


def highlight_segments(text: str, report: Report) -> list[dict]:
    """Split text into plain and highlighted segments for the template.

    Returns [{"text": ..., "severity": None | "high" | ..., "label": ...}, ...].
    Overlapping matches merge and keep the most severe tag. The template renders
    each segment as escaped text, so user input can never become HTML.
    """
    text = text[:MAX_INPUT_LENGTH]
    ranges = []
    for f in report.findings:
        for m in f.matches:
            ranges.append({"start": m.start, "end": m.end, "severity": f.severity, "label": f.label})
    ranges.sort(key=lambda r: (r["start"], -SEVERITY_RANK[r["severity"]]))

    merged: list[dict] = []
    for r in ranges:
        if merged and r["start"] < merged[-1]["end"]:
            last = merged[-1]
            last["end"] = max(last["end"], r["end"])
            if SEVERITY_RANK[r["severity"]] > SEVERITY_RANK[last["severity"]]:
                last["severity"], last["label"] = r["severity"], r["label"]
        else:
            merged.append(dict(r))

    segments, pos = [], 0
    for r in merged:
        if r["start"] > pos:
            segments.append({"text": text[pos:r["start"]], "severity": None, "label": None})
        segments.append({"text": text[r["start"]:r["end"]], "severity": r["severity"], "label": r["label"]})
        pos = r["end"]
    if pos < len(text):
        segments.append({"text": text[pos:], "severity": None, "label": None})
    return segments
