"""Library of ready-made Logstash filters for common enterprise log formats.

Each parser is a directory `library/<category>/<id>/` holding:
- `parser.toml`  — name, description, input format, detection regexes and the fields it produces;
- `filter.conf`  — the Logstash `filter { … }` section (only plugins allowed by the runner sandbox);
- `sample.log` (line input) or `sample.jsonl` (JSON lines input) — synthetic, representative events.

`scripts/check-parsers.py` runs every parser on its sample in a real Logstash and checks that the declared
fields are produced without failure tags, in both ECS compatibility modes.
"""

import re
import tomllib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

LIBRARY = Path(__file__).parent / "library"
CATEGORIES = {
    "windows": "Windows",
    "web": "Web & proxy",
    "network": "Network & security",
    "system": "Systems & generic",
    "industrial": "Industrial (OT/ICS)",
}
DETECT_LINES = 200


@dataclass(frozen=True)
class Parser:
    id: str
    name: str
    category: str
    vendor: str
    description: str
    input_format: str  # "lines" | "json"
    detect: tuple[re.Pattern[str], ...]
    fields: tuple[str, ...]
    filter: str
    sample: str
    notes: str = ""
    priority: int = 0  # breaks score ties in detection (specific parsers > generic ones)

    def summary(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "category_label": CATEGORIES[self.category],
            "vendor": self.vendor,
            "description": self.description,
            "input_format": self.input_format,
            "fields": list(self.fields),
        }

    def full(self) -> dict:
        return {**self.summary(), "filter": self.filter, "sample": self.sample, "notes": self.notes}


def _load(directory: Path) -> Parser:
    meta = tomllib.loads((directory / "parser.toml").read_text(encoding="utf-8"))
    category = directory.parent.name
    if category not in CATEGORIES:
        raise ValueError(f"{directory}: unknown category {category!r}")
    fmt = meta.get("input_format", "lines")
    sample_file = directory / ("sample.jsonl" if fmt == "json" else "sample.log")
    return Parser(
        id=directory.name,
        name=meta["name"],
        category=category,
        vendor=meta.get("vendor", ""),
        description=meta["description"].strip(),
        input_format=fmt,
        detect=tuple(re.compile(p) for p in meta["detect"]),
        fields=tuple(meta.get("fields", [])),
        filter=(directory / "filter.conf").read_text(encoding="utf-8"),
        sample=sample_file.read_text(encoding="utf-8").strip("\n"),
        notes=meta.get("notes", "").strip(),
        priority=int(meta.get("priority", 0)),
    )


@lru_cache
def all_parsers() -> tuple[Parser, ...]:
    parsers = [_load(d) for d in sorted(LIBRARY.glob("*/*")) if (d / "parser.toml").is_file()]
    ids = [p.id for p in parsers]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate parser id in the library")
    order = list(CATEGORIES)
    return tuple(sorted(parsers, key=lambda p: (order.index(p.category), p.name.lower())))


def get(parser_id: str) -> Parser | None:
    return next((p for p in all_parsers() if p.id == parser_id), None)


def detect(sample: str, input_format: str | None = None, limit: int = 5) -> list[dict]:
    """Rank parsers by the share of sample lines matching one of their detection regexes."""
    lines = [line for line in sample.splitlines() if line.strip() and not line.startswith("#")][:DETECT_LINES]
    if not lines:
        return []
    looks_json = sum(line.lstrip().startswith("{") for line in lines) > len(lines) / 2
    fmt = input_format or ("json" if looks_json else "lines")
    ranked = []
    for parser in all_parsers():
        if parser.input_format == "json" and fmt != "json" and not looks_json:
            continue
        if parser.input_format == "lines" and input_format == "json":
            continue  # decoded JSON events have no raw `message` for a line parser
        hits = sum(any(rx.search(line) for rx in parser.detect) for line in lines)
        if hits:
            ranked.append(({**parser.summary(), "score": round(hits / len(lines), 3)}, parser.priority))
    ranked.sort(key=lambda r: (-r[0]["score"], -r[1]))
    ranked = [r for r, _ in ranked]
    return ranked[:limit]
