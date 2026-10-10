#!/usr/bin/env python3
"""Run every library parser on its sample in a real Logstash runner and check the result.

For each parser and each ECS compatibility mode (disabled, v8):
- the configuration is accepted and Logstash reports no error;
- one event per sample line (or `expected_events` from parser.toml), none tagged `_*failure` / `_*error`;
- every field declared in `fields` is produced by at least one event, and never as an array.

Usage (runner started with a known token, e.g. `docker run -p 127.0.0.1:8701:8700 …`):
    LSX_RUNNER_URL=http://127.0.0.1:8701 LSX_RUNNER_TOKEN=… python scripts/check-parsers.py [parser_id …]
"""

import json
import os
import re
import sys
import tomllib
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.parsers import LIBRARY, all_parsers  # noqa: E402

URL = os.environ.get("LSX_RUNNER_URL", "http://127.0.0.1:8701").rstrip("/")
TOKEN = os.environ.get("LSX_RUNNER_TOKEN", "")
FAILURE_TAG = re.compile(r"^_.*(failure|error)", re.IGNORECASE)


def run(config: str, data: str, fmt: str, ecs: str) -> dict:
    body = {"config": config, "input": data, "input_format": fmt, "ecs_compatibility": ecs, "timeout": 120}
    req = urllib.request.Request(  # noqa: S310 - local runner URL from the operator
        f"{URL}/run",
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=300) as resp:  # noqa: S310
        return json.loads(resp.read())


def lookup(event: dict, path: str):
    if path in event:
        return event[path]
    node = event
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def check(parser, ecs: str) -> list[str]:
    meta = tomllib.loads((LIBRARY / parser.category / parser.id / "parser.toml").read_text(encoding="utf-8"))
    res = run(parser.filter, parser.sample, parser.input_format, ecs)
    problems = [f"config: {e}" for e in res.get("config_errors", [])]
    problems += [f"logstash: {e[-300:]}" for e in res.get("errors", [])]
    events = res.get("events", [])
    lines = [line for line in parser.sample.splitlines() if line.strip()]
    expected = meta.get("expected_events", len(lines))
    if len(events) != expected:
        problems.append(f"{len(events)} events, expected {expected}")
    for i, event in enumerate(events):
        tags = [t for t in event.get("tags", []) if FAILURE_TAG.match(str(t))]
        if tags:
            problems.append(f"event {i + 1}: tags {tags}")
    for field in parser.fields:
        values = [lookup(e, field) for e in events]
        if not any(v not in (None, "", [], {}) for v in values):
            problems.append(f"field `{field}` never produced")
        # An array usually means a capture appended to a pre-filled field (`tags` is an array by design).
        if field != "tags" and any(isinstance(v, list) for v in values):
            problems.append(f"field `{field}` is an array in some events")
    return problems


def main() -> int:
    wanted = set(sys.argv[1:])
    parsers = [p for p in all_parsers() if not wanted or p.id in wanted]
    jobs = [(p, ecs) for p in parsers for ecs in ("disabled", "v8")]
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda job: (job, check(*job)), jobs))
    failed = 0
    for (parser, ecs), problems in results:
        status = "ok" if not problems else "FAIL"
        print(f"{status:4} {parser.category:10} {parser.id:28} ecs={ecs}")
        for p in problems[:12]:
            print(f"       - {p}")
        failed += bool(problems)
    print(f"\n{len(results) - failed}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
