"""Autonomous configuration agent.

Loop: generate filter → run Logstash in the isolated runner → evaluate deterministically
(Logstash errors, *failure tags, expected-output diff) → if no expected output is given, ask the
model to judge the output against the instructions → feed issues back → repeat until validated
or the iteration budget is exhausted. Progress is streamed as events.
"""

import json
import re
from collections import Counter
from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.parsers import detect as detect_format
from app.parsers import get as get_parser
from app.services.llm import LLMError, chat, load_llm_config
from app.services.runner_client import RunnerError, run_pipeline
from app.services.settings_store import get_setting

ALLOWED_PLUGINS = (
    "grok, dissect, kv, csv, json, xml, date, mutate, drop, split, clone, fingerprint, geoip, useragent, "
    "cidr, urldecode, de_dot, prune, truncate, uuid, syslog_pri, translate (inline dictionary only), "
    "aggregate, throttle, metrics"
)

SYSTEM_PROMPT = """You are a senior Logstash engineer acting as an autonomous configuration agent.
Write the Logstash FILTER section that transforms the provided sample logs according to the user's instructions.

Hard rules:
- Reply with exactly ONE fenced code block tagged `logstash` containing `filter {{ ... }}`.
  A short explanation may precede it.
- Do NOT write input or output sections: they are injected by the test harness
  (input = stdin with codec `{codec}`, output = JSON lines). Each input line is one event in `message`{json_hint}.
- Allowed filter plugins only: {plugins}.
- Forbidden: ruby, exec, any network/database plugin, ${{ENV}} references,
  file paths (patterns_dir, dictionary_path...).
- Tag parsing failures explicitly when relevant and keep the configuration idiomatic and readable.
- ECS compatibility mode of the pipeline: `{ecs}`.
"""

FAILURE_TAG = re.compile(r"^_.*(failure|error)", re.IGNORECASE)
OUTPUT_OPEN = re.compile(r"output\s*\{")
CODE_BLOCK = re.compile(r"```(?:logstash|conf|ruby)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)


def _trim(text: str, limit: int, tail: bool = False) -> str:
    if len(text) <= limit:
        return text
    return ("…" + text[-limit:]) if tail else (text[:limit] + "…")


def extract_config(reply: str) -> str | None:
    blocks = CODE_BLOCK.findall(reply)
    for block in blocks:
        if "filter" in block:
            return block.strip()
    stripped = reply.strip()
    return stripped if stripped.startswith("filter") else None


def parse_expected(raw: str | None) -> list[dict] | None:
    if not raw or not raw.strip():
        return None
    raw = raw.strip()
    try:
        value = json.loads(raw)
        return value if isinstance(value, list) else [value]
    except json.JSONDecodeError:
        return [json.loads(line) for line in raw.splitlines() if line.strip()]


def _diff(expected: Any, actual: Any, path: str, out: list[str]) -> None:
    if len(out) >= 15:
        return
    if expected == "*":  # wildcard: field must exist
        if actual is None:
            out.append(f"{path}: missing (expected present)")
        return
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            out.append(f"{path}: expected object, got {json.dumps(actual)[:120]}")
            return
        for key, val in expected.items():
            _diff(val, actual.get(key), f"{path}.{key}" if path else key, out)
        return
    if expected != actual:
        out.append(f"{path}: expected {json.dumps(expected)[:120]}, got {json.dumps(actual)[:120]}")


def evaluate(result: dict[str, Any], expected: list[dict] | None, has_input: bool) -> list[str]:
    issues: list[str] = []
    if result.get("config_errors"):
        issues.extend(f"Configuration rejected: {e}" for e in result["config_errors"])
        return issues
    if not result.get("ok"):
        issues.append(f"Logstash failed (exit code {result.get('exit_code')}).")
    issues.extend(f"Logstash error: {line}" for line in result.get("errors", [])[:8])
    events = result.get("events", [])
    if has_input and not events and expected != []:
        issues.append("No event was produced.")
    tags = Counter(t for e in events for t in (e.get("tags") or []) if isinstance(t, str) and FAILURE_TAG.match(t))
    for tag, count in tags.items():
        issues.append(f"{count}/{len(events)} events tagged `{tag}`.")
    if expected is not None:
        if len(expected) != len(events):
            issues.append(f"Expected {len(expected)} events, got {len(events)}.")
        diffs: list[str] = []
        for i, (exp, act) in enumerate(zip(expected, events, strict=False)):
            before = len(diffs)
            _diff(exp, act, "", diffs)
            diffs[before:] = [f"event[{i}] {d}" for d in diffs[before:]]
        issues.extend(diffs)
    syslog = result.get("syslog")
    if syslog:
        frames = syslog.get("frames", [])
        if events and not frames:
            issues.append("The syslog output emitted no frame.")
        frame_errors = list(dict.fromkeys(e for f in frames for e in f.get("errors", [])))
        issues.extend(f"Syslog frame: {e} (fix the fields used by the fixed syslog output)" for e in frame_errors[:5])
    return issues


def split_output_sections(config: str) -> str:
    """Return the `output { … }` sections of a configuration (strings/comments aware), verbatim."""
    out, i, n = [], 0, len(config)
    while i < n:
        c = config[i]
        if c == "#":
            j = config.find("\n", i)
            i = n if j == -1 else j
            continue
        if c in "\"'":
            j = i + 1
            while j < n and config[j] != c:
                j += 2 if config[j] == "\\" else 1
            i = j + 1
            continue
        boundary = i == 0 or not (config[i - 1].isalnum() or config[i - 1] == "_")
        m = OUTPUT_OPEN.match(config, i) if boundary else None
        if m:
            depth, j, quote = 0, m.end() - 1, None
            while j < n:
                ch = config[j]
                if quote:
                    if ch == "\\":
                        j += 1
                    elif ch == quote:
                        quote = None
                elif ch in "\"'":
                    quote = ch
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            out.append(config[i : j + 1])
            i = j + 1
            continue
        i += 1
    return "\n\n".join(out)


def with_outputs(config: str, outputs: str) -> str:
    if not outputs or split_output_sections(config):
        return config
    return f"{config.rstrip()}\n\n{outputs}\n"


def _feedback(result: dict[str, Any], issues: list[str]) -> str:
    sample = json.dumps(result.get("events", [])[:3], indent=2, ensure_ascii=False)
    return (
        "The test run did not validate. Issues:\n- "
        + "\n- ".join(issues)
        + f"\n\nFirst output events:\n```json\n{_trim(sample, 5000)}\n```"
        + f"\n\nLogstash log tail:\n```\n{_trim(result.get('logs', ''), 3000, tail=True)}\n```"
        + "\nFix the filter and reply with the full corrected `filter { ... }` block."
    )


async def _judge(cfg, instructions: str, result: dict[str, Any]) -> list[str]:
    sample = json.dumps(result.get("events", [])[:5], indent=2, ensure_ascii=False)
    reply = await chat(
        cfg,
        [
            {
                "role": "system",
                "content": "You verify Logstash outputs. Answer ONLY with JSON: "
                '{"satisfied": true|false, "issues": ["..."]}. Be strict but do not invent requirements.',
            },
            {
                "role": "user",
                "content": f"Instructions:\n{instructions}\n\nOutput events:\n```json\n{_trim(sample, 8000)}\n```",
            },
        ],
    )
    match = re.search(r"\{.*\}", reply, re.DOTALL)
    try:
        verdict = json.loads(match.group(0)) if match else {}
    except json.JSONDecodeError:
        return []  # unparseable verdict: rely on deterministic checks only
    if verdict.get("satisfied", True):
        return []
    return [f"Reviewer: {i}" for i in verdict.get("issues", [])][:8] or [
        "Reviewer: output does not match instructions."
    ]


def _result_summary(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": result.get("ok"),
        "events": result.get("events", [])[:200],
        "event_count": len(result.get("events", [])),
        "errors": result.get("errors", []),
        "config_errors": result.get("config_errors", []),
        "logs": _trim(result.get("logs", ""), 20000, tail=True),
        "duration_ms": result.get("duration_ms"),
        "syslog": result.get("syslog"),
    }


async def run_agent(
    db: AsyncSession,
    *,
    logs: str,
    input_format: str,
    instructions: str,
    expected_raw: str | None,
    initial_config: str | None,
    max_iterations: int,
    input_fields: dict[str, str] | None = None,
) -> AsyncIterator[dict[str, Any]]:
    cfg = await load_llm_config(db)
    ai = await get_setting(db, "ai")
    ecs = ai["ecs_compatibility"]
    try:
        expected = parse_expected(expected_raw)
    except json.JSONDecodeError:
        yield {"type": "error", "message": "Expected output is not valid JSON / JSON lines."}
        return

    json_hint = (
        " (JSON input is decoded: fields are already at the root of the event)" if input_format == "json" else ""
    )
    system = SYSTEM_PROMPT.format(
        codec="json" if input_format == "json" else "line", json_hint=json_hint, plugins=ALLOWED_PLUGINS, ecs=ecs
    )
    task = f"Instructions:\n{instructions}\n\nSample logs:\n```\n{_trim(logs, 6000)}\n```"
    if input_fields:
        listed = "\n".join(f"- {name} = {value}" for name, value in input_fields.items())
        task += (
            "\n\nThe input also sets these fields on every event (e.g. the source file path); "
            f"use them when the instructions need values they contain:\n{listed}"
        )
    if not (initial_config and initial_config.strip()):
        match = next(iter(detect_format(logs, input_format, limit=1)), None)
        if match and match["score"] >= 0.8:
            parser = get_parser(match["id"])
            yield {"type": "status", "n": 0, "message": f"Sample recognised as {parser.name}: suggested to the model"}
            task += (
                f'\n\nThe sample matches the library parser "{parser.name}". You may start from it and adapt it '
                f"to the instructions:\n```logstash\n{_trim(parser.filter, 6000)}\n```"
            )
    if expected is not None:
        task += (
            '\n\nExpected output events (subset match, "*" = any value):\n'
            f"```json\n{_trim(expected_raw or '', 4000)}\n```"
        )
    messages = [{"role": "system", "content": system}, {"role": "user", "content": task}]

    config = initial_config.strip() if initial_config and initial_config.strip() else None
    # The user's output sections (e.g. the production syslog output) are fixed: re-attached to
    # every proposal so the real output format is verified at each iteration.
    outputs = split_output_sections(config or "")
    if outputs:
        messages[0]["content"] += (
            "\nThe user's `output` sections (shown below) are fixed and re-attached automatically; never "
            f"modify them, only produce the filter.\n```logstash\n{_trim(outputs, 4000)}\n```\n"
        )
    if config:
        messages.append({"role": "assistant", "content": f"```logstash\n{config}\n```"})

    for n in range(1, max_iterations + 1):
        yield {"type": "iteration", "n": n}
        try:
            if not (n == 1 and config):
                yield {"type": "status", "n": n, "message": f"Asking {cfg.provider}/{cfg.model}…"}
                reply = await chat(cfg, messages)
                messages.append({"role": "assistant", "content": reply})
                config = extract_config(reply)
                if config:
                    config = with_outputs(config, outputs)
                if not config:
                    messages.append({"role": "user", "content": "No `filter { }` code block found. Reply with one."})
                    yield {"type": "evaluation", "n": n, "issues": ["Model reply had no filter code block."]}
                    continue
            yield {"type": "config", "n": n, "config": config}
            yield {"type": "status", "n": n, "message": "Running Logstash…"}
            result = await run_pipeline(config, logs, input_format, ecs, input_fields)
            yield {"type": "result", "n": n, **_result_summary(result)}
            issues = evaluate(result, expected, bool(logs.strip()))
            if not issues and expected is None:
                yield {"type": "status", "n": n, "message": "Reviewing output against instructions…"}
                issues = await _judge(cfg, instructions, result)
        except (LLMError, RunnerError) as exc:
            yield {"type": "error", "message": str(exc)}
            yield {"type": "done", "success": False, "iterations": n, "config": config}
            return
        yield {"type": "evaluation", "n": n, "issues": issues}
        if not issues:
            yield {"type": "done", "success": True, "iterations": n, "config": config}
            return
        messages.append({"role": "user", "content": _feedback(result, issues)})

    yield {"type": "done", "success": False, "iterations": max_iterations, "config": config}
