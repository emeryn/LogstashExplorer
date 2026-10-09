"""Native EVTX → JSON lines conversion (Rust `evtx` parser via its Python binding)."""

import io
import json

from evtx import PyEvtxParser

EVTX_MAGIC = b"ElfFile\x00"


def is_evtx(head: bytes) -> bool:
    return head.startswith(EVTX_MAGIC)


def evtx_to_json_lines(data: bytes, max_records: int) -> tuple[str, int, bool]:
    """Return (json_lines, record_count, truncated). Each line is a flat-ish ECS-friendly event."""
    if not is_evtx(data[:8]):
        raise ValueError("not an EVTX file")
    parser = PyEvtxParser(io.BytesIO(data), number_of_threads=1)
    lines: list[str] = []
    truncated = False
    for record in parser.records_json():
        if len(lines) >= max_records:
            truncated = True
            break
        try:
            event = json.loads(record["data"])
        except ValueError, KeyError:
            continue
        event.setdefault("evtx", {})
        if isinstance(event["evtx"], dict):
            event["evtx"]["record_id"] = record.get("event_record_id")
            event["evtx"]["timestamp"] = record.get("timestamp")
        lines.append(json.dumps(event, ensure_ascii=False, separators=(",", ":")))
    return "\n".join(lines), len(lines), truncated
