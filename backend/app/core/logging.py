"""Centralised logging.

- JSON lines on stdout (collected by the container runtime).
- Optional RFC 5424 forwarding to a remote syslog server configured from the admin interface
  (see app.core.syslog).
- PII masking filter (emails, phone numbers, IBAN, card numbers, FR NIR), toggled at runtime
  from the admin interface (privacy by design — RGPD/CNIL).
"""

import json
import logging
import re
from datetime import UTC, datetime

LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

_PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[EMAIL]"),
    (re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,3})?\b"), "[IBAN]"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "[CARD]"),
    (re.compile(r"\b[12]\s?\d{2}\s?\d{2}\s?(?:\d{2}|2A|2B)\s?\d{3}\s?\d{3}(?:\s?\d{2})?\b"), "[NIR]"),
    (re.compile(r"(?:\+|00)\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,5}"), "[PHONE]"),
    (re.compile(r"\b0[1-9](?:[\s.-]?\d{2}){4}\b"), "[PHONE]"),
]


class _MaskingState:
    enabled: bool = True


masking_state = _MaskingState()


def mask_pii(text: str) -> str:
    for pattern, repl in _PII_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def _mask_value(value: object) -> object:
    if isinstance(value, str):
        return mask_pii(value)
    if isinstance(value, dict):
        return {k: _mask_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_value(v) for v in value]
    return value


class PiiMaskingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if masking_state.enabled:
            record.msg = mask_pii(record.getMessage())
            record.args = None
            ctx = getattr(record, "ctx", None)
            if ctx:
                record.ctx = _mask_value(ctx)
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        ctx = getattr(record, "ctx", None)
        if ctx:
            payload["ctx"] = ctx
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


def setup_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    stdout = logging.StreamHandler()
    stdout.setFormatter(JsonFormatter())
    stdout.addFilter(PiiMaskingFilter())
    root.addHandler(stdout)

    for noisy in ("uvicorn.access", "httpx", "apscheduler"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def set_level(level: str) -> None:
    if level in LEVELS:
        logging.getLogger().setLevel(level)
