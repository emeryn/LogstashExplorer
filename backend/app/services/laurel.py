"""Raw auditd → LAUREL JSON lines (https://github.com/threathunters-io/laurel), run as a subprocess.

LAUREL groups the records of each audit event (SYSCALL, EXECVE, PATH, PROCTITLE…) into one JSON object
and decodes hex-encoded strings. It is normally an auditd plugin that also enriches events from the
live host (/proc, user database, containers); here the file comes from another machine, so every
host-dependent enrichment is switched off and only the in-stream transformation is kept.
"""

import json
import os
import re
import shutil
import subprocess  # nosec B404 # fixed binary, no shell, input on stdin
import tempfile

from app.core.config import get_settings

RAW_RECORD = re.compile(r"^(?:node=\S+ )?type=[A-Z_]+ msg=audit\(\d+\.\d+:\d+\): ?", re.M)
TIMEOUT_S = 60

# Same transformation as a production LAUREL, minus everything read from the converting host.
CONFIG = """\
directory = "{directory}"
input = "stdin"
statusreport-period = 0

[auditlog]
file = "-"

[state]
file = ""

[transform]
execve-argv = ["array", "string"]

[translate]
universal = true
user-db = false
drop-raw = false

[enrich]
pid = false
spawned-by = false
execve-env = []
container = false
systemd = false
script = false
user-groups = false

[filter]
filter-null-keys = false
filter-action = "drop"
"""


class LaurelError(RuntimeError):
    pass


def available() -> bool:
    return bool(shutil.which(get_settings().laurel_bin))


def looks_like_raw_auditd(text: str) -> bool:
    return RAW_RECORD.search(text[:65536]) is not None


def _clean(event: dict) -> dict:
    # user-groups=false does not stop LAUREL from resolving the uid against the local group
    # database, which describes this container, not the audited host.
    syscall = event.get("SYSCALL")
    if isinstance(syscall, dict):
        syscall.pop("UID_GROUPS", None)
    return event


def to_json_lines(text: str, max_events: int) -> tuple[str, int, bool, int]:
    """Return (json_lines, event_count, truncated, unparsed_lines)."""
    binary = shutil.which(get_settings().laurel_bin)
    if not binary:
        raise LaurelError("LAUREL is not installed on this server")
    data = text.replace("\r\n", "\n").replace("\r", "\n")
    if not data.endswith("\n"):
        data += "\n"
    with tempfile.TemporaryDirectory(prefix="laurel-") as work:
        config = os.path.join(work, "config.toml")
        # LAUREL refuses a world-writable configuration file.
        fd = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(CONFIG.format(directory=work))
        try:
            proc = subprocess.run(  # noqa: S603 # nosec B603 # fixed argv, no shell
                [binary, "--config", config],
                input=data.encode("utf-8", "surrogateescape"),
                capture_output=True,
                timeout=TIMEOUT_S,
                cwd=work,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise LaurelError(f"LAUREL did not finish within {TIMEOUT_S} s") from exc
    if proc.returncode != 0:
        raise LaurelError(f"LAUREL exited with status {proc.returncode}")
    out = proc.stdout.decode("utf-8", "replace")
    diagnostics = out + proc.stderr.decode("utf-8", "replace")
    lines: list[str] = []
    truncated = False
    # LAUREL's own diagnostics may be printed on stdout too: keep only the JSON objects.
    for raw in out.splitlines():
        if not raw.startswith("{"):
            continue
        try:
            event = json.loads(raw)
        except ValueError:
            continue
        if len(lines) >= max_events:
            truncated = True
            break
        lines.append(json.dumps(_clean(event), ensure_ascii=False, separators=(",", ":")))
    return "\n".join(lines), len(lines), truncated, diagnostics.count("cannot parse")
