"""Isolated Logstash runner.

Runs on an internal-only network (no egress), as an unprivileged user, with a read-only root
filesystem. It accepts a user configuration, keeps only its `filter` sections (input/output
are blanked and replaced by a controlled stdin → JSON-lines file harness), enforces a filter
plugin allowlist, and executes an ephemeral Logstash process with a hard timeout.

Standard library only: the attack surface stays minimal.
"""

import hmac
import json
import logging
import os
import re
import shutil
import signal
import subprocess  # nosec B404 # fixed argv, no shell
import tempfile
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import syslog_check

LOGSTASH_HOME = Path(os.environ.get("LOGSTASH_HOME", "/usr/share/logstash"))
SETTINGS_TEMPLATE = Path(os.environ.get("RUNNER_SETTINGS_DIR", "/opt/ls-settings"))
TOKEN_FILE = Path(os.environ.get("RUNNER_TOKEN_FILE", "/run/lsx-secrets/runner/runner_token"))
PORT = int(os.environ.get("RUNNER_PORT", "8700"))
CONCURRENCY = int(os.environ.get("RUNNER_CONCURRENCY", "2"))
MAX_TIMEOUT = int(os.environ.get("RUNNER_MAX_TIMEOUT", "300"))
MAX_BODY = 8 * 1024 * 1024
MAX_EVENTS = 10_000
MAX_OUTPUT_BYTES = 20 * 1024 * 1024
JAVA_OPTS = os.environ.get("RUNNER_JAVA_OPTS", "-Xms256m -Xmx768m -XX:+UseSerialGC -XX:TieredStopAtLevel=1")

ALLOWED_FILTERS = {
    "grok", "dissect", "kv", "csv", "json", "xml", "date", "mutate", "drop", "split", "clone",
    "fingerprint", "geoip", "useragent", "cidr", "urldecode", "de_dot", "prune", "truncate", "uuid",
    "syslog_pri", "translate", "aggregate", "throttle", "metrics", "json_encode", "bytes", "age",
}  # fmt: skip
# Options that make a plugin read or write files inside the sandbox.
FORBIDDEN_OPTIONS = re.compile(
    r"\b(patterns_dir|patterns_files_glob|dictionary_path|database|regexes|network_path|"
    r"aggregate_maps_path|path|template|cache_path)\s*=>"
)
KEYWORDS = {"if", "else"}
FIELD_REF_ELEMENT = re.compile(r"\[[^\[\]\n,\"']+\]")
# Input fields simulate what a real input adds to each event (e.g. the file input's [log][file][path]).
INPUT_FIELD_NAME = re.compile(r"^(?:\[[A-Za-z0-9_@.-]{1,64}\]){1,6}$|^[A-Za-z0-9_@.-]{1,64}$")
MAX_INPUT_FIELDS = 20

log = logging.getLogger("runner")
_slots = threading.BoundedSemaphore(CONCURRENCY)
_token = TOKEN_FILE.read_text(encoding="utf-8").strip() if TOKEN_FILE.exists() else ""


class ConfigError(ValueError):
    pass


# ---- Configuration scanner -----------------------------------------------------------------
def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _skip_string(text: str, i: int) -> int:
    quote = text[i]
    i += 1
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == quote:
            return i + 1
        i += 1
    raise ConfigError(f"line {_line_of(text, i)}: unterminated string")


def _mask(text: str) -> str:
    """Return `text` with comments, strings and regex literals replaced by spaces (same length,
    newlines kept) so structure can be analysed safely."""
    out = list(text)
    i, n = 0, len(text)
    last_sig = ""
    while i < n:
        c = text[i]
        if c == "[":
            # Field reference element such as `[#text]` (EVTX JSON): its "#" does not start a comment.
            m = FIELD_REF_ELEMENT.match(text, i)
            if m:
                i, last_sig = m.end(), "]"
                continue
        if c == "#":
            j = text.find("\n", i)
            j = n if j == -1 else j
            out[i:j] = " " * (j - i)
            i = j
            continue
        if c in "\"'":
            j = _skip_string(text, i)
            out[i + 1 : j - 1] = [ch if ch == "\n" else " " for ch in text[i + 1 : j - 1]]
            i, last_sig = j, '"'
            continue
        if c == "/" and last_sig in ("=~", "!~"):
            j = i + 1
            while j < n and text[j] != "/":
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                raise ConfigError(f"line {_line_of(text, i)}: unterminated regex")
            out[i + 1 : j] = " " * (j - i - 1)
            i, last_sig = j + 1, "/"
            continue
        if not c.isspace():
            last_sig = text[i - 1 : i + 1] if c == "~" and i > 0 else c
        i += 1
    return "".join(out)


def _matching_brace(masked: str, open_pos: int) -> int:
    depth = 0
    for i in range(open_pos, len(masked)):
        if masked[i] == "{":
            depth += 1
        elif masked[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    raise ConfigError(f"line {_line_of(masked, open_pos)}: unbalanced braces")


SECTION = re.compile(r"\s*(input|filter|output)\s*\{")
PLUGIN_OPEN = re.compile(r"([A-Za-z_][\w-]*)\s*\{")
# syslog output options that are replaced by the capture harness (TLS material = file paths).
SYSLOG_REDIRECTED = re.compile(r"\b(host|port|protocol|reconnect_interval|ssl_[a-z_]+)\s*=>\s*")
SYSLOG_LITERAL_OPTS = ("facility", "severity", "rfc", "use_labels", "sourcehost", "priority")


def _plugins(masked: str, start: int, end: int):
    """Yield (name, name_pos, open_brace, close_brace) for plugin blocks in masked[start:end].
    Descends into if/else blocks; skips hash values (`key => { … }`) and nested codec blocks."""
    pos = start
    while True:
        m = PLUGIN_OPEN.search(masked, pos, end)
        if not m:
            return
        brace = m.end() - 1
        if masked[start : m.start()].rstrip().endswith("=>"):
            pos = _matching_brace(masked, brace) + 1  # hash value or codec => plugin { … }
            continue
        if m.group(1) in KEYWORDS:
            pos = brace + 1  # conditional branch: look inside
            continue
        close = _matching_brace(masked, brace)
        yield m.group(1), m.start(), brace, close
        pos = close + 1


def _blank(result: list[str], source: str, a: int, b: int) -> None:
    """Replace source[a:b] by spaces, keeping newlines (Logstash line numbers stay aligned)."""
    result[a:b] = ["\n" if ch == "\n" else " " for ch in source[a:b]]


def _value_end(masked: str, i: int) -> int:
    """End index (exclusive) of the option value starting at i in masked text."""
    c = masked[i]
    if c in "\"'":
        return masked.index(c, i + 1) + 1  # string contents are masked: next quote closes it
    if c == "[":
        depth = 0
        for j in range(i, len(masked)):
            depth += masked[j] == "["
            depth -= masked[j] == "]"
            if depth == 0:
                return j + 1
    if c == "{":
        return _matching_brace(masked, i) + 1
    m = re.match(r"[^\s}]+", masked[i:])
    return i + (m.end() if m else 1)


def _literal_options(config: str, masked: str, a: int, b: int) -> dict[str, str]:
    out = {}
    for m in re.finditer(r"\b(" + "|".join(SYSLOG_LITERAL_OPTS) + r")\s*=>\s*", masked[a:b]):
        v0 = a + m.end()
        out[m.group(1)] = config[v0 : _value_end(masked, v0)].strip("\"'")
    return out


def prepare_config(
    config: str, syslog_tcp_port: int = 0, syslog_udp_port: int = 0
) -> tuple[str, list[str], list[str], list[dict]]:
    """Return (sanitised config, plugins used, warnings, syslog outputs). Raises ConfigError.

    - filter sections: allowlisted plugins only, no file-access options;
    - output sections: `syslog` blocks are kept but redirected to the local capture listener,
      every other output plugin is neutralised;
    - input sections: neutralised (the harness injects stdin).
    """
    masked = _mask(config)
    result = list(config)
    plugins: list[str] = []
    warnings: list[str] = []
    syslog_outputs: list[dict] = []
    filters = 0
    pos = 0
    while pos < len(masked):
        if masked[pos:].strip() == "":
            break
        m = SECTION.match(masked, pos)
        if not m:
            line = _line_of(masked, pos + len(masked[pos:]) - len(masked[pos:].lstrip()))
            raise ConfigError(f"line {line}: expected an `input`, `filter` or `output` section")
        start = m.end() - 1
        end = _matching_brace(masked, start)
        name = m.group(1)
        if name == "filter":
            filters += 1
            for plugin, ppos, _, _ in _plugins(masked, start + 1, end):
                if plugin not in ALLOWED_FILTERS:
                    raise ConfigError(f"line {_line_of(masked, ppos)}: filter plugin `{plugin}` is not allowed")
                plugins.append(plugin)
            om = FORBIDDEN_OPTIONS.search(masked, start + 1, end)
            if om:
                raise ConfigError(
                    f"line {_line_of(masked, om.start())}: option `{om.group(1)}` is not allowed "
                    "(file access is disabled in the sandbox)"
                )
        elif name == "output":
            for plugin, ppos, brace, close in _plugins(masked, start + 1, end):
                line = _line_of(masked, ppos)
                if plugin != "syslog":
                    warnings.append(f"line {line}: output `{plugin}` ignored (only `syslog` outputs are captured)")
                    _blank(result, config, ppos, close + 1)
                    continue
                options = _literal_options(config, masked, brace + 1, close)
                protocol = "tcp"
                for om in SYSLOG_REDIRECTED.finditer(masked, brace + 1, close):
                    v_end = _value_end(masked, om.end())
                    if om.group(1) == "protocol":
                        protocol = config[om.end() : v_end].strip("\"'")
                    _blank(result, config, om.start(), v_end)
                if protocol == "ssl-tcp":
                    warnings.append(f"line {line}: syslog over TLS is captured in clear text (same frames, no TLS)")
                transport = "udp" if protocol == "udp" else "tcp"
                port = syslog_udp_port if transport == "udp" else syslog_tcp_port
                result[brace] = f'{{ host => "127.0.0.1" port => {port} protocol => "{transport}" '
                fm = FORBIDDEN_OPTIONS.search(masked, brace + 1, close)
                if fm:
                    raise ConfigError(f"line {line}: option `{fm.group(1)}` is not allowed in the syslog output")
                syslog_outputs.append(
                    {"line": line, "protocol": protocol, "rfc": options.get("rfc", "rfc3164"), "options": options}
                )
                warnings.extend(f"line {line}: {w}" for w in syslog_check.static_warnings(options))
                plugins.append("output:syslog")
        else:
            warnings.append("`input` section ignored: the test harness injects stdin")
            _blank(result, config, m.start(1), end + 1)
        pos = end + 1
    if filters == 0 and not syslog_outputs:
        raise ConfigError("no `filter { ... }` section found")
    prepared = "".join(result)
    if "${" in prepared:
        raise ConfigError("environment/keystore substitution (${...}) is only allowed in redirected syslog options")
    return prepared, sorted(set(plugins)), warnings, syslog_outputs


# ---- Execution -----------------------------------------------------------------------------
ANSI = re.compile(r"\x1b\[[0-9;]*m")
BACKTRACE = re.compile(r",\s*backtrace:\s*\[.*$")


def check_input_fields(fields: object) -> dict[str, str]:
    """Validate the simulated input fields: plain field references and literal values only (no quotes,
    newlines, trailing backslash or %{} interpolation), so they can be embedded in the harness safely."""
    if fields is None:
        return {}
    if not isinstance(fields, dict) or len(fields) > MAX_INPUT_FIELDS:
        raise ConfigError(f"input fields: at most {MAX_INPUT_FIELDS} name/value pairs")
    for name, value in fields.items():
        if not isinstance(name, str) or not INPUT_FIELD_NAME.match(name):
            raise ConfigError(f"input fields: invalid field name {str(name)[:80]!r} (e.g. [log][file][path])")
        if (
            not isinstance(value, str)
            or len(value) > 2048
            or any(c in value for c in '"\r\n')
            or value.endswith("\\")
            or "%{" in value
        ):
            raise ConfigError(f"input fields: invalid value for {name} (no quotes, newlines or %{{}}, max 2048 chars)")
    return fields


def _harness(input_format: str, out_file: Path, fields: dict[str, str] | None = None) -> str:
    codec = "json" if input_format == "json" else 'line { charset => "UTF-8" }'
    add_field = ""
    if fields:
        pairs = " ".join(f'"{name}" => "{value}"' for name, value in fields.items())
        add_field = f" add_field => {{ {pairs} }}"
    return (
        f"\ninput {{ stdin {{ codec => {codec}{add_field} }} }}\n"
        f'output {{ file {{ path => "{out_file}" codec => json_lines }} }}\n'
    )


def _settings_dir(work: Path, ecs: str) -> Path:
    settings = work / "settings"
    settings.mkdir()
    for name in ("jvm.options", "log4j2.properties"):
        shutil.copy(SETTINGS_TEMPLATE / name, settings / name)
    (settings / "logstash.yml").write_text(
        "api.enabled: false\n"
        "pipeline.workers: 1\n"
        "pipeline.ordered: true\n"
        "pipeline.batch.size: 125\n"
        f"pipeline.ecs_compatibility: {ecs}\n"
        "config.reload.automatic: false\n"
        "log.level: warn\n"
    )
    return settings


def run(
    config: str, input_data: str, input_format: str, ecs: str, timeout: int, fields: dict[str, str] | None = None
) -> dict:
    started = time.monotonic()
    capture = syslog_check.SyslogCapture()
    try:
        fields = check_input_fields(fields)
        prepared, plugins, warnings, syslog_outputs = prepare_config(config, capture.tcp_port, capture.udp_port)
    except ConfigError as exc:
        capture.close()
        return {"ok": False, "config_errors": [str(exc)], "events": [], "errors": [], "logs": "",
                "warnings": [], "plugins": [], "syslog": None, "duration_ms": 0}  # fmt: skip

    try:
        result = _execute(prepared, input_data, input_format, ecs, timeout, fields)
    finally:
        frames = capture.close()
    result.update(
        warnings=warnings + result["warnings"],
        plugins=plugins,
        syslog={"outputs": syslog_outputs, "frames": syslog_check.analyse(frames)} if syslog_outputs else None,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return result


def _execute(
    prepared: str, input_data: str, input_format: str, ecs: str, timeout: int, fields: dict[str, str] | None = None
) -> dict:
    with tempfile.TemporaryDirectory(prefix="ls-") as tmp:  # TMPDIR = private tmpfs
        work = Path(tmp)
        out_file = work / "out.jsonl"
        conf_file = work / "pipeline.conf"
        conf_file.write_text(prepared + _harness(input_format, out_file, fields), encoding="utf-8")
        settings = _settings_dir(work, ecs)
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(work),
            "LANG": "C.UTF-8",
            "LS_JAVA_OPTS": f"{JAVA_OPTS} -Djava.io.tmpdir={work}",
        }
        argv = [
            str(LOGSTASH_HOME / "bin" / "logstash"),
            "--path.settings", str(settings),
            "--path.data", str(work / "data"),
            "--path.logs", str(work / "logs"),
            "-f", str(conf_file),
        ]  # fmt: skip
        proc = subprocess.Popen(  # noqa: S603 # nosec B603
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=work,
            start_new_session=True,
        )
        timed_out = False
        if input_data and not input_data.endswith("\n"):
            input_data += "\n"  # the line codec only emits newline-terminated lines
        try:
            logs_raw, _ = proc.communicate(input_data.encode("utf-8"), timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(proc.pid, signal.SIGKILL)
            logs_raw, _ = proc.communicate()

        logs = ANSI.sub("", logs_raw.decode("utf-8", errors="replace"))
        events = []
        if out_file.exists():
            with out_file.open("rb") as fh:
                for raw in fh.read(MAX_OUTPUT_BYTES).splitlines():
                    if len(events) >= MAX_EVENTS:
                        break
                    try:
                        events.append(json.loads(raw))
                    except ValueError:
                        continue  # truncated last line (output size cap or killed run)

    errors = [
        BACKTRACE.sub("}", ln.strip()).replace("\\n", "\n").replace('\\"', '"')
        for ln in logs.splitlines()
        if re.search(r"\[(ERROR|FATAL)\s*\]", ln)
    ]
    log_warnings = [ln.strip() for ln in logs.splitlines() if re.search(r"\[WARN\s*\]", ln)]
    if timed_out:
        errors.insert(0, f"Logstash timed out after {timeout}s and was killed")
    return {
        "ok": proc.returncode == 0 and not timed_out and not errors,
        "exit_code": proc.returncode,
        "events": events,
        "errors": errors[:50],
        "warnings": log_warnings[:50],
        "config_errors": [],
        "logs": logs[-200_000:],
    }


# ---- HTTP interface ------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "lsx-runner"
    sys_version = ""

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:  # route access logs to our logger
        log.debug("%s %s", self.address_string(), fmt % args)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send(200, {"status": "ok", "logstash": (LOGSTASH_HOME / "bin" / "logstash").exists()})
        else:
            self._send(404, {"detail": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/run":
            return self._send(404, {"detail": "not found"})
        supplied = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if not _token or not hmac.compare_digest(supplied.encode(), _token.encode()):
            return self._send(HTTPStatus.UNAUTHORIZED, {"detail": "unauthorized"})
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            return self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"detail": "invalid body size"})
        try:
            req = json.loads(self.rfile.read(length))
            config = str(req["config"])
            input_data = str(req.get("input", ""))
            input_format = req.get("input_format", "lines")
            ecs = req.get("ecs_compatibility", "disabled")
            timeout = min(int(req.get("timeout", 120)), MAX_TIMEOUT)
            fields = req.get("fields")
            if input_format not in ("lines", "json") or ecs not in ("disabled", "v1", "v8"):
                raise ValueError
        except ValueError, KeyError, TypeError:
            return self._send(HTTPStatus.BAD_REQUEST, {"detail": "invalid request"})
        if not _slots.acquire(timeout=120):
            return self._send(HTTPStatus.TOO_MANY_REQUESTS, {"detail": "busy"})
        try:
            result = run(config, input_data, input_format, ecs, timeout, fields)
        except Exception:  # noqa: BLE001
            log.exception("run failed")
            return self._send(500, {"detail": "runner failure"})
        finally:
            _slots.release()
        log.info("run ok=%s events=%d duration_ms=%d", result["ok"], len(result["events"]), result["duration_ms"])
        self._send(200, result)


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("RUNNER_LOG_LEVEL", "INFO"),
        format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
    )
    if not _token:
        raise SystemExit(f"runner token missing at {TOKEN_FILE}")
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)  # noqa: S104 # nosec B104 # internal network only
    log.info("runner listening on :%d (concurrency=%d)", PORT, CONCURRENCY)
    server.serve_forever()


if __name__ == "__main__":
    main()
