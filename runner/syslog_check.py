"""Syslog output verification.

The user's real `output { syslog { … } }` block is executed by Logstash, but host/port/protocol are
redirected to a local capture listener. Every frame actually written on the wire is recorded, then
decoded the way rsyslog would see it (pri, facility, severity, timereported, hostname, app-name,
procid, msgid, structured-data, msg) and checked against RFC 5424 / RFC 3164 and rsyslog limits.
"""

import re
import socket
import threading
from datetime import datetime

# Labels accepted by logstash-output-syslog 3.1.0, in the plugin's own order: the plugin uses the
# list INDEX as facility code — which diverges from RFC 5424 numbering after "clock".
PLUGIN_FACILITIES = [
    "kernel", "user-level", "mail", "daemon", "security/authorization", "syslogd", "line printer",
    "network news", "uucp", "clock", "ftp", "ntp", "log audit", "log alert",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
]  # fmt: skip
RFC_FACILITY_CODE = {
    "kernel": 0, "user-level": 1, "mail": 2, "daemon": 3, "security/authorization": 4, "syslogd": 5,
    "line printer": 6, "network news": 7, "uucp": 8, "clock": 9, "ftp": 11, "ntp": 12,
    "log audit": 13, "log alert": 14, **{f"local{i}": 16 + i for i in range(8)},
}  # fmt: skip
SEVERITIES = ["emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug"]
# rsyslog facility names (syslogfacility-text) by RFC code
RSYSLOG_FACILITY = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv",
    "ftp", "ntp", "audit", "alert", "clock", *[f"local{i}" for i in range(8)],
]  # fmt: skip
RSYSLOG_SEVERITY = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]

RSYSLOG_MAX_MESSAGE = 8096  # rsyslog default maxMessageSize (8k)
MAX_CAPTURE = 5 * 1024 * 1024

RFC5424 = re.compile(r"^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (.*)$", re.DOTALL)
RFC3164 = re.compile(
    r"^<(\d{1,3})>([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (\S+) ([^\s\[:]+)(?:\[([^\]]*)\])?: ?(.*)$", re.DOTALL
)
PRINTUSASCII = re.compile(r"^[\x21-\x7e]+$")


# ---- Capture --------------------------------------------------------------------------------
class SyslogCapture:
    """TCP + UDP listeners on 127.0.0.1 recording every frame in arrival order."""

    def __init__(self) -> None:
        self.frames: list[dict] = []
        self._lock = threading.Lock()
        self._size = 0
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(("127.0.0.1", 0))
        self.tcp.listen(8)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self._stop = threading.Event()
        self._threads = [
            threading.Thread(target=self._accept_loop, daemon=True),
            threading.Thread(target=self._udp_loop, daemon=True),
        ]
        for t in self._threads:
            t.start()

    @property
    def tcp_port(self) -> int:
        return self.tcp.getsockname()[1]

    @property
    def udp_port(self) -> int:
        return self.udp.getsockname()[1]

    def _add(self, transport: str, raw: bytes) -> None:
        with self._lock:
            if self._size + len(raw) > MAX_CAPTURE:
                return
            self._size += len(raw)
            self.frames.append({"transport": transport, "raw": raw})

    def _accept_loop(self) -> None:
        self.tcp.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self.tcp.accept()
            except OSError:
                continue
            threading.Thread(target=self._tcp_conn, args=(conn,), daemon=True).start()

    def _tcp_conn(self, conn: socket.socket) -> None:
        buf = b""
        conn.settimeout(0.5)
        with conn:
            while not self._stop.is_set():
                try:
                    chunk = conn.recv(65536)
                except TimeoutError:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                # logstash-output-syslog uses non-transparent framing: one frame per LF.
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    self._add("tcp", line + b"\n")
        if buf:
            self._add("tcp", buf)

    def _udp_loop(self) -> None:
        self.udp.settimeout(0.2)
        while not self._stop.is_set():
            try:
                data, _ = self.udp.recvfrom(65535)
            except OSError:
                continue
            self._add("udp", data)

    def close(self) -> list[dict]:
        threading.Event().wait(0.3)  # let in-flight frames arrive
        self._stop.set()
        for s in (self.tcp, self.udp):
            try:
                s.close()
            except OSError:
                pass
        for t in self._threads:
            t.join(timeout=1)
        return list(self.frames)


# ---- Static checks on the syslog output block --------------------------------------------------
def static_warnings(options: dict[str, str]) -> list[str]:
    """`options` holds literal (unquoted) option values of one syslog output block."""
    out: list[str] = []
    use_labels = options.get("use_labels", "true").lower() != "false"
    if use_labels:
        fac = options.get("facility")
        if fac is not None and "%{" not in fac:
            if fac not in PLUGIN_FACILITIES:
                out.append(f'facility "{fac}" is not a label known by the plugin: it silently falls back to '
                           f'"user-level" (1). Valid labels: {", ".join(PLUGIN_FACILITIES)}.')  # fmt: skip
            elif PLUGIN_FACILITIES.index(fac) != RFC_FACILITY_CODE[fac]:
                plugin_code, rfc_code = PLUGIN_FACILITIES.index(fac), RFC_FACILITY_CODE[fac]
                sev = options.get("severity", "notice")
                sev_code = SEVERITIES.index(sev) if sev in SEVERITIES else 5
                out.append(
                    f'facility "{fac}": logstash-output-syslog encodes it as {plugin_code} '
                    f"({RSYSLOG_FACILITY[plugin_code]}) instead of the RFC 5424 value {rfc_code} "
                    f"({RSYSLOG_FACILITY[rfc_code]}). rsyslog will see facility {RSYSLOG_FACILITY[plugin_code]}. "
                    f'Workaround: use_labels => false and priority => "{rfc_code * 8 + sev_code}".'
                )
        sev = options.get("severity")
        if sev is not None and "%{" not in sev and sev not in SEVERITIES:
            out.append(f'severity "{sev}" is not a known label: it silently falls back to "notice" (5). '
                       f"Valid labels: {', '.join(SEVERITIES)}.")  # fmt: skip
    if options.get("rfc", "rfc3164") == "rfc3164" and "sourcehost" not in options:
        out.append('sourcehost defaults to "%{host}": with ECS enabled [host] is an object; '
                   'prefer sourcehost => "%{[host][hostname]}".')  # fmt: skip
    return out


# ---- Frame decoding & validation -------------------------------------------------------------
def _parse_sd(sd: str) -> tuple[list[dict], str, list[str]]:
    """Parse RFC 5424 STRUCTURED-DATA at the start of `sd`. Returns (elements, rest, errors)."""
    if sd.startswith("-"):
        return [], sd[1:], []
    elements, errors, i = [], [], 0
    while i < len(sd) and sd[i] == "[":
        j = i + 1
        m = re.match(r"([^\s=\]\"]+)", sd[j:])
        if not m:
            return elements, sd[i:], ["malformed SD-ELEMENT (missing SD-ID)"]
        sd_id = m.group(1)
        if len(sd_id) > 32:
            errors.append(f"SD-ID '{sd_id}' longer than 32 characters")
        if "@" not in sd_id and sd_id not in ("timeQuality", "origin", "meta"):
            errors.append(f"SD-ID '{sd_id}' is not IANA-registered: use name@<private enterprise number>")
        j += len(sd_id)
        params: dict[str, str] = {}
        while j < len(sd) and sd[j] == " ":
            pm = re.match(r' ([^\s=\]"]+)="', sd[j:])
            if not pm:
                return elements, sd[i:], [f"malformed SD-PARAM in [{sd_id}]"]
            j += len(pm.group(0))
            val = []
            while j < len(sd) and sd[j] != '"':
                if sd[j] == "\\" and j + 1 < len(sd):
                    if sd[j + 1] not in '"\\]':
                        errors.append(f"invalid escape '\\{sd[j + 1]}' in [{sd_id}]")
                    val.append(sd[j + 1])
                    j += 2
                    continue
                if sd[j] == "]":
                    errors.append(f"unescaped ']' in value of {pm.group(1)} in [{sd_id}]")
                val.append(sd[j])
                j += 1
            if j >= len(sd):
                return elements, "", [f"unterminated SD-PARAM value in [{sd_id}]"]
            params[pm.group(1)] = "".join(val)
            j += 1
        if j >= len(sd) or sd[j] != "]":
            return elements, sd[i:], [f"SD-ELEMENT [{sd_id}] not closed by ']'"]
        elements.append({"id": sd_id, "params": params})
        i = j + 1
    if not elements:
        return [], sd, ["STRUCTURED-DATA must be '-' or start with '['"]
    return elements, sd[i:], errors


def _field_check(name: str, value: str, max_len: int, issues: list[str]) -> None:
    if value == "-":
        return
    if "%{" in value or "{" in value or '"' in value:
        issues.append(f"{name} '{value[:60]}' looks like an unresolved or object field reference")
    if not PRINTUSASCII.match(value):
        issues.append(f"{name} must be printable US-ASCII without spaces")
    if len(value) > max_len:
        issues.append(f"{name} longer than {max_len} characters ({len(value)})")


def analyse_frame(frame: dict) -> dict:
    raw: bytes = frame["raw"]
    text = raw.decode("utf-8", errors="replace")
    body = text[:-1] if text.endswith("\n") else text
    errors: list[str] = []
    warnings: list[str] = []
    fields: dict[str, object] = {}

    if len(raw) > RSYSLOG_MAX_MESSAGE:
        warnings.append(f"{len(raw)} bytes: rsyslog truncates above maxMessageSize ({RSYSLOG_MAX_MESSAGE} by default)")
    if "\r" in body or "\n" in body:
        errors.append("raw line break inside the message: the receiver will split it into several records")

    m = RFC5424.match(body)
    if m:
        fmt = "rfc5424"
        pri, ts, host, app, procid, msgid, rest = m.groups()
        elements, msg, sd_errors = _parse_sd(rest)
        errors.extend(sd_errors)
        if sd_errors and '\\"' in rest:
            errors.append(
                "SD contains literal backslashes: Logstash config strings do not process escapes by default; "
                "write structured_data => '[id@123 key=\"%{field}\"]' with single quotes"
            )
        if msg.startswith(" "):
            msg = msg[1:]
        elif msg:
            errors.append("missing space between STRUCTURED-DATA and MSG")
        try:
            datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            errors.append(f"TIMESTAMP '{ts}' is not RFC 3339")
        _field_check("HOSTNAME", host, 255, errors)
        _field_check("APP-NAME", app, 48, errors)
        _field_check("PROCID", procid, 128, errors)
        _field_check("MSGID", msgid, 32, errors)
        fields.update(timereported=ts, hostname=host, app_name=app, procid=procid, msgid=msgid,
                      structured_data=elements or "-", msg=msg)  # fmt: skip
    else:
        m = RFC3164.match(body)
        if m:
            fmt = "rfc3164"
            pri, ts, host, tag, procid, msg = m.groups()
            if re.match(r"[A-Z][a-z]{2} 0\d", ts):
                warnings.append("day is zero-padded ('Oct 07'): RFC 3164 uses a space ('Oct  7'); rsyslog accepts both")
            warnings.append(
                "RFC 3164 timestamp has no year nor time zone: Logstash always writes it in UTC, rsyslog reads it "
                "in its own local time zone — events are shifted if the rsyslog host is not in UTC"
            )
            if procid == "-":
                warnings.append("procid is '-': the tag becomes 'app[-]:' (set procid or leave it meaningful)")
            if len(tag) > 32:
                warnings.append(f"TAG '{tag}' longer than 32 characters (RFC 3164 limit)")
            _field_check("HOSTNAME", host, 255, errors)
            fields.update(timereported=ts, hostname=host, app_name=tag, procid=procid, msgid="-",
                          structured_data="-", msg=msg)  # fmt: skip
        else:
            fmt = "unknown"
            pm = re.match(r"^<(\d{1,3})>", body)
            pri = pm.group(1) if pm else None
            errors.append("frame matches neither RFC 5424 nor RFC 3164 header syntax")
            fields["msg"] = body

    if pri is not None:
        p = int(pri)
        if p > 191:
            errors.append(f"PRI {p} out of range (0-191)")
        else:
            fields.update(pri=p, facility=RSYSLOG_FACILITY[p // 8], facility_code=p // 8,
                          severity=RSYSLOG_SEVERITY[p % 8], severity_code=p % 8)  # fmt: skip
    if "msg" in fields and not str(fields["msg"]).strip():
        warnings.append("empty MSG")
    if "\\n" in str(fields.get("msg", "")):
        warnings.append("multi-line source message: line breaks were escaped as literal '\\n' by the plugin")

    return {
        "transport": frame["transport"],
        "format": fmt,
        "raw": text,
        "bytes": len(raw),
        "fields": fields,
        "errors": errors,
        "warnings": warnings,
    }


def analyse(frames: list[dict]) -> list[dict]:
    return [analyse_frame(f) for f in frames]
