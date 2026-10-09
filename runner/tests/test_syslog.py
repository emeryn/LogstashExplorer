import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import ConfigError, prepare_config  # noqa: E402
from syslog_check import analyse_frame, static_warnings  # noqa: E402

PROD = """filter { mutate { add_field => { "x" => "y" } } }
output {
  if [type] == "audit" {
    syslog {
      host => "${SYSLOG_HOST}"
      port => 6514
      protocol => "ssl-tcp"
      ssl_certificate_authorities => ["/etc/pki/ca.pem"]
      rfc => "rfc5424"
      facility => "local0"
      severity => "informational"
      appname => "lsx"
      codec => plain { format => "%{message}" }
    }
  }
  elasticsearch { hosts => ["https://es:9200"] }
}
"""


def test_syslog_output_redirected_and_other_outputs_neutralised():
    out, plugins, warnings, outputs = prepare_config(PROD, 40001, 40002)
    assert out.count("\n") == PROD.count("\n")
    assert 'host => "127.0.0.1" port => 40001 protocol => "tcp"' in out
    assert "SYSLOG_HOST" not in out and "6514" not in out and "ssl-tcp" not in out and "/etc/pki" not in out
    assert "elasticsearch" not in out
    assert 'codec => plain { format => "%{message}" }' in out  # nested codec kept, not seen as a plugin
    assert "output:syslog" in plugins
    assert outputs == [{"line": 4, "protocol": "ssl-tcp", "rfc": "rfc5424",
                        "options": {"rfc": "rfc5424", "facility": "local0", "severity": "informational"}}]  # fmt: skip
    joined = " ".join(warnings)
    assert "elasticsearch" in joined and "TLS" in joined and "local0" in joined


def test_udp_protocol_goes_to_udp_listener():
    out, *_ = prepare_config('output { syslog { protocol => "udp" port => 514 host => "h" } }', 1, 2)
    assert 'port => 2 protocol => "udp"' in out


def test_env_reference_outside_redirected_options_rejected():
    with pytest.raises(ConfigError):
        prepare_config('output { syslog { host => "h" port => 1 appname => "${APP}" } }', 1, 2)


def test_static_warnings():
    w = " ".join(static_warnings({"facility": "local0", "severity": "informational", "rfc": "rfc5424"}))
    assert "encodes it as 14" in w and 'priority => "134"' in w
    assert "falls back" in " ".join(static_warnings({"facility": "auth", "rfc": "rfc5424"}))
    assert static_warnings({"facility": "daemon", "severity": "error", "rfc": "rfc5424"}) == []


def test_rfc5424_frame_decoding():
    raw = b'<134>1 2026-10-07T10:15:32.000+02:00 web01 lsx 42 ACCESS [lsx@32473 ip="1.2.3.4"] GET /index\n'
    a = analyse_frame({"transport": "tcp", "raw": raw})
    assert a["format"] == "rfc5424" and not a["errors"]
    f = a["fields"]
    assert (f["facility"], f["severity"], f["hostname"], f["msgid"]) == ("local0", "info", "web01", "ACCESS")
    assert f["structured_data"] == [{"id": "lsx@32473", "params": {"ip": "1.2.3.4"}}]
    assert f["msg"] == "GET /index"


def test_rfc5424_frame_errors():
    raw = b'<14>1 2026-10-07T10:15:32.000Z {"hostname":"x"} my app - - - hello\n'
    a = analyse_frame({"transport": "tcp", "raw": raw})
    assert any("HOSTNAME" in e for e in a["errors"])


def test_rfc3164_frame_decoding():
    a = analyse_frame({"transport": "udp", "raw": b"<13>Oct 07 10:15:32 web01 LOGSTASH[-]: hello world\n"})
    assert a["format"] == "rfc3164"
    assert a["fields"]["app_name"] == "LOGSTASH" and a["fields"]["msg"] == "hello world"
    assert any("zero-padded" in w for w in a["warnings"]) and any("app[-]" in w for w in a["warnings"])
