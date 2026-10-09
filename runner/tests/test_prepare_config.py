import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import ConfigError, prepare_config  # noqa: E402


def test_filter_kept_and_io_blanked_with_same_line_count():
    conf = (
        "input { beats { port => 5044 } }\n"
        'filter {\n  grok { match => { "message" => "%{IP:ip}" } }\n}\n'
        "output { stdout {} }\n"
    )
    out, plugins, warnings, _ = prepare_config(conf)
    assert out.count("\n") == conf.count("\n")
    assert "beats" not in out and "stdout" not in out
    assert plugins == ["grok"]
    assert len(warnings) == 2


def test_conditionals_strings_comments_and_regex_are_ignored():
    conf = """filter {
  # ruby { code => "x" }  <- comment
  if [msg] =~ /\\{ruby \\{/ {
    mutate { add_field => { "x" => "exec { }" } }
  } else if "a" in [tags] {
    drop {}
  } else {
    date { match => ["ts", "ISO8601"] }
  }
}"""
    _, plugins, _, _ = prepare_config(conf)
    assert plugins == ["date", "drop", "mutate"]


@pytest.mark.parametrize(
    "conf,needle",
    [
        ('filter { ruby { code => "system(1)" } }', "ruby"),
        ("filter { if [a] { exec { command => 'id' } } }", "exec"),
        ('filter { grok { patterns_dir => ["/run"] } }', "patterns_dir"),
        ('filter { mutate { add_field => { "t" => "${RUNNER_TOKEN}" } } }', "${"),
        ("filter { grok { }", "unbalanced"),
        ("grok { }", "expected an"),
        ("output { stdout {} }", "no `filter"),
    ],
)
def test_rejections(conf, needle):
    with pytest.raises(ConfigError) as exc:
        prepare_config(conf)
    assert needle in str(exc.value)
