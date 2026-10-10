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


def test_hash_inside_field_reference_is_not_a_comment():
    conf = 'filter {\n  if [Event][System][EventID][#text] {\n    mutate { add_tag => ["x"] }\n  }\n}\n'
    prepared, plugins, _, _ = prepare_config(conf)
    assert plugins == ["mutate"] and "[#text]" in prepared


def test_input_fields_are_injected_in_the_harness():
    from runner import _harness, check_input_fields

    path = "/var/log/apache2/srv-web01/access.log"
    fields = check_input_fields({"[log][file][path]": path, "env": r"C:\logs\app"})
    harness = _harness("lines", Path("/tmp/out.jsonl"), fields)
    assert f'add_field => {{ "[log][file][path]" => "{path}" "env" => "C:\\logs\\app" }}' in harness


@pytest.mark.parametrize(
    "fields",
    [
        {"[log][file][path]": 'a" } } output { exec { command => "id'},
        {"a b": "x"},
        {"x": "line1\nline2"},
        {"x": "ends with backslash\\"},
        {"x": "%{[@metadata][secret]}"},
        {f"f{i}": "v" for i in range(21)},
        ["not", "a", "dict"],
    ],
)
def test_input_fields_rejections(fields):
    from runner import check_input_fields

    with pytest.raises(ConfigError):
        check_input_fields(fields)
