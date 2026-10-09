from app.services.agent import evaluate, extract_config, parse_expected


def test_extract_config():
    reply = "Here you go:\n```logstash\nfilter {\n  grok {}\n}\n```\nDone."
    assert extract_config(reply) == "filter {\n  grok {}\n}"
    assert extract_config("no code") is None


def test_parse_expected_variants():
    assert parse_expected('{"a": 1}') == [{"a": 1}]
    assert parse_expected('[{"a": 1}, {"a": 2}]') == [{"a": 1}, {"a": 2}]
    assert parse_expected('{"a": 1}\n{"a": 2}') == [{"a": 1}, {"a": 2}]
    assert parse_expected("  ") is None


def test_evaluate_detects_failures_and_diffs():
    result = {
        "ok": True,
        "events": [{"client": {"ip": "1.2.3.4"}, "tags": ["_grokparsefailure"]}, {"client": {"ip": "5.6.7.8"}}],
        "errors": [],
    }
    issues = evaluate(result, [{"client": {"ip": "1.2.3.4"}}, {"client": {"ip": "*"}, "status": 200}], True)
    assert any("_grokparsefailure" in i for i in issues)
    assert any("event[1] status" in i for i in issues)
    assert not any("event[1] client.ip" in i for i in issues)


def test_evaluate_success():
    result = {"ok": True, "events": [{"status": 200}], "errors": []}
    assert evaluate(result, [{"status": 200}], True) == []


def test_config_errors_short_circuit():
    result = {"ok": False, "config_errors": ["line 1: filter plugin `ruby` is not allowed"]}
    assert evaluate(result, None, True) == ["Configuration rejected: line 1: filter plugin `ruby` is not allowed"]


def test_model_discovery_parsers():
    from app.services.llm import parse_ollama_tags, parse_openai_models

    qwen_details = {"parameter_size": "14.8B", "quantization_level": "Q4_K_M"}
    ollama = {
        "models": [
            {"name": "qwen2.5-coder:14b", "size": 9_000_000_000, "details": qwen_details},
            {"name": "llama3.1:8b", "size": 4_900_000_000, "details": {"parameter_size": "8.0B"}},
        ]
    }
    parsed = parse_ollama_tags(ollama)
    assert [m["id"] for m in parsed] == ["llama3.1:8b", "qwen2.5-coder:14b"]
    assert parsed[1]["label"] == "qwen2.5-coder:14b (14.8B, Q4_K_M, 9.0 Go)"
    openai = {"data": [{"id": i} for i in ("gpt-5", "text-embedding-3-large", "whisper-1", "gpt-5-mini", "tts-1")]}
    assert [m["id"] for m in parse_openai_models(openai)] == ["gpt-5", "gpt-5-mini"]
