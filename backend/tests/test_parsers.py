import types

import pytest
from fastapi import HTTPException

from app import parsers
from app.core import input_fields
from app.core.deps import get_principal_partial


def test_library_loads_with_every_category():
    library = parsers.all_parsers()
    assert len(library) >= 25
    assert {p.category for p in library} == set(parsers.CATEGORIES)
    for p in library:
        assert p.filter.lstrip().startswith("filter {"), p.id
        assert p.sample and p.fields and p.detect, p.id
        assert p.input_format in ("lines", "json"), p.id


@pytest.mark.parametrize("parser", parsers.all_parsers(), ids=lambda p: p.id)
def test_each_parser_is_detected_first_on_its_own_sample(parser):
    for fmt in (parser.input_format, None):
        assert parsers.detect(parser.sample, fmt)[0]["id"] == parser.id


def test_detection_ignores_unrelated_text_and_line_parsers_for_json_input():
    assert parsers.detect("hello world\nnothing to see") == []
    evtx = parsers.get("windows-security").sample
    ids = [m["id"] for m in parsers.detect(evtx, "json")]
    assert "json-lines" not in ids and ids[0] == "windows-security"


def test_parser_details():
    p = parsers.get("cisco-asa")
    assert p.full()["category_label"] == "Network & security"
    assert parsers.get("does-not-exist") is None


@pytest.mark.parametrize(
    "fields",
    [{"[log][file][path]": "/var/log/apache2/srv-web01/access.log"}, {"env": r"C:\logs\app"}, None, {}],
)
def test_input_fields_accepted(fields):
    assert input_fields.check(fields) == (fields or None)


@pytest.mark.parametrize(
    "fields",
    [
        {"[log][file][path]": 'x" } } output { exec { command => "id'},
        {"a b": "x"},
        {"x": "two\nlines"},
        {"x": "trailing\\"},
        {"x": "%{[@metadata][secret]}"},
        {f"f{i}": "v" for i in range(21)},
    ],
)
def test_input_fields_rejected(fields):
    with pytest.raises(ValueError):
        input_fields.check(fields)


class _Req:
    def __init__(self, method: str, path: str):
        self.method = method
        self.url = types.SimpleNamespace(path=path)


@pytest.mark.parametrize(
    ("method", "path", "allowed"),
    [
        ("GET", "/api/pipelines", True),
        ("POST", "/api/pipeline/run", True),
        ("POST", "/api/mcp", True),
        ("POST", "/api/pipelines", False),
        ("PUT", "/api/pipelines/1", False),
        ("DELETE", "/api/me/tokens/1", False),
    ],
)
async def test_read_only_tokens_cannot_change_data(monkeypatch, method, path, allowed):
    principal = types.SimpleNamespace(token=types.SimpleNamespace(scope="read"))

    async def fake_auth(request, db):
        return principal

    monkeypatch.setattr("app.core.deps._authenticate", fake_auth)
    if allowed:
        assert await get_principal_partial(_Req(method, path), db=None) is principal
    else:
        with pytest.raises(HTTPException) as exc:
            await get_principal_partial(_Req(method, path), db=None)
        assert exc.value.status_code == 403
