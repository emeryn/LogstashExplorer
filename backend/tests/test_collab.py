import uuid

import pytest
from fastapi import HTTPException

from app.services.agent import evaluate, split_output_sections, with_outputs
from app.services.concurrency import RunSlot, in_flight, user_run_slot

CONF = """filter { mutate { add_field => { "out" => "output { not a section }" } } }
# output { commented }
output {
  syslog { host => "h" port => 514 message => "}{" }
}
"""


def test_split_output_sections_is_string_and_comment_aware():
    outputs = split_output_sections(CONF)
    assert outputs.startswith("output {") and outputs.endswith("}")
    assert 'message => "}{"' in outputs
    assert "not a section" not in outputs and "commented" not in outputs


def test_with_outputs_reattaches_fixed_outputs_once():
    outputs = split_output_sections(CONF)
    merged = with_outputs("filter { drop {} }", outputs)
    assert merged.count("output {") == 1
    assert with_outputs(merged, outputs) == merged  # already present: untouched


async def test_per_user_run_limit(monkeypatch):
    monkeypatch.setattr("app.services.concurrency.get_settings", lambda: type("S", (), {"max_runs_per_user": 2})())
    user = uuid.uuid4()
    async with user_run_slot(user):
        slot = RunSlot(user)
        with pytest.raises(HTTPException) as exc:
            RunSlot(user)
        assert exc.value.status_code == 429
        slot.release()
        slot.release()  # idempotent
        assert in_flight(user) == 1
    assert in_flight(user) == 0


def test_syslog_frame_errors_become_agent_issues():
    result = {
        "ok": True,
        "errors": [],
        "events": [{"message": "x"}],
        "syslog": {"frames": [{"errors": ["HOSTNAME '{x}' looks like an unresolved or object field reference"]}]},
    }
    issues = evaluate(result, None, True)
    assert any(i.startswith("Syslog frame: HOSTNAME") for i in issues)
    result["syslog"]["frames"] = []
    assert "The syslog output emitted no frame." in evaluate(result, None, True)


def test_best_permission_between_personal_and_group_shares():
    from app.api.projects import _best
    from app.db.models import SharePermission

    assert _best([SharePermission.READ, SharePermission.WRITE]) == "write"
    assert _best([SharePermission.READ]) == "read"
    assert _best([]) is None
