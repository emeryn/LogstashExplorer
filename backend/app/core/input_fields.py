"""Simulated input fields: what a real Logstash input would add to every event before the filters
(e.g. the file input's `[log][file][path]`, a beats `[fields][env]`…), so filters relying on them can be tested.

Same rules as the runner, which re-validates them before embedding them in its harness.
"""

import re
from typing import Annotated

from pydantic import AfterValidator

NAME = re.compile(r"^(?:\[[A-Za-z0-9_@.-]{1,64}\]){1,6}$|^[A-Za-z0-9_@.-]{1,64}$")
MAX_FIELDS = 20
MAX_VALUE = 2048


def check(fields: dict[str, str] | None) -> dict[str, str] | None:
    if not fields:
        return None
    if len(fields) > MAX_FIELDS:
        raise ValueError(f"at most {MAX_FIELDS} input fields")
    for name, value in fields.items():
        if not NAME.match(name):
            raise ValueError(f"invalid input field name {name[:80]!r} (expected e.g. [log][file][path] or env)")
        if len(value) > MAX_VALUE or any(c in value for c in '"\r\n') or value.endswith("\\") or "%{" in value:
            raise ValueError(f"invalid value for {name}: no double quotes, newlines, trailing backslash or %{{}}")
    return fields


InputFields = Annotated[dict[str, str] | None, AfterValidator(check)]
