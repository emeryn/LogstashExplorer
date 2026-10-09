"""Client for the isolated Logstash runner (internal network only, bearer-token authenticated)."""

from typing import Any

import httpx

from app.core.config import get_settings
from app.core.secrets import require_secret


class RunnerError(RuntimeError):
    pass


async def run_pipeline(
    config: str, input_data: str, input_format: str = "lines", ecs_compatibility: str = "disabled"
) -> dict[str, Any]:
    s = get_settings()
    try:
        async with httpx.AsyncClient(timeout=s.runner_timeout_s + s.runner_queue_wait_s + 30) as client:
            resp = await client.post(
                f"{s.runner_url}/run",
                json={
                    "config": config,
                    "input": input_data,
                    "input_format": input_format,
                    "ecs_compatibility": ecs_compatibility,
                    "timeout": s.runner_timeout_s,
                },
                headers={"Authorization": f"Bearer {require_secret('runner_token')}"},
            )
    except httpx.HTTPError as exc:
        raise RunnerError(f"Logstash runner unreachable: {exc.__class__.__name__}") from exc
    if resp.status_code == 429:
        raise RunnerError("All Logstash runners are busy (queue full): retry in a moment")
    if resp.status_code >= 500 or resp.status_code in (401, 403):
        raise RunnerError(f"Logstash runner error (HTTP {resp.status_code})")
    return resp.json()
