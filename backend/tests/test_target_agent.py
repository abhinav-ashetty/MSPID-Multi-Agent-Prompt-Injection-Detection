"""Offline tests for the deterministic Target Agent."""

import pytest

from app.agents.target.target_agent import LocalTargetAgent
from app.agents.attacker.attacker_agent import AttackCategory
from app.models.simulation import TargetRequest, TargetResponse


@pytest.mark.asyncio
async def test_local_target_returns_configured_response() -> None:
    target = LocalTargetAgent(response="A fixed test response.")
    request = TargetRequest(
        simulation_id="simulation-1",
        prompt="A local test prompt",
        attack_category=AttackCategory.BENIGN,
    )

    result = await target.run(request)

    assert isinstance(result, TargetResponse)
    assert result.response == "A fixed test response."
    assert result.target_name == "local-test-target"
    assert result.completed is True
    assert result.metadata["simulation_id"] == "simulation-1"
