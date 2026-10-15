"""Offline tests for bounded Defender retries on transient provider overload."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.agents.defender.defender_agent import DefenderAgent
from app.models.security import AttackType, Decision, SecurityAssessment


class ProviderUnavailable(Exception):
    status_code = 503


@pytest.mark.asyncio
async def test_defender_retries_503_and_succeeds(monkeypatch):
    defender = DefenderAgent.__new__(DefenderAgent)
    assessment = SecurityAssessment(
        decision=Decision.BLOCK,
        risk_score=95,
        attack_type=AttackType.PROMPT_INJECTION,
        confidence=0.98,
        reason="Detected an instruction override attempt.",
    )
    success = SimpleNamespace(messages=[SimpleNamespace(content=assessment)])
    defender.agent = SimpleNamespace(
        run=AsyncMock(side_effect=[ProviderUnavailable(), ProviderUnavailable(), success])
    )
    sleep = AsyncMock()
    monkeypatch.setattr("app.agents.defender.defender_agent.asyncio.sleep", sleep)

    result = await defender.analyze("offline test prompt")

    assert result == assessment
    assert defender.agent.run.await_count == 3
    assert [call.args[0] for call in sleep.await_args_list] == [1, 2]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content",
    [
        {
            "decision": "BLOCK",
            "risk_score": 95,
            "attack_type": "PROMPT_INJECTION",
            "confidence": 0.98,
            "reason": "Detected an instruction override attempt.",
        },
        (
            '{"decision":"BLOCK","risk_score":95,'
            '"attack_type":"PROMPT_INJECTION","confidence":0.98,'
            '"reason":"Detected an instruction override attempt."}'
        ),
    ],
)
async def test_defender_validates_structured_gemini_response(content):
    defender = DefenderAgent.__new__(DefenderAgent)
    defender.agent = SimpleNamespace(
        run=AsyncMock(return_value=SimpleNamespace(
            messages=[SimpleNamespace(content=content)]
        ))
    )

    result = await defender.analyze("offline test prompt")

    assert isinstance(result, SecurityAssessment)
    assert result.risk_score == 95
    assert result.decision == Decision.BLOCK


@pytest.mark.asyncio
async def test_defender_rejects_missing_structured_gemini_response():
    defender = DefenderAgent.__new__(DefenderAgent)
    defender.agent = SimpleNamespace(
        run=AsyncMock(return_value=SimpleNamespace(
            messages=[SimpleNamespace(content="No structured response returned")]
        ))
    )

    with pytest.raises(ValueError, match="valid structured security assessment"):
        await defender.analyze("offline test prompt")


@pytest.mark.asyncio
async def test_defender_does_not_retry_non_503_errors(monkeypatch):
    defender = DefenderAgent.__new__(DefenderAgent)
    failure = RuntimeError("non-retryable")
    defender.agent = SimpleNamespace(run=AsyncMock(side_effect=failure))
    sleep = AsyncMock()
    monkeypatch.setattr("app.agents.defender.defender_agent.asyncio.sleep", sleep)

    with pytest.raises(RuntimeError, match="non-retryable"):
        await defender.analyze("offline test prompt")

    defender.agent.run.assert_awaited_once()
    sleep.assert_not_awaited()


@pytest.mark.asyncio
async def test_defender_stops_after_three_503_responses(monkeypatch):
    defender = DefenderAgent.__new__(DefenderAgent)
    defender.agent = SimpleNamespace(
        run=AsyncMock(side_effect=ProviderUnavailable("still unavailable"))
    )
    sleep = AsyncMock()
    monkeypatch.setattr("app.agents.defender.defender_agent.asyncio.sleep", sleep)

    with pytest.raises(ProviderUnavailable):
        await defender.analyze("offline test prompt")

    assert defender.agent.run.await_count == 3
    assert sleep.await_count == 2
