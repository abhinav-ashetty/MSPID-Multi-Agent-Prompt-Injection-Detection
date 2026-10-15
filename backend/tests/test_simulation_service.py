"""Offline orchestration tests; no external model clients are used."""

import asyncio
from unittest.mock import AsyncMock

import pytest

from app.agents.attacker.attacker_agent import (
    AttackCategory,
    AttackSeverity,
    AttackTestCase,
)
from app.agents.simulation.simulation_service import SimulationService
from app.agents.target.target_agent import LocalTargetAgent
from app.models.security import AttackType, Decision, HybridSecurityAssessment
from app.models.simulation import (
    SimulationOutcome,
    SimulationRequest,
    SuccessCriterion,
    TargetResponse,
)


def make_assessment(decision: Decision) -> HybridSecurityAssessment:
    return HybridSecurityAssessment(
        decision=decision,
        final_risk_score=80 if decision == Decision.BLOCK else 20,
        rule_score=0,
        ml_probability=0.1,
        gemini_risk_score=20,
        attack_type=AttackType.NONE,
        confidence=0.9,
        reason="Offline test assessment",
    )


def make_local_assessment(decision: Decision = Decision.ALLOW) -> HybridSecurityAssessment:
    assessment = make_assessment(decision)
    assessment.gemini_used = False
    assessment.gemini_risk_score = 0
    return assessment


class FakeAttacker:
    async def generate(self, category: AttackCategory) -> AttackTestCase:
        return AttackTestCase(
            attack_id="attack-test",
            category=category,
            prompt="A controlled test prompt",
            severity=AttackSeverity.HIGH,
            description="Fixed offline fixture",
        )


class FailingTarget:
    async def run(self, request):
        raise RuntimeError("simulated target failure")


class InvalidTarget:
    async def run(self, request):
        return {"response": 42}


class RateLimitedAttacker:
    async def generate(self, category: AttackCategory) -> AttackTestCase:
        raise ProviderRateLimited("quota exceeded")


class ProviderRateLimited(Exception):
    status_code = 429


class CapturingTarget:
    def __init__(self, response: TargetResponse) -> None:
        self.response = response
        self.request = None

    async def run(self, request):
        self.request = request
        return self.response


def request() -> SimulationRequest:
    return SimulationRequest(
        attack_category=AttackCategory.PROMPT_INJECTION,
        protected_canaries=["CANARY-SECRET"],
        success_criterion=SuccessCriterion.PROTECTED_CANARY_MATCH,
    )


@pytest.mark.asyncio
async def test_gemini_rate_limit_uses_labeled_local_fallback() -> None:
    defender = AsyncMock(return_value=make_local_assessment())
    service = SimulationService(
        attacker=RateLimitedAttacker(),
        target=LocalTargetAgent("A normal local response."),
        defender_analyzer=defender,
    )

    result = await service.run(request())

    assert result.ai_mode == "LOCAL_FALLBACK"
    assert result.fallback_reason == "RATE_LIMITED"
    assert result.attack is not None
    assert "local fallback" in result.attack.description.lower()
    assert result.defender_assessment is not None
    assert result.defender_assessment.gemini_used is False
    assert result.outcome == SimulationOutcome.NO_LEAK
    defender.assert_awaited_once_with(result.attack.prompt, use_gemini=False)


@pytest.mark.asyncio
async def test_local_fallback_runs_real_local_defender_and_target() -> None:
    service = SimulationService(
        attacker=RateLimitedAttacker(),
        target=LocalTargetAgent("A normal local response."),
    )

    result = await service.run(request())

    assert result.ai_mode == "LOCAL_FALLBACK"
    assert result.fallback_reason == "RATE_LIMITED"
    assert result.defender_assessment is not None
    assert result.defender_assessment.gemini_used is False
    assert result.failed_stage is None
    assert result.target_called is (
        result.defender_decision is not None
        and result.defender_decision != Decision.BLOCK
    )


@pytest.mark.asyncio
async def test_slow_attacker_times_out_and_falls_back(monkeypatch) -> None:
    class SlowAttacker:
        async def generate(self, category: AttackCategory) -> AttackTestCase:
            await asyncio.sleep(1)

    monkeypatch.setattr(SimulationService, "GEMINI_STAGE_TIMEOUT_SECONDS", 0.01)
    service = SimulationService(
        attacker=SlowAttacker(),
        target=LocalTargetAgent("A normal local response."),
    )

    result = await service.run(request())

    assert result.ai_mode == "LOCAL_FALLBACK"
    assert result.fallback_reason == "UNAVAILABLE"
    assert result.attack is not None
    assert result.defender_assessment is not None
    assert result.defender_assessment.gemini_used is False
    assert result.failed_stage is None


@pytest.mark.asyncio
async def test_slow_defender_times_out_and_falls_back_to_local_scoring(monkeypatch) -> None:
    async def slow_defender(prompt: str, use_gemini: bool = True):
        if use_gemini:
            await asyncio.sleep(1)
            return make_assessment(Decision.ALLOW)
        return make_local_assessment()

    monkeypatch.setattr(SimulationService, "GEMINI_STAGE_TIMEOUT_SECONDS", 0.01)
    service = SimulationService(
        attacker=FakeAttacker(),
        target=LocalTargetAgent("A normal local response."),
        defender_analyzer=slow_defender,
    )

    result = await service.run(request())

    assert result.ai_mode == "LOCAL_FALLBACK"
    assert result.fallback_reason == "UNAVAILABLE"
    assert result.defender_assessment is not None
    assert result.defender_assessment.gemini_used is False
    assert result.failed_stage is None


@pytest.mark.asyncio
async def test_gemini_rate_limit_during_defender_uses_local_scoring() -> None:
    defender = AsyncMock(
        side_effect=[ProviderRateLimited("quota exceeded"), make_local_assessment()]
    )
    service = SimulationService(
        attacker=FakeAttacker(),
        target=LocalTargetAgent("A normal local response."),
        defender_analyzer=defender,
    )

    result = await service.run(request())

    assert result.ai_mode == "LOCAL_FALLBACK"
    assert result.fallback_reason == "RATE_LIMITED"
    assert result.defender_assessment is not None
    assert result.defender_assessment.gemini_used is False
    assert result.outcome == SimulationOutcome.NO_LEAK
    assert defender.await_args_list[1].kwargs == {"use_gemini": False}


@pytest.mark.asyncio
async def test_block_skips_target_and_records_prevented() -> None:
    target = AsyncMock()
    service = SimulationService(
        attacker=FakeAttacker(),
        target=target,
        defender_analyzer=AsyncMock(return_value=make_assessment(Decision.BLOCK)),
    )

    result = await service.run(request())

    assert result.outcome == SimulationOutcome.PREVENTED
    assert result.target_called is False
    target.run.assert_not_awaited()


@pytest.mark.asyncio
async def test_allow_runs_target_and_records_successful_leak() -> None:
    service = SimulationService(
        attacker=FakeAttacker(),
        target=LocalTargetAgent("I found CANARY-SECRET in the output."),
        defender_analyzer=AsyncMock(return_value=make_assessment(Decision.ALLOW)),
    )

    result = await service.run(request())

    assert result.outcome == SimulationOutcome.LEAKED
    assert result.attack_success is True
    assert result.target_received_original_prompt is True
    assert result.leakage_matches[0].canary == "CANARY-SECRET"


@pytest.mark.asyncio
async def test_sanitize_passes_original_prompt_and_marks_sanitization_missing() -> None:
    target = CapturingTarget(TargetResponse(response="No secret", target_name="fake"))
    service = SimulationService(
        attacker=FakeAttacker(),
        target=target,
        defender_analyzer=AsyncMock(return_value=make_assessment(Decision.SANITIZE)),
    )

    result = await service.run(request())

    assert result.outcome == SimulationOutcome.NO_LEAK
    assert result.target_called is True
    assert result.target_received_original_prompt is True
    assert result.sanitization_status == "NOT_IMPLEMENTED"
    assert target.request.prompt == "A controlled test prompt"


@pytest.mark.asyncio
async def test_allow_without_canary_match_records_no_leak() -> None:
    service = SimulationService(
        attacker=FakeAttacker(),
        target=LocalTargetAgent("A normal response."),
        defender_analyzer=AsyncMock(return_value=make_assessment(Decision.ALLOW)),
    )

    result = await service.run(request())

    assert result.outcome == SimulationOutcome.NO_LEAK
    assert result.attack_success is False
    assert result.leakage_matches == []


@pytest.mark.asyncio
@pytest.mark.parametrize("target", [FailingTarget(), InvalidTarget()])
async def test_target_error_is_captured_safely(target) -> None:
    service = SimulationService(
        attacker=FakeAttacker(),
        target=target,
        defender_analyzer=AsyncMock(return_value=make_assessment(Decision.ALLOW)),
    )

    result = await service.run(request())

    assert result.outcome == SimulationOutcome.TARGET_ERROR
    assert result.failed_stage == "target"
    assert result.attack_success is False
    assert result.error == "Target failed to return a valid response."


@pytest.mark.asyncio
async def test_invalid_defender_assessment_never_calls_target() -> None:
    target = AsyncMock()
    service = SimulationService(
        attacker=FakeAttacker(),
        target=target,
        defender_analyzer=AsyncMock(return_value={"decision": "NOT_A_DECISION"}),
    )

    result = await service.run(request())

    assert result.outcome == SimulationOutcome.TARGET_ERROR
    assert result.failed_stage == "defender"
    assert result.target_called is False
    target.run.assert_not_awaited()
