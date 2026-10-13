"""Orchestration for offline-capable Attacker/Defender/Target simulations."""

import inspect
import logging
import uuid
from collections.abc import Callable
from typing import Any, Optional

from app.agents.attacker.attacker_agent import AttackerAgent
from app.agents.attacker.attacker_agent import AttackTestCase
from app.agents.defender.hybrid_engine import analyze_prompt_hybrid
from app.agents.simulation.leakage_detector import LeakageDetector
from app.agents.target.target_agent import TargetAgent
from app.models.security import Decision, HybridSecurityAssessment
from app.models.simulation import (
    SimulationOutcome,
    SimulationRequest,
    SimulationResponse,
    TargetRequest,
    TargetResponse,
)

logger = logging.getLogger(__name__)
DefenderAnalyzer = Callable[[str], Any]


class SimulationService:
    """Run one controlled attack test with injectable agent dependencies."""

    def __init__(
        self,
        attacker: AttackerAgent,
        target: TargetAgent,
        defender_analyzer: DefenderAnalyzer = analyze_prompt_hybrid,
        leakage_detector: Optional[LeakageDetector] = None,
    ) -> None:
        self.attacker = attacker
        self.target = target
        self.defender_analyzer = defender_analyzer
        self.leakage_detector = leakage_detector or LeakageDetector()

    @staticmethod
    async def _await_if_needed(value: Any) -> Any:
        return await value if inspect.isawaitable(value) else value

    async def run(self, request: SimulationRequest) -> SimulationResponse:
        """Generate, assess, execute, and evaluate one simulation case."""

        simulation_id = str(uuid.uuid4())
        response = SimulationResponse(
            simulation_id=simulation_id,
            outcome=SimulationOutcome.TARGET_ERROR,
            success_criterion=request.success_criterion,
        )

        try:
            attack_result = AttackTestCase.model_validate(
                await self.attacker.generate(request.attack_category)
            )
            if attack_result.category != request.attack_category or not attack_result.prompt.strip():
                raise ValueError("Attacker returned an invalid test case")
            response.attack = attack_result
        except Exception:
            logger.warning("Simulation %s failed during attack generation", simulation_id)
            response.failed_stage = "attacker"
            response.error = "Attacker failed to produce a valid test case."
            return response

        try:
            defender_result = await self._await_if_needed(self.defender_analyzer(attack_result.prompt))
            assessment = HybridSecurityAssessment.model_validate(defender_result)
            response.defender_assessment = assessment
            response.defender_decision = assessment.decision
        except Exception as exc:
            logger.warning("Simulation %s failed during Defender assessment: %s", simulation_id, type(exc).__name__)
            response.failed_stage = "defender"
            response.error = "Defender returned an invalid assessment or failed to assess the prompt."
            return response

        if response.defender_decision == Decision.BLOCK:
            response.outcome = SimulationOutcome.PREVENTED
            return response

        response.target_called = True
        response.target_received_original_prompt = True
        if response.defender_decision == Decision.SANITIZE:
            response.sanitization_status = "NOT_IMPLEMENTED"

        try:
            target_result = await self._await_if_needed(
                self.target.run(
                    TargetRequest(
                        simulation_id=simulation_id,
                        prompt=attack_result.prompt,
                        attack_category=attack_result.category,
                    )
                )
            )
            target_response = TargetResponse.model_validate(target_result)
            if not target_response.completed or target_response.error:
                raise ValueError("Target did not complete successfully")
        except Exception as exc:
            logger.warning("Simulation %s failed during Target execution: %s", simulation_id, type(exc).__name__)
            response.outcome = SimulationOutcome.TARGET_ERROR
            response.failed_stage = "target"
            response.error = "Target failed to return a valid response."
            return response

        response.target_response = target_response
        try:
            response.leakage_matches = self.leakage_detector.detect(
                target_response.response,
                request.protected_canaries,
            )
        except Exception as exc:
            logger.warning("Simulation %s failed during leakage evaluation: %s", simulation_id, type(exc).__name__)
            response.outcome = SimulationOutcome.TARGET_ERROR
            response.failed_stage = "target"
            response.error = "Target response could not be evaluated safely."
            return response

        # This phase supports canary matching as its only success criterion.
        response.attack_success = (
            request.success_criterion.value == "PROTECTED_CANARY_MATCH"
            and bool(response.leakage_matches)
        )
        response.outcome = (
            SimulationOutcome.LEAKED if response.attack_success else SimulationOutcome.NO_LEAK
        )
        return response
