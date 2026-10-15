"""Schemas for controlled, local AIShield attack simulations."""

from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

from app.agents.attacker.attacker_agent import AttackCategory, AttackTestCase
from app.models.security import Decision, HybridSecurityAssessment


class SimulationOutcome(str, Enum):
    """Final result of one simulation run."""

    PREVENTED = "PREVENTED"
    LEAKED = "LEAKED"
    NO_LEAK = "NO_LEAK"
    TARGET_ERROR = "TARGET_ERROR"


class SuccessCriterion(str, Enum):
    """Supported deterministic criteria for declaring an attack successful."""

    PROTECTED_CANARY_MATCH = "PROTECTED_CANARY_MATCH"


class SimulationRequest(BaseModel):
    """Input used to generate and run one controlled attack test."""

    attack_category: AttackCategory
    protected_canaries: list[str] = Field(default_factory=list)
    success_criterion: SuccessCriterion = SuccessCriterion.PROTECTED_CANARY_MATCH

    @field_validator("protected_canaries")
    @classmethod
    def validate_canaries(cls, values: list[str]) -> list[str]:
        if any(not isinstance(value, str) or not value.strip() for value in values):
            raise ValueError("Protected canaries must be non-empty strings")
        return values


class TargetRequest(BaseModel):
    """Prompt and case metadata passed to a Target Agent."""

    simulation_id: str
    prompt: str = Field(min_length=1)
    attack_category: AttackCategory
    metadata: dict[str, str] = Field(default_factory=dict)


class TargetResponse(BaseModel):
    """Validated output returned by a Target Agent."""

    response: str = Field(min_length=1)
    target_name: str = Field(min_length=1)
    completed: bool = True
    error: Optional[str] = None
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("response", "target_name")
    @classmethod
    def validate_non_whitespace(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Target response and target name cannot be whitespace only")
        return value


class LeakageMatch(BaseModel):
    """One protected canary found in a target response."""

    canary: str
    match_type: Literal["EXACT", "NORMALIZED"]


class SimulationResponse(BaseModel):
    """Structured outcome for a single simulation run."""

    simulation_id: str
    outcome: SimulationOutcome
    ai_mode: Literal["GEMINI", "LOCAL_FALLBACK"] = "GEMINI"
    fallback_reason: Optional[Literal["RATE_LIMITED", "UNAVAILABLE"]] = None
    attack: Optional[AttackTestCase] = None
    defender_assessment: Optional[HybridSecurityAssessment] = None
    defender_decision: Optional[Decision] = None
    target_called: bool = False
    target_received_original_prompt: bool = False
    target_response: Optional[TargetResponse] = None
    leakage_matches: list[LeakageMatch] = Field(default_factory=list)
    attack_success: bool = False
    success_criterion: SuccessCriterion
    sanitization_status: Literal["NOT_APPLICABLE", "NOT_IMPLEMENTED"] = "NOT_APPLICABLE"
    failed_stage: Optional[Literal["attacker", "defender", "target"]] = None
    error: Optional[str] = None
