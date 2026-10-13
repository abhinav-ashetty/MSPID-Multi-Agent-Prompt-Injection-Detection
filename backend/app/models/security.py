"""Security assessment models for the Defender Agent."""

from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional, List


class Decision(str, Enum):
    """Security decision enum."""

    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"


class AttackType(str, Enum):
    """Attack type enum."""

    NONE = "NONE"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    OTHER = "OTHER"


class SecurityAssessment(BaseModel):
    """Structured security assessment output from the Defender Agent."""

    decision: Decision = Field(
        ...,
        description="Security decision: ALLOW, SANITIZE, or BLOCK",
    )
    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Risk score from 0 (safe) to 100 (critical)",
    )
    attack_type: AttackType = Field(
        ...,
        description="Type of attack detected",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence in the assessment from 0.0 to 1.0",
    )
    reason: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Short explanation for the assessment",
    )


class RuleDetectionResult(BaseModel):
    """Result of rule-based security detection."""

    is_suspicious: bool = Field(
        ...,
        description="Whether any suspicious patterns were detected",
    )
    rule_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Rule-based score from 0 (safe) to 100 (highly suspicious)",
    )
    matched_rules: list[str] = Field(
        default_factory=list,
        description="Names of rule categories that matched",
    )
    indicators: list[str] = Field(
        default_factory=list,
        description="Specific matched patterns/indicators",
    )
    reason: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Human-readable explanation of the detection result",
    )


class HybridSecurityAssessment(BaseModel):
    """Structured output from the Hybrid Risk Engine combining multiple detectors."""

    decision: Decision = Field(
        ...,
        description="Final security decision: ALLOW, SANITIZE, or BLOCK",
    )
    final_risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Final combined risk score from 0 (safe) to 100 (critical)",
    )
    rule_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Rule-based detector score (0-100)",
    )
    ml_probability: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="ML classifier probability of being malicious (0.0-1.0)",
    )
    gemini_risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Gemini DefenderAgent risk score (0-100)",
    )
    gemini_used: bool = Field(
        default=True,
        description="Whether Gemini was used in this assessment",
    )
    attack_type: AttackType = Field(
        ...,
        description="Type of attack detected (from Gemini assessment)",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence in the final assessment from 0.0 to 1.0",
    )
    reason: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Human-readable explanation of the hybrid assessment",
    )
    # Optional fields for detailed explanation
    rule_details: Optional[List[str]] = Field(
        default=None,
        description="Optional details from rule detector (matched rules/indicators)",
    )
    ml_details: Optional[dict] = Field(
        default=None,
        description="Optional details from ML classifier (e.g., feature importance)",
    )
    gemini_details: Optional[str] = Field(
        default=None,
        description="Optional details from Gemini assessment (reasoning)",
    )
