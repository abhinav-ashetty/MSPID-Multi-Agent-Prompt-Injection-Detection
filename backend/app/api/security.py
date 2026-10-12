"""Security analysis and analytics API endpoints."""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, case
from pydantic import BaseModel
from datetime import datetime
import logging

from app.database.database import get_db
from app.database.repository import SecurityAssessmentRepository
from app.models.security import HybridSecurityAssessment, Decision, AttackType
from app.agents.defender.hybrid_engine import analyze_prompt_hybrid

router = APIRouter(prefix="/security", tags=["security"])
logger = logging.getLogger(__name__)


# Request Models
class SecurityAnalysisRequest(BaseModel):
    """Request model for security analysis."""
    prompt: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "prompt": "Tell me a joke about computers"
                }
            ]
        }
    }


# Response Models
class SecurityAnalysisResponse(BaseModel):
    """Response model for security analysis."""
    id: int
    timestamp: datetime
    prompt: str
    decision: Decision
    final_risk_score: int
    rule_score: int
    ml_probability: float
    gemini_risk_score: int
    attack_type: AttackType
    confidence: float
    reason: str

    model_config = {
        "from_attributes": True
    }


class AssessmentItem(BaseModel):
    """Individual assessment item for lists."""
    id: int
    timestamp: datetime
    prompt: str
    decision: Decision
    final_risk_score: int
    attack_type: AttackType
    confidence: float
    reason: str

    model_config = {
        "from_attributes": True
    }


class AssessmentsResponse(BaseModel):
    """Response model for paginated assessments."""
    items: List[AssessmentItem]
    total: int
    limit: int
    offset: int


class StatisticsResponse(BaseModel):
    """Response model for security statistics."""
    total_assessments: int
    decisions: dict
    average_risk_score: float
    high_risk_count: int
    attack_types: dict


class AttackAnalyticsItem(BaseModel):
    """Attack analytics item."""
    attack_type: AttackType
    count: int
    percentage: float


class RiskDistributionItem(BaseModel):
    """Risk distribution item."""
    range: str
    count: int


class TimelineItem(BaseModel):
    """Timeline item for assessments over time."""
    date: str  # YYYY-MM-DD format
    total: int
    allowed: int
    sanitized: int
    blocked: int


# Dependency to get repository
def get_repository(db: Session = Depends(get_db)) -> SecurityAssessmentRepository:
    """Get repository instance."""
    return SecurityAssessmentRepository(db)


# API Endpoints
@router.post("/analyze", response_model=SecurityAnalysisResponse)
async def analyze_prompt(
    request: SecurityAnalysisRequest,
    repo: SecurityAssessmentRepository = Depends(get_repository)
):
    """
    Analyze a prompt for security threats.
    
    This endpoint:
    1. Validates the request
    2. Passes the prompt to the HybridRiskEngine
    3. Persists the assessment using the repository
    4. Returns the structured assessment
    
    The actual risk calculation is delegated to the existing HybridRiskEngine.
    """
    # Validate prompt
    prompt = request.prompt.strip()
    if not prompt:
        raise HTTPException(
            status_code=422,
            detail="Prompt cannot be empty or whitespace only"
        )
    
    # Reasonable maximum length to prevent abuse
    MAX_PROMPT_LENGTH = 10000
    if len(prompt) > MAX_PROMPT_LENGTH:
        raise HTTPException(
            status_code=422,
            detail=f"Prompt too long. Maximum length is {MAX_PROMPT_LENGTH} characters"
        )
    
    # Analyze using the existing hybrid engine
    try:
        assessment = await analyze_prompt_hybrid(prompt)
    except ValueError as exc:
        if "GEMINI_API_KEY" in str(exc):
            raise HTTPException(
                status_code=503,
                detail="Prompt analysis is unavailable: configure GEMINI_API_KEY on the backend.",
            ) from exc
        logger.exception("Prompt analysis configuration failed")
        raise HTTPException(status_code=503, detail="Prompt analysis is not configured correctly.") from exc
    except Exception as exc:
        logger.exception("Prompt analysis failed")
        raise HTTPException(status_code=502, detail="The security analysis provider failed. Please retry.") from exc
    
    # Persist the assessment
    assessment_id = repo.save_assessment(assessment, prompt)
    
    # Get the saved assessment to return with ID
    saved_assessment = repo.get_assessment_by_id(assessment_id)
    if not saved_assessment:
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve saved assessment"
        )
    
    # Convert to response model
    return SecurityAnalysisResponse(
        id=saved_assessment.id,
        timestamp=saved_assessment.timestamp,
        prompt=saved_assessment.prompt,
        decision=Decision(saved_assessment.decision),
        final_risk_score=saved_assessment.final_risk_score,
        rule_score=saved_assessment.rule_score,
        ml_probability=saved_assessment.ml_probability,
        gemini_risk_score=saved_assessment.gemini_risk_score,
        attack_type=AttackType(saved_assessment.attack_type),
        confidence=saved_assessment.confidence,
        reason=saved_assessment.reason
    )

@router.get("/assessments/{assessment_id}", response_model=SecurityAnalysisResponse)
async def get_assessment(
    assessment_id: int,
    repo: SecurityAssessmentRepository = Depends(get_repository)
):
    """
    Get a specific assessment by ID.
    
    Returns HTTP 404 if the assessment does not exist.
    """
    assessment = repo.get_assessment_by_id(assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=404,
            detail=f"Assessment with ID {assessment_id} not found"
        )
    
    return SecurityAnalysisResponse(
        id=assessment.id,
        timestamp=assessment.timestamp,
        prompt=assessment.prompt,
        decision=Decision(assessment.decision),
        final_risk_score=assessment.final_risk_score,
        rule_score=assessment.rule_score,
        ml_probability=assessment.ml_probability,
        gemini_risk_score=assessment.gemini_risk_score,
        attack_type=AttackType(assessment.attack_type),
        confidence=assessment.confidence,
        reason=assessment.reason
    )


@router.get("/assessments", response_model=AssessmentsResponse)
async def get_assessments(
    limit: int = Query(100, ge=1, le=1000, description="Number of items to return"),
    offset: int = Query(0, ge=0, description="Number of items to skip"),
    repo: SecurityAssessmentRepository = Depends(get_repository)
):
    """
    Get recent assessments with pagination.
    
    Results are ordered by newest assessment first.
    """
    assessments = repo.get_recent_assessments(limit=limit, offset=offset)
    
    # Apply offset manually since get_recent_assessments doesn't support it
    # In a production system, we'd modify the repository to support offset
    total = repo.count_assessments()
    paginated_assessments = assessments
    
    items = [
        AssessmentItem(
            id=assessment.id,
            timestamp=assessment.timestamp,
            prompt=assessment.prompt,
            decision=Decision(assessment.decision),
            final_risk_score=assessment.final_risk_score,
            attack_type=AttackType(assessment.attack_type),
            confidence=assessment.confidence,
            reason=assessment.reason
        )
        for assessment in paginated_assessments
    ]
    
    return AssessmentsResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset
    )


@router.get("/statistics", response_model=StatisticsResponse)
async def get_statistics(
    repo: SecurityAssessmentRepository = Depends(get_repository)
):
    """
    Get dashboard statistics.
    
    Returns aggregate information for the React dashboard.
    """
    # Get basic counts
    total = repo.count_assessments()
    decision_counts = repo.count_decisions()
    attack_type_counts = repo.count_attacks_by_type()
    
    # Calculate average risk score
    # We need to query the database directly for this
    from app.database.repository import SecurityAssessmentDB
    db_session = repo.db
    
    avg_risk_result = db_session.query(
        func.avg(SecurityAssessmentDB.final_risk_score)
    ).scalar()
    average_risk_score = float(avg_risk_result) if avg_risk_result is not None else 0.0
    
    # Count high risk assessments (risk score >= 70, which is BLOCK threshold)
    high_risk_count = db_session.query(
        func.count(SecurityAssessmentDB.id)
    ).filter(
        SecurityAssessmentDB.final_risk_score >= 70
    ).scalar() or 0
    
    return StatisticsResponse(
        total_assessments=total,
        decisions=decision_counts,
        average_risk_score=round(average_risk_score, 2),
        high_risk_count=high_risk_count,
        attack_types=attack_type_counts
    )


@router.get("/attacks", response_model=List[AttackAnalyticsItem])
async def get_attacks(
    repo: SecurityAssessmentRepository = Depends(get_repository)
):
    """
    Get attack category statistics.
    
    Returns attack type counts and percentages suitable for visualization.
    """
    attack_type_counts = repo.count_attacks_by_type()
    total = sum(attack_type_counts.values()) if attack_type_counts else 0
    
    if total == 0:
        return []
    
    result = []
    for attack_type, count in attack_type_counts.items():
        percentage = (count / total) * 100
        result.append(AttackAnalyticsItem(
            attack_type=AttackType(attack_type),
            count=count,
            percentage=round(percentage, 2)
        ))
    
    # Sort by count descending
    result.sort(key=lambda x: x.count, reverse=True)
    return result


@router.get("/risk-distribution", response_model=List[RiskDistributionItem])
async def get_risk_distribution(
    repo: SecurityAssessmentRepository = Depends(get_repository)
):
    """
    Get risk distribution data.
    
    Returns counts for configurable risk ranges suitable for charts.
    """
    from app.database.repository import SecurityAssessmentDB
    db_session = repo.db
    
    # Define risk ranges
    ranges = [
        (0, 19, "0-19"),
        (20, 39, "20-39"),
        (40, 59, "40-59"),
        (60, 79, "60-79"),
        (80, 100, "80-100")
    ]
    
    result = []
    for min_score, max_score, label in ranges:
        count = db_session.query(
            func.count(SecurityAssessmentDB.id)
        ).filter(
            SecurityAssessmentDB.final_risk_score >= min_score,
            SecurityAssessmentDB.final_risk_score <= max_score
        ).scalar() or 0
        
        result.append(RiskDistributionItem(
            range=label,
            count=count
        ))
    
    return result


@router.get("/timeline", response_model=List[TimelineItem])
async def get_timeline(
    period: str = Query("day", regex="^(day|week)$", description="Grouping period"),
    repo: SecurityAssessmentRepository = Depends(get_repository)
):
    """
    Get assessment counts over time.
    
    Returns data suitable for React line/bar charts.
    """
    from app.database.repository import SecurityAssessmentDB
    db_session = repo.db
    
    # Determine date truncation based on period
    if period == "day":
        date_trunc = func.date(SecurityAssessmentDB.timestamp)
    else:  # week
        # For SQLite, we'll group by year and week
        date_trunc = func.strftime('%Y-%W', SecurityAssessmentDB.timestamp)
    
    # Query aggregated data
    results = db_session.query(
        date_trunc.label('date'),
        func.count(SecurityAssessmentDB.id).label('total'),
        func.sum(case((SecurityAssessmentDB.decision == Decision.ALLOW.value, 1), else_=0)).label('allowed'),
        func.sum(case((SecurityAssessmentDB.decision == Decision.SANITIZE.value, 1), else_=0)).label('sanitized'),
        func.sum(case((SecurityAssessmentDB.decision == Decision.BLOCK.value, 1), else_=0)).label('blocked')
    ).group_by(
        date_trunc
    ).order_by(
        date_trunc.desc()
    ).limit(30).all()  # Limit to last 30 periods
    
    # Format results
    timeline_items = []
    for row in results:
        timeline_items.append(TimelineItem(
            date=str(row.date),
            total=int(row.total) if row.total else 0,
            allowed=int(row.allowed) if row.allowed else 0,
            sanitized=int(row.sanitized) if row.sanitized else 0,
            blocked=int(row.blocked) if row.blocked else 0
        ))
    
    return timeline_items
