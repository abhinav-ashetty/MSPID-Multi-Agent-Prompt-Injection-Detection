"""Repository layer for Defender security assessment persistence."""

from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import and_, func, desc
from datetime import datetime

from app.database.database import Base
from app.models.security import (
    HybridSecurityAssessment,
    Decision,
    AttackType,
)
from sqlalchemy import Column, Integer, String, Text, Float, DateTime


class SecurityAssessmentDB(Base):
    """SQLAlchemy model for storing security assessments."""
    
    __tablename__ = "security_assessments"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    prompt = Column(Text, nullable=False)
    
    # Assessment results
    decision = Column(String(20), nullable=False)  # ALLOW, SANITIZE, BLOCK
    final_risk_score = Column(Integer, nullable=False)
    rule_score = Column(Integer, nullable=False)
    ml_probability = Column(Float, nullable=False)
    gemini_risk_score = Column(Integer, nullable=False)
    attack_type = Column(String(20), nullable=False)  # NONE, PROMPT_INJECTION, OTHER
    confidence = Column(Float, nullable=False)
    reason = Column(Text, nullable=False)
    
    # Optional details from rule detector
    matched_rules = Column(Text, nullable=True)  # JSON string or comma-separated
    indicators = Column(Text, nullable=True)     # JSON string or comma-separated
    rule_reason = Column(Text, nullable=True)
    
    # Optional details from ML classifier
    ml_prediction = Column(Integer, nullable=True)
    ml_probability_benign = Column(Float, nullable=True)
    
    # Optional details from Gemini
    gemini_details = Column(Text, nullable=True)


class SecurityAssessmentRepository:
    """Repository for security assessment persistence operations."""
    
    def __init__(self, db_session: Session):
        """Initialize repository with database session.
        
        Args:
            db_session: SQLAlchemy database session
        """
        self.db = db_session
    
    def save_assessment(self, assessment: HybridSecurityAssessment, prompt: str) -> int:
        """Save a security assessment to the database.
        
        Args:
            assessment: The HybridSecurityAssessment to save
            prompt: The original prompt that was assessed
            
        Returns:
            The ID of the saved assessment record
        """
        # Extract rule details if available
        matched_rules_str = None
        indicators_str = None
        rule_reason = None
        
        if assessment.rule_details:
            # Assuming rule_details is a list of strings like ["Matched rules: RULE1, RULE2"]
            # For simplicity, we'll join them or take the first one
            if isinstance(assessment.rule_details, list) and assessment.rule_details:
                # Extract just the rules part if it follows our format
                first_detail = assessment.rule_details[0]
                if first_detail.startswith("Matched rules: "):
                    matched_rules_str = first_detail[15:]  # Remove "Matched rules: " prefix
                else:
                    matched_rules_str = ", ".join(assessment.rule_details)
        
        # Create database model instance
        db_assessment = SecurityAssessmentDB(
            prompt=prompt,
            decision=assessment.decision.value,
            final_risk_score=assessment.final_risk_score,
            rule_score=assessment.rule_score,
            ml_probability=assessment.ml_probability,
            gemini_risk_score=assessment.gemini_risk_score,
            attack_type=assessment.attack_type.value,
            confidence=assessment.confidence,
            reason=assessment.reason,
            matched_rules=matched_rules_str,
            indicators=indicators_str,  # We could extract this from rule_result if needed
            rule_reason=rule_reason,
            ml_prediction=1 if assessment.ml_probability > 0.5 else 0 if assessment.ml_details else None,
            ml_probability_benign=(
                1.0 - assessment.ml_probability 
                if assessment.ml_details is None 
                else assessment.ml_details.get("probability_benign")
            ),
            gemini_details=assessment.gemini_details,
        )
        
        # Save to database
        self.db.add(db_assessment)
        self.db.commit()
        self.db.refresh(db_assessment)
        
        return db_assessment.id
    
    def get_assessment_by_id(self, assessment_id: int) -> Optional[SecurityAssessmentDB]:
        """Retrieve an assessment by its ID.
        
        Args:
            assessment_id: The ID of the assessment to retrieve
            
        Returns:
            SecurityAssessmentDB object if found, None otherwise
        """
        return self.db.query(SecurityAssessmentDB).filter(
            SecurityAssessmentDB.id == assessment_id
        ).first()
    
    def get_recent_assessments(self, limit: int = 100, offset: int = 0) -> List[SecurityAssessmentDB]:
        """Retrieve recent assessments ordered by timestamp (newest first).
        
        Args:
            limit: Maximum number of assessments to return
            
        Returns:
            List of SecurityAssessmentDB objects ordered by timestamp descending
        """
        return self.db.query(SecurityAssessmentDB)\
            .order_by(desc(SecurityAssessmentDB.timestamp))\
            .offset(offset)\
            .limit(limit)\
            .all()
    
    def count_assessments(self) -> int:
        """Count total number of assessments in the database.
        
        Returns:
            Total count of assessments
        """
        return self.db.query(func.count(SecurityAssessmentDB.id)).scalar()
    
    def count_decisions(self) -> dict:
        """Count assessments by decision type.
        
        Returns:
            Dictionary with counts for ALLOW, SANITIZE, BLOCK decisions
        """
        from sqlalchemy import case
        
        results = self.db.query(
            func.count(
                case((SecurityAssessmentDB.decision == Decision.ALLOW.value, 1))
            ).label("allow_count"),
            func.count(
                case((SecurityAssessmentDB.decision == Decision.SANITIZE.value, 1))
            ).label("sanitize_count"),
            func.count(
                case((SecurityAssessmentDB.decision == Decision.BLOCK.value, 1))
            ).label("block_count")
        ).first()
        
        return {
            "ALLOW": results.allow_count or 0,
            "SANITIZE": results.sanitize_count or 0,
            "BLOCK": results.block_count or 0,
        }
    
    def count_attacks_by_type(self) -> dict:
        """Count assessments by attack type.
        
        Returns:
            Dictionary with counts for each attack type
        """
        results = self.db.query(
            SecurityAssessmentDB.attack_type,
            func.count(SecurityAssessmentDB.id).label("count")
        ).group_by(SecurityAssessmentDB.attack_type).all()
        
        return {row.attack_type: row.count for row in results}
