"""SQLite persistence for controlled attack simulation runs."""

import json
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, desc, func
from sqlalchemy.orm import Session

from app.database.database import Base
from app.models.simulation import SimulationOutcome, SimulationResponse


class SimulationRunDB(Base):
    """Database row for a single Attacker/Defender/Target simulation."""

    __tablename__ = "simulation_runs"

    id = Column(Integer, primary_key=True, index=True)
    simulation_id = Column(String(36), nullable=False, unique=True, index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    attack_category = Column(String(50), nullable=False)
    prompt = Column(Text, nullable=True)
    defender_decision = Column(String(20), nullable=True)
    target_called = Column(Boolean, nullable=False, default=False)
    target_received_original_prompt = Column(Boolean, nullable=False, default=False)
    leakage_matches_json = Column(Text, nullable=False, default="[]")
    attack_success = Column(Boolean, nullable=False, default=False)
    outcome = Column(String(20), nullable=False)
    success_criterion = Column(String(50), nullable=False)
    sanitization_status = Column(String(30), nullable=False)
    failed_stage = Column(String(20), nullable=True)
    error = Column(Text, nullable=True)
    result_json = Column(Text, nullable=False)


class SimulationRepository:
    """Repository operations for simulation history and summary counts."""

    def __init__(self, db_session: Session) -> None:
        self.db = db_session

    def save(self, result: SimulationResponse, attack_category: str) -> SimulationRunDB:
        attack = result.attack
        row = SimulationRunDB(
            simulation_id=result.simulation_id,
            attack_category=attack_category,
            prompt=attack.prompt if attack else None,
            defender_decision=result.defender_decision.value if result.defender_decision else None,
            target_called=result.target_called,
            target_received_original_prompt=result.target_received_original_prompt,
            leakage_matches_json=json.dumps(
                [match.model_dump(mode="json") for match in result.leakage_matches]
            ),
            attack_success=result.attack_success,
            outcome=result.outcome.value,
            success_criterion=result.success_criterion.value,
            sanitization_status=result.sanitization_status,
            failed_stage=result.failed_stage,
            error=result.error,
            result_json=json.dumps(result.model_dump(mode="json")),
        )
        try:
            self.db.add(row)
            self.db.commit()
            self.db.refresh(row)
        except Exception:
            self.db.rollback()
            raise
        return row

    def get_by_simulation_id(self, simulation_id: str) -> Optional[SimulationRunDB]:
        return self.db.query(SimulationRunDB).filter(
            SimulationRunDB.simulation_id == simulation_id
        ).first()

    def list_runs(self, limit: int = 50, offset: int = 0) -> tuple[list[SimulationRunDB], int]:
        rows = self.db.query(SimulationRunDB).order_by(
            desc(SimulationRunDB.created_at), desc(SimulationRunDB.id)
        ).offset(offset).limit(limit).all()
        total = self.db.query(func.count(SimulationRunDB.id)).scalar() or 0
        return rows, int(total)

    def statistics(self) -> dict[str, object]:
        total = self.db.query(func.count(SimulationRunDB.id)).scalar() or 0
        outcomes = {
            outcome.value: self.db.query(func.count(SimulationRunDB.id)).filter(
                SimulationRunDB.outcome == outcome.value
            ).scalar() or 0
            for outcome in SimulationOutcome
        }
        successful = self.db.query(func.count(SimulationRunDB.id)).filter(
            SimulationRunDB.attack_success.is_(True)
        ).scalar() or 0
        return {
            "total_simulations": int(total),
            "successful_attacks": int(successful),
            "outcomes": {key: int(value) for key, value in outcomes.items()},
        }
