"""API endpoints for controlled attack simulations and history."""

import json
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.agents.attacker.attacker_agent import AttackerAgent
from app.agents.defender.hybrid_engine import analyze_prompt_hybrid
from app.agents.simulation.simulation_service import SimulationService
from app.agents.target.target_agent import LocalTargetAgent
from app.database.database import get_db
from app.database.simulation_repository import SimulationRepository, SimulationRunDB
from app.models.simulation import (
    SimulationRequest,
    SimulationResponse,
)

router = APIRouter(prefix="/simulations", tags=["simulations"])
logger = logging.getLogger(__name__)


class SimulationRunRecord(BaseModel):
    id: int
    created_at: datetime
    result: SimulationResponse

    model_config = ConfigDict(from_attributes=True)


class SimulationHistoryItem(BaseModel):
    id: int
    simulation_id: str
    created_at: datetime
    attack_category: str
    prompt: Optional[str]
    defender_decision: Optional[str]
    target_called: bool
    target_received_original_prompt: bool
    leakage_matches: list[dict]
    attack_success: bool
    outcome: str
    success_criterion: str
    sanitization_status: str
    failed_stage: Optional[str]
    error: Optional[str]


class SimulationHistoryResponse(BaseModel):
    items: list[SimulationHistoryItem]
    total: int
    limit: int
    offset: int


class SimulationStatistics(BaseModel):
    total_simulations: int
    successful_attacks: int
    outcomes: dict[str, int]


def get_repository(db: Session = Depends(get_db)) -> SimulationRepository:
    return SimulationRepository(db)


async def get_simulation_service():
    """Build request-scoped model clients only for simulation-run requests."""

    attacker = None
    try:
        try:
            attacker = AttackerAgent()
        except Exception as exc:
            # Still create a service so this component failure becomes a
            # sanitized, persisted TARGET_ERROR result instead of disappearing.
            logger.warning("Simulation Attacker unavailable: %s", type(exc).__name__)
            attacker = _UnavailableAttacker()
        yield SimulationService(
            attacker=attacker,
            target=LocalTargetAgent(),
            defender_analyzer=analyze_prompt_hybrid,
        )
    finally:
        if attacker is not None and hasattr(attacker, "close"):
            try:
                await attacker.close()
            except Exception as exc:
                logger.warning("Could not close simulation Attacker client: %s", type(exc).__name__)


class _UnavailableAttacker:
    """Fail safely through the normal simulation-result path."""

    async def generate(self, attack_category):
        raise RuntimeError("Attacker model is not configured")


def _history_item(row: SimulationRunDB) -> SimulationHistoryItem:
    return SimulationHistoryItem(
        id=row.id,
        simulation_id=row.simulation_id,
        created_at=row.created_at,
        attack_category=row.attack_category,
        prompt=row.prompt,
        defender_decision=row.defender_decision,
        target_called=row.target_called,
        target_received_original_prompt=row.target_received_original_prompt,
        leakage_matches=json.loads(row.leakage_matches_json),
        attack_success=row.attack_success,
        outcome=row.outcome,
        success_criterion=row.success_criterion,
        sanitization_status=row.sanitization_status,
        failed_stage=row.failed_stage,
        error=row.error,
    )


@router.post("/run", response_model=SimulationRunRecord, status_code=201)
async def run_simulation(
    request: SimulationRequest,
    service: SimulationService = Depends(get_simulation_service),
    repo: SimulationRepository = Depends(get_repository),
) -> SimulationRunRecord:
    try:
        result = await service.run(request)
        row = repo.save(result, request.attack_category.value)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Simulation run failed with %s", type(exc).__name__)
        raise HTTPException(
            status_code=500,
            detail="Simulation could not be completed or saved.",
        ) from exc
    return SimulationRunRecord(id=row.id, created_at=row.created_at, result=result)


@router.get("/statistics", response_model=SimulationStatistics)
async def get_simulation_statistics(
    repo: SimulationRepository = Depends(get_repository),
) -> SimulationStatistics:
    try:
        return SimulationStatistics(**repo.statistics())
    except Exception as exc:
        logger.error("Simulation statistics failed with %s", type(exc).__name__)
        raise HTTPException(
            status_code=500,
            detail="Simulation statistics are unavailable.",
        ) from exc


@router.get("", response_model=SimulationHistoryResponse)
async def list_simulations(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    repo: SimulationRepository = Depends(get_repository),
) -> SimulationHistoryResponse:
    try:
        rows, total = repo.list_runs(limit=limit, offset=offset)
        return SimulationHistoryResponse(
            items=[_history_item(row) for row in rows],
            total=total,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:
        logger.error("Simulation history failed with %s", type(exc).__name__)
        raise HTTPException(
            status_code=500,
            detail="Simulation history is unavailable.",
        ) from exc


@router.get("/{simulation_id}", response_model=SimulationRunRecord)
async def get_simulation(
    simulation_id: str,
    repo: SimulationRepository = Depends(get_repository),
) -> SimulationRunRecord:
    try:
        row = repo.get_by_simulation_id(simulation_id)
    except Exception as exc:
        logger.error("Simulation lookup failed with %s", type(exc).__name__)
        raise HTTPException(
            status_code=500,
            detail="Simulation details are unavailable.",
        ) from exc
    if row is None:
        raise HTTPException(status_code=404, detail="Simulation was not found.")
    try:
        result = SimulationResponse.model_validate_json(row.result_json)
    except Exception as exc:
        logger.error("Stored simulation record is invalid (%s)", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Stored simulation record is unavailable.") from exc
    return SimulationRunRecord(id=row.id, created_at=row.created_at, result=result)
