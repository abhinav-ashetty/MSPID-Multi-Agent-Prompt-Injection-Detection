"""Offline tests for simulation API and SQLite persistence."""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.agents.attacker.attacker_agent import (
    AttackCategory,
    AttackSeverity,
    AttackTestCase,
)
from app.api.simulation import get_repository, get_simulation_service
from app.api import simulation as simulation_api
from app.database.database import Base, get_db
from app.main import create_app
from app.models.security import AttackType, Decision, HybridSecurityAssessment
from app.models.simulation import (
    LeakageMatch,
    SimulationOutcome,
    SimulationRequest,
    SimulationResponse,
    SuccessCriterion,
    TargetResponse,
)


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(autocommit=False, autoflush=False, bind=engine)()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture
def simulation_result():
    attack = AttackTestCase(
        attack_id="attack-api-test",
        category=AttackCategory.PROMPT_INJECTION,
        prompt="Controlled test prompt",
        severity=AttackSeverity.HIGH,
        description="Offline fixture",
    )
    assessment = HybridSecurityAssessment(
        decision=Decision.ALLOW,
        final_risk_score=25,
        rule_score=10,
        ml_probability=0.2,
        gemini_risk_score=30,
        attack_type=AttackType.NONE,
        confidence=0.9,
        reason="Offline fixture assessment",
    )
    return SimulationResponse(
        simulation_id="simulation-api-test",
        outcome=SimulationOutcome.LEAKED,
        attack=attack,
        defender_assessment=assessment,
        defender_decision=Decision.ALLOW,
        target_called=True,
        target_received_original_prompt=True,
        target_response=TargetResponse(
            response="CANARY-SECRET",
            target_name="fake-target",
        ),
        leakage_matches=[LeakageMatch(canary="CANARY-SECRET", match_type="EXACT")],
        attack_success=True,
        success_criterion=SuccessCriterion.PROTECTED_CANARY_MATCH,
    )


@pytest.fixture
def client(db_session, simulation_result):
    app = create_app()
    service = AsyncMock()
    service.run.return_value = simulation_result
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_simulation_service] = lambda: service
    # Keep application startup from touching the developer's SQLite file.
    with patch("app.database.database.create_tables"):
        with TestClient(app) as test_client:
            yield test_client, service, db_session
    app.dependency_overrides.clear()


def test_run_simulation_persists_complete_result(client):
    test_client, service, db_session = client
    from app.database.repository import SecurityAssessmentDB

    assessment = SecurityAssessmentDB(
        prompt="Existing assessment prompt",
        decision="ALLOW",
        final_risk_score=5,
        rule_score=0,
        ml_probability=0.01,
        gemini_risk_score=5,
        attack_type="NONE",
        confidence=0.9,
        reason="Existing assessment",
    )
    db_session.add(assessment)
    db_session.commit()
    existing_assessment_id = assessment.id

    response = test_client.post(
        "/api/v1/simulations/run",
        json={
            "attack_category": "PROMPT_INJECTION",
            "protected_canaries": ["CANARY-SECRET"],
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["result"]["outcome"] == "LEAKED"
    assert body["result"]["attack_success"] is True
    service.run.assert_awaited_once()

    from app.database.simulation_repository import SimulationRunDB

    row = db_session.query(SimulationRunDB).one()
    assert row.attack_category == "PROMPT_INJECTION"
    assert row.prompt == "Controlled test prompt"
    assert row.defender_decision == "ALLOW"
    assert row.target_called is True
    assert row.attack_success is True
    assert row.outcome == "LEAKED"
    assert row.created_at is not None
    assert "CANARY-SECRET" in row.leakage_matches_json
    preserved_assessment = db_session.query(SecurityAssessmentDB).one()
    assert preserved_assessment.id == existing_assessment_id
    assert preserved_assessment.prompt == "Existing assessment prompt"


def test_history_detail_pagination_and_statistics(client):
    test_client, _, _ = client
    test_client.post(
        "/api/v1/simulations/run",
        json={"attack_category": "PROMPT_INJECTION", "protected_canaries": []},
    )

    listed = test_client.get("/api/v1/simulations?limit=1&offset=0")
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert listed.json()["items"][0]["outcome"] == "LEAKED"

    detail = test_client.get("/api/v1/simulations/simulation-api-test")
    assert detail.status_code == 200
    assert detail.json()["result"]["attack"]["prompt"] == "Controlled test prompt"

    stats = test_client.get("/api/v1/simulations/statistics")
    assert stats.status_code == 200
    assert stats.json() == {
        "total_simulations": 1,
        "successful_attacks": 1,
        "outcomes": {
            "PREVENTED": 0,
            "LEAKED": 1,
            "NO_LEAK": 0,
            "TARGET_ERROR": 0,
        },
    }


def test_unknown_simulation_returns_not_found(client):
    response = client[0].get("/api/v1/simulations/unknown")

    assert response.status_code == 404
    assert response.json()["detail"] == "Simulation was not found."


def test_invalid_simulation_request_is_rejected(client):
    test_client, service, _ = client

    response = test_client.post(
        "/api/v1/simulations/run",
        json={"attack_category": "NOT_A_CATEGORY"},
    )

    assert response.status_code == 422
    service.run.assert_not_awaited()


def test_component_failure_is_persisted_without_internal_details(client):
    test_client, service, db_session = client
    service.run.return_value = SimulationResponse(
        simulation_id="simulation-error-test",
        outcome=SimulationOutcome.TARGET_ERROR,
        success_criterion=SuccessCriterion.PROTECTED_CANARY_MATCH,
        failed_stage="attacker",
        error="Attacker failed to produce a valid test case.",
    )

    response = test_client.post(
        "/api/v1/simulations/run",
        json={"attack_category": "ROLE_MANIPULATION"},
    )

    assert response.status_code == 201
    from app.database.simulation_repository import SimulationRunDB

    row = db_session.query(SimulationRunDB).one()
    assert row.outcome == "TARGET_ERROR"
    assert row.attack_category == "ROLE_MANIPULATION"
    assert row.prompt is None
    assert row.error == "Attacker failed to produce a valid test case."


def test_unhandled_service_exception_returns_generic_error(client):
    test_client, service, _ = client
    service.run.side_effect = RuntimeError("GEMINI_API_KEY=private-value")

    response = test_client.post(
        "/api/v1/simulations/run",
        json={"attack_category": "ROLE_MANIPULATION"},
    )

    assert response.status_code == 500
    assert response.json() == {"detail": "Simulation could not be completed or saved."}
    assert "private-value" not in response.text


@pytest.mark.asyncio
async def test_missing_attacker_configuration_becomes_sanitized_result():
    with patch.object(
        simulation_api,
        "AttackerAgent",
        side_effect=ValueError("GEMINI_API_KEY=private-value"),
    ):
        dependency = simulation_api.get_simulation_service()
        service = await dependency.__anext__()
        result = await service.run(
            SimulationRequest(attack_category=AttackCategory.PROMPT_INJECTION)
        )
        await dependency.aclose()

    assert result.outcome == SimulationOutcome.TARGET_ERROR
    assert result.failed_stage == "attacker"
    assert "private-value" not in (result.error or "")


@pytest.mark.parametrize(
    ("method_name", "path", "expected_detail"),
    [
        ("statistics", "/api/v1/simulations/statistics", "Simulation statistics are unavailable."),
        ("list_runs", "/api/v1/simulations", "Simulation history is unavailable."),
        ("get_by_simulation_id", "/api/v1/simulations/run-1", "Simulation details are unavailable."),
    ],
)
def test_read_endpoint_failures_return_safe_errors(client, method_name, path, expected_detail):
    test_client = client[0]
    with patch.object(
        simulation_api.SimulationRepository,
        method_name,
        side_effect=RuntimeError("GEMINI_API_KEY=private-value"),
    ):
        response = test_client.get(path)

    assert response.status_code == 500
    assert response.json() == {"detail": expected_detail}
    assert "private-value" not in response.text
