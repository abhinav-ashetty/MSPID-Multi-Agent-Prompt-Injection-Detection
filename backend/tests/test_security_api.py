"""Tests for the security API endpoints."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import create_app
from app.database.database import Base, get_db
from app.models.security import HybridSecurityAssessment, Decision, AttackType


@pytest.fixture
def client(db_session):
    """Create a test client."""
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def db_session():
    """Create a fresh database session for each test."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def mock_hybrid_assessment():
    """Create a mock HybridSecurityAssessment for testing."""
    return HybridSecurityAssessment(
        decision=Decision.ALLOW,
        final_risk_score=25,
        rule_score=10,
        ml_probability=0.2,
        gemini_risk_score=30,
        attack_type=AttackType.NONE,
        confidence=0.9,
        reason="This is a safe prompt",
        rule_details=["No suspicious patterns detected"],
        ml_details={"feature1": 0.5, "feature2": 0.3},
        gemini_details="Gemini determined this is safe"
    )


def test_analyze_prompt_valid(client, mock_hybrid_assessment):
    """Test POST /analyze with valid prompt."""
    with patch('app.api.security.analyze_prompt_hybrid', 
               return_value=mock_hybrid_assessment) as mock_analyze:
        response = client.post(
            "/api/v1/security/analyze",
            json={"prompt": "Hello, how are you?"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["id"] is not None
        assert data["prompt"] == "Hello, how are you?"
        assert data["decision"] == Decision.ALLOW.value
        assert data["final_risk_score"] == 25
        assert data["rule_score"] == 10
        assert data["ml_probability"] == 0.2
        assert data["gemini_risk_score"] == 30
        assert data["attack_type"] == AttackType.NONE.value
        assert data["confidence"] == 0.9
        assert data["reason"] == "This is a safe prompt"
        
        # Verify the hybrid engine was called
        mock_analyze.assert_called_once_with("Hello, how are you?", use_gemini=True)


def test_analyze_prompt_can_disable_gemini(client, mock_hybrid_assessment):
    local_assessment = mock_hybrid_assessment.model_copy(
        update={"gemini_used": False, "gemini_risk_score": 0}
    )
    with patch(
        'app.api.security.analyze_prompt_hybrid',
        return_value=local_assessment,
    ) as mock_analyze:
        response = client.post(
            "/api/v1/security/analyze",
            json={"prompt": "Hello, how are you?", "use_gemini": False},
        )

    assert response.status_code == 200
    assert response.json()["gemini_used"] is False
    assert response.json()["gemini_risk_score"] == 0
    mock_analyze.assert_called_once_with("Hello, how are you?", use_gemini=False)


def test_analyze_prompt_reports_provider_503_as_temporary_unavailability(client):
    class ProviderUnavailable(Exception):
        status_code = 503

    with patch(
        'app.api.security.analyze_prompt_hybrid',
        side_effect=ProviderUnavailable("provider overloaded"),
    ):
        response = client.post(
            "/api/v1/security/analyze",
            json={"prompt": "Test prompt"},
        )

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "The security analysis provider is temporarily unavailable. Please retry shortly."
    )


def test_analyze_prompt_reports_invalid_gemini_credentials(client):
    class ProviderAuthenticationError(Exception):
        status_code = 401

    with patch(
        'app.api.security.analyze_prompt_hybrid',
        side_effect=ProviderAuthenticationError("invalid credentials"),
    ):
        response = client.post(
            "/api/v1/security/analyze",
            json={"prompt": "Test prompt"},
        )

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "Gemini rejected the configured credentials. Set GEMINI_API_KEY to a valid "
        "Gemini API key from Google AI Studio, then restart the backend."
    )


def test_analyze_prompt_reports_provider_429_as_quota_exhaustion(client):
    class ProviderRateLimited(Exception):
        status_code = 429

    with patch(
        'app.api.security.analyze_prompt_hybrid',
        side_effect=ProviderRateLimited("quota exceeded"),
    ):
        response = client.post(
            "/api/v1/security/analyze",
            json={"prompt": "Test prompt"},
        )

    assert response.status_code == 429
    assert response.json()["detail"] == (
        "The Gemini API quota or rate limit has been exceeded. "
        "Please wait before retrying or check your Gemini API quota and billing."
    )


def test_analyze_prompt_empty(client):
    """Test POST /analyze with empty prompt."""
    response = client.post(
        "/api/v1/security/analyze",
        json={"prompt": ""}
    )
    
    assert response.status_code == 422
    assert "Prompt cannot be empty" in response.json()["detail"]


def test_analyze_prompt_whitespace_only(client):
    """Test POST /analyze with whitespace-only prompt."""
    response = client.post(
        "/api/v1/security/analyze",
        json={"prompt": "   \t\n  "}
    )
    
    assert response.status_code == 422
    assert "Prompt cannot be empty" in response.json()["detail"]


def test_analyze_prompt_too_long(client):
    """Test POST /analyze with excessively long prompt."""
    long_prompt = "x" * 10001
    response = client.post(
        "/api/v1/security/analyze",
        json={"prompt": long_prompt}
    )
    
    assert response.status_code == 422
    assert "Prompt too long" in response.json()["detail"]


def test_get_assessment_by_id(client, mock_hybrid_assessment):
    """Test GET /assessments/{assessment_id}."""
    with patch('app.api.security.analyze_prompt_hybrid', 
               return_value=mock_hybrid_assessment):
        # First create an assessment
        create_response = client.post(
            "/api/v1/security/analyze",
            json={"prompt": "Test prompt"}
        )
        assert create_response.status_code == 200
        assessment_id = create_response.json()["id"]
        
        # Then retrieve it
        get_response = client.get(f"/api/v1/security/assessments/{assessment_id}")
        assert get_response.status_code == 200
        data = get_response.json()
        assert data["id"] == assessment_id
        assert data["prompt"] == "Test prompt"


def test_get_assessment_not_found(client):
    """Test GET /assessments/{assessment_id} with non-existent ID."""
    response = client.get("/api/v1/security/assessments/99999")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]
