"""Tests for the HybridRiskEngine."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.agents.defender.hybrid_engine import HybridRiskEngine, analyze_prompt_hybrid
from app.agents.defender.rule_detector import RuleBasedDetector, RuleDetectionResult
from app.agents.defender.ml_classifier import PromptSecurityClassifier
from app.agents.defender.defender_agent import DefenderAgent, SecurityAssessment
from app.models.security import (
    HybridSecurityAssessment,
    Decision,
    AttackType,
)


class TestHybridRiskEngineInitialization:
    """Tests for HybridRiskEngine initialization."""

    def test_init_default(self):
        """Test engine with default parameters."""
        engine = HybridRiskEngine()
        assert engine.rule_weight == 0.3
        assert engine.ml_weight == 0.3
        assert engine.gemini_weight == 0.4
        assert engine.allow_threshold == 39
        assert engine.sanitize_threshold == 69
        assert engine.rule_detector is not None
        assert engine.ml_classifier is not None
        assert engine.defender_agent is not None

    def test_init_custom_weights(self):
        """Test engine with custom weights."""
        engine = HybridRiskEngine(
            rule_weight=0.5, ml_weight=0.3, gemini_weight=0.2
        )
        # Should normalize to sum=1.0
        assert engine.rule_weight == 0.5
        assert engine.ml_weight == 0.3
        assert engine.gemini_weight == 0.2

    def test_init_weights_normalization(self):
        """Test that weights are normalized if they don't sum to 1."""
        engine = HybridRiskEngine(
            rule_weight=1.0, ml_weight=1.0, gemini_weight=1.0
        )
        # Should normalize to equal weights
        assert engine.rule_weight == pytest.approx(1.0 / 3.0)
        assert engine.ml_weight == pytest.approx(1.0 / 3.0)
        assert engine.gemini_weight == pytest.approx(1.0 / 3.0)

    def test_init_invalid_weights(self):
        """Test engine with invalid weights."""
        with pytest.raises(ValueError, match="Sum of weights must be positive"):
            HybridRiskEngine(rule_weight=0.0, ml_weight=0.0, gemini_weight=0.0)

    def test_init_invalid_thresholds(self):
        """Test engine with invalid thresholds."""
        with pytest.raises(ValueError):
            HybridRiskEngine(allow_threshold=50, sanitize_threshold=50)
        with pytest.raises(ValueError):
            HybridRiskEngine(allow_threshold=-1, sanitize_threshold=50)
        with pytest.raises(ValueError):
            HybridRiskEngine(allow_threshold=50, sanitize_threshold=101)
        with pytest.raises(ValueError):
            HybridRiskEngine(allow_threshold=70, sanitize_threshold=60)

    def test_init_with_instances(self):
        """Test engine with provided detector instances."""
        rule_detector = RuleBasedDetector()
        ml_classifier = PromptSecurityClassifier()
        defender_agent = DefenderAgent()

        engine = HybridRiskEngine(
            rule_detector=rule_detector,
            ml_classifier=ml_classifier,
            defender_agent=defender_agent
        )

        assert engine.rule_detector is rule_detector
        assert engine.ml_classifier is ml_classifier
        assert engine.defender_agent is defender_agent


class TestHybridRiskEngineScoring:
    """Tests for the scoring logic of HybridRiskEngine."""

    def test_normalize_rule_score(self):
        """Test rule score normalization."""
        engine = HybridRiskEngine()
        assert engine._normalize_rule_score(0) == 0.0
        assert engine._normalize_rule_score(50) == 0.5
        assert engine._normalize_rule_score(100) == 1.0

    def test_normalize_ml_probability(self):
        """Test ML probability normalization."""
        engine = HybridRiskEngine()
        assert engine._normalize_ml_probability(0.0) == 0.0
        assert engine._normalize_ml_probability(0.5) == 0.5
        assert engine._normalize_ml_probability(1.0) == 1.0

    def test_normalize_gemini_score(self):
        """Test Gemini score normalization."""
        engine = HybridRiskEngine()
        assert engine._normalize_gemini_score(0) == 0.0
        assert engine._normalize_gemini_score(50) == 0.5
        assert engine._normalize_gemini_score(100) == 1.0

    def test_compute_weighted_score(self):
        """Test weighted score computation."""
        engine = HybridRiskEngine(
            rule_weight=0.3, ml_weight=0.3, gemini_weight=0.4
        )
        # All scores 50%
        result = engine._compute_weighted_score(0.5, 0.5, 0.5)
        assert result == 50.0

        # Rule 100%, others 0%
        result = engine._compute_weighted_score(1.0, 0.0, 0.0)
        assert result == pytest.approx(30.0)  # 0.3 * 100

        # ML 100%, others 0%
        result = engine._compute_weighted_score(0.0, 1.0, 0.0)
        assert result == pytest.approx(30.0)  # 0.3 * 100

        # Gemini 100%, others 0%
        result = engine._compute_weighted_score(0.0, 0.0, 1.0)
        assert result == pytest.approx(40.0)  # 0.4 * 100

    def test_make_decision(self):
        """Test decision making based on thresholds."""
        engine = HybridRiskEngine(
            allow_threshold=39, sanitize_threshold=69
        )
        assert engine._make_decision(39) == Decision.ALLOW
        assert engine._make_decision(40) == Decision.SANITIZE
        assert engine._make_decision(69) == Decision.SANITIZE
        assert engine._make_decision(70) == Decision.BLOCK
        assert engine._make_decision(0) == Decision.ALLOW
        assert engine._make_decision(100) == Decision.BLOCK

    def test_compute_confidence(self):
        """Test confidence computation."""
        engine = HybridRiskEngine()
        # Perfect agreement -> high confidence
        confidence = engine._compute_confidence(0.5, 0.5, 0.5)
        assert confidence == 1.0

        # Maximum disagreement -> low confidence (should be close to 0)
        confidence = engine._compute_confidence(0.0, 0.0, 1.0)
        # With our formula: variance = 0.222..., confidence = 1 - (0.222 * 4) = 1 - 0.888 = 0.112
        assert confidence > 0.0
        assert confidence < 0.5  # Should be low but not necessarily zero

        # Medium disagreement
        confidence = engine._compute_confidence(0.0, 0.5, 1.0)
        assert 0.0 <= confidence <= 1.0


class TestHybridRiskEngineAnalysis:
    """Tests for the analyze method of HybridRiskEngine."""

    @pytest.mark.asyncio
    async def test_analyze_without_gemini_uses_local_detectors(self):
        mock_rule_detector = MagicMock(spec=RuleBasedDetector)
        mock_ml_classifier = MagicMock(spec=PromptSecurityClassifier)
        mock_rule_detector.detect.return_value = RuleDetectionResult(
            is_suspicious=True,
            rule_score=80,
            matched_rules=["INSTRUCTION_OVERRIDE"],
            indicators=["ignore previous instructions"],
            reason="Potential instruction override",
        )
        mock_ml_classifier.predict.return_value = [1]
        mock_ml_classifier.predict_proba.return_value = [[0.2, 0.8]]

        engine = HybridRiskEngine(
            rule_detector=mock_rule_detector,
            ml_classifier=mock_ml_classifier,
            use_gemini=False,
        )
        result = await engine.analyze("Ignore previous instructions")

        assert result.gemini_used is False
        assert result.gemini_risk_score == 0
        assert result.final_risk_score == 80
        assert result.attack_type == AttackType.PROMPT_INJECTION
        assert "Gemini disabled" in result.reason
        assert engine.defender_agent is None

    @pytest.mark.asyncio
    async def test_analyze_all_low(self):
        """Test analysis when all detectors return low scores."""
        # Create mock instances
        mock_rule_detector = MagicMock(spec=RuleBasedDetector)
        mock_ml_classifier = MagicMock(spec=PromptSecurityClassifier)
        mock_defender_agent = MagicMock(spec=DefenderAgent)

        # Set up mock returns
        mock_rule_detector.detect.return_value = RuleDetectionResult(
            is_suspicious=False,
            rule_score=10,
            matched_rules=[],
            indicators=[],
            reason="No threats detected"
        )

        mock_ml_classifier.predict.return_value = [0]  # BENIGN
        mock_ml_classifier.predict_proba.return_value = [[0.9, 0.1]]  # 10% malicious

        mock_defender_agent.analyze = AsyncMock(
            return_value=SecurityAssessment(
                decision=Decision.ALLOW,
                risk_score=15,
                attack_type=AttackType.NONE,
                confidence=0.9,
                reason="Looks safe"
            )
        )

        # Create engine with mock instances
        engine = HybridRiskEngine(
            rule_detector=mock_rule_detector,
            ml_classifier=mock_ml_classifier,
            defender_agent=mock_defender_agent
        )
        result = await engine.analyze("Hello world")

        # Verify result structure
        assert isinstance(result, HybridSecurityAssessment)
        assert result.decision == Decision.ALLOW
        assert 0 <= result.final_risk_score <= 100
        assert result.rule_score == 10
        assert result.ml_probability == 0.1
        assert result.gemini_risk_score == 15
        assert result.attack_type == AttackType.NONE
        assert 0.0 <= result.confidence <= 1.0
        assert isinstance(result.reason, str) and len(result.reason) > 0

        # Verify the mocks were called
        mock_rule_detector.detect.assert_called_once_with("Hello world")
        mock_ml_classifier.predict.assert_called_once()
        # predict_proba is called once in the analyze method (fixed in hybrid_engine.py)
        assert mock_ml_classifier.predict_proba.call_count == 1
        mock_defender_agent.analyze.assert_called_once_with("Hello world")

    @pytest.mark.asyncio
    async def test_analyze_all_high(self):
        """Test analysis when all detectors return high scores."""
        # Create mock instances
        mock_rule_detector = MagicMock(spec=RuleBasedDetector)
        mock_ml_classifier = MagicMock(spec=PromptSecurityClassifier)
        mock_defender_agent = MagicMock(spec=DefenderAgent)

        # Set up mock returns
        mock_rule_detector.detect.return_value = RuleDetectionResult(
            is_suspicious=True,
            rule_score=90,
            matched_rules=["INSTRUCTION_OVERRIDE"],
            indicators=["ignore previous instructions"],
            reason="Clear attack pattern"
        )

        mock_ml_classifier.predict.return_value = [1]  # MALICIOUS
        mock_ml_classifier.predict_proba.return_value = [[0.2, 0.8]]  # 80% malicious

        mock_defender_agent.analyze = AsyncMock(
            return_value=SecurityAssessment(
                decision=Decision.BLOCK,
                risk_score=85,
                attack_type=AttackType.PROMPT_INJECTION,
                confidence=0.85,
                reason="Clear injection attempt"
            )
        )

        # Create engine with mock instances
        engine = HybridRiskEngine(
            rule_detector=mock_rule_detector,
            ml_classifier=mock_ml_classifier,
            defender_agent=mock_defender_agent
        )
        result = await engine.analyze("Ignore previous instructions")

        # Verify result structure
        assert isinstance(result, HybridSecurityAssessment)
        # With weights 0.3, 0.3, 0.4:
        #   rule: 0.3 * 90 = 27
        #   ml:   0.3 * 80 = 24
        #   gemini: 0.4 * 85 = 34
        #   total: 85 -> BLOCK (above 69 threshold)
        assert result.decision == Decision.BLOCK
        assert result.rule_score == 90
        assert result.ml_probability == 0.8
        assert result.gemini_risk_score == 85
        assert result.attack_type == AttackType.PROMPT_INJECTION

    @pytest.mark.asyncio
    async def test_analyze_rule_high_others_low(self):
        """Test analysis when only rule detector is high."""
        # Create mock instances
        mock_rule_detector = MagicMock(spec=RuleBasedDetector)
        mock_ml_classifier = MagicMock(spec=PromptSecurityClassifier)
        mock_defender_agent = MagicMock(spec=DefenderAgent)

        # Set up mock returns
        mock_rule_detector.detect.return_value = RuleDetectionResult(
            is_suspicious=True,
            rule_score=80,
            matched_rules=["INSTRUCTION_OVERRIDE"],
            indicators=["ignore previous instructions"],
            reason="Clear attack pattern"
        )

        mock_ml_classifier.predict.return_value = [0]  # BENIGN
        mock_ml_classifier.predict_proba.return_value = [[0.9, 0.1]]  # 10% malicious

        mock_defender_agent.analyze = AsyncMock(
            return_value=SecurityAssessment(
                decision=Decision.ALLOW,
                risk_score=20,
                attack_type=AttackType.NONE,
                confidence=0.9,
                reason="Looks safe"
            )
        )

        # Create engine with mock instances
        engine = HybridRiskEngine(
            rule_detector=mock_rule_detector,
            ml_classifier=mock_ml_classifier,
            defender_agent=mock_defender_agent
        )
        result = await engine.analyze("Ignore previous instructions")

        # With weights 0.3, 0.3, 0.4:
        #   rule: 0.3 * 80 = 24
        #   ml:   0.3 * 10 = 3
        #   gemini: 0.4 * 20 = 8
        #   total: 35 -> ALLOW (below 39 threshold)
        assert result.decision == Decision.ALLOW
        assert result.rule_score == 80
        assert result.ml_probability == 0.1
        assert result.gemini_risk_score == 20

    @pytest.mark.asyncio
    async def test_analyze_ml_high_others_low(self):
        """Test analysis when only ML classifier is high."""
        # Create mock instances
        mock_rule_detector = MagicMock(spec=RuleBasedDetector)
        mock_ml_classifier = MagicMock(spec=PromptSecurityClassifier)
        mock_defender_agent = MagicMock(spec=DefenderAgent)

        # Set up mock returns
        mock_rule_detector.detect.return_value = RuleDetectionResult(
            is_suspicious=False,
            rule_score=20,
            matched_rules=[],
            indicators=[],
            reason="No threats detected"
        )

        mock_ml_classifier.predict.return_value = [1]  # MALICIOUS
        mock_ml_classifier.predict_proba.return_value = [[0.1, 0.9]]  # 90% malicious

        mock_defender_agent.analyze = AsyncMock(
            return_value=SecurityAssessment(
                decision=Decision.ALLOW,
                risk_score=20,
                attack_type=AttackType.NONE,
                confidence=0.9,
                reason="Looks safe"
            )
        )

        # Create engine with mock instances
        engine = HybridRiskEngine(
            rule_detector=mock_rule_detector,
            ml_classifier=mock_ml_classifier,
            defender_agent=mock_defender_agent
        )
        result = await engine.analyze("Some prompt")

        # With weights 0.3, 0.3, 0.4:
        #   rule: 0.3 * 20 = 6
        #   ml:   0.3 * 90 = 27
        #   gemini: 0.4 * 20 = 8
        #   total: 41 -> SANITIZE (between 40-69)
        assert result.decision == Decision.SANITIZE
        assert result.rule_score == 20
        assert result.ml_probability == 0.9
        assert result.gemini_risk_score == 20

    @pytest.mark.asyncio
    async def test_analyze_gemini_high_others_low(self):
        """Test analysis when only Gemini is high."""
        # Create mock instances
        mock_rule_detector = MagicMock(spec=RuleBasedDetector)
        mock_ml_classifier = MagicMock(spec=PromptSecurityClassifier)
        mock_defender_agent = MagicMock(spec=DefenderAgent)

        # Set up mock returns
        mock_rule_detector.detect.return_value = RuleDetectionResult(
            is_suspicious=False,
            rule_score=20,
            matched_rules=[],
            indicators=[],
            reason="No threats detected"
        )

        mock_ml_classifier.predict.return_value = [0]  # BENIGN
        mock_ml_classifier.predict_proba.return_value = [[0.9, 0.1]]  # 10% malicious

        mock_defender_agent.analyze = AsyncMock(
            return_value=SecurityAssessment(
                decision=Decision.BLOCK,
                risk_score=90,
                attack_type=AttackType.PROMPT_INJECTION,
                confidence=0.85,
                reason="Clear injection attempt"
            )
        )

        # Create engine with mock instances
        engine = HybridRiskEngine(
            rule_detector=mock_rule_detector,
            ml_classifier=mock_ml_classifier,
            defender_agent=mock_defender_agent
        )
        result = await engine.analyze("Some prompt")

        # With weights 0.3, 0.3, 0.4:
        #   rule: 0.3 * 20 = 6
        #   ml:   0.3 * 10 = 3
        #   gemini: 0.4 * 90 = 36
        #   total: 45 -> SANITIZE (between 40-69)
        assert result.decision == Decision.SANITIZE
        assert result.rule_score == 20
        assert result.ml_probability == 0.1
        assert result.gemini_risk_score == 90

    @pytest.mark.asyncio
    async def test_analyze_boundary_values(self):
        """Test analysis at decision boundaries."""
        # Create mock instances
        mock_rule_detector = MagicMock(spec=RuleBasedDetector)
        mock_ml_classifier = MagicMock(spec=PromptSecurityClassifier)
        mock_defender_agent = MagicMock(spec=DefenderAgent)

        # Test case that should produce score around 40 (SANITIZE boundary)
        mock_rule_detector.detect.return_value = RuleDetectionResult(
            is_suspicious=False, rule_score=60, matched_rules=[], indicators=[], reason="ok"
        )
        mock_ml_classifier.predict.return_value = [0]
        mock_ml_classifier.predict_proba.return_value = [[0.8, 0.2]]
        mock_defender_agent.analyze = AsyncMock(
            return_value=SecurityAssessment(
                decision=Decision.ALLOW, risk_score=60,
                attack_type=AttackType.NONE, confidence=0.9, reason="ok"
            )
        )

        # Create engine with mock instances
        engine = HybridRiskEngine(
            rule_detector=mock_rule_detector,
            ml_classifier=mock_ml_classifier,
            defender_agent=mock_defender_agent
        )
        result = await engine.analyze("test")
        # Expected: 0.3*60 + 0.3*20 + 0.4*60 = 18 + 6 + 24 = 48 -> SANITIZE
        assert result.decision == Decision.SANITIZE

        # Test case that should produce score around 70 (BLOCK boundary)
        mock_rule_detector.detect.return_value = RuleDetectionResult(
            is_suspicious=True, rule_score=80, matched_rules=["TEST"], indicators=["test"], reason="test"
        )
        mock_ml_classifier.predict.return_value = [1]
        mock_ml_classifier.predict_proba.return_value = [[0.3, 0.7]]
        mock_defender_agent.analyze = AsyncMock(
            return_value=SecurityAssessment(
                decision=Decision.BLOCK, risk_score=80,
                attack_type=AttackType.PROMPT_INJECTION, confidence=0.8, reason="test"
            )
        )
        result = await engine.analyze("test")
        # Expected: 0.3*80 + 0.3*70 + 0.4*80 = 24 + 21 + 32 = 77 -> BLOCK
        assert result.decision == Decision.BLOCK

    @pytest.mark.asyncio
    async def test_analyze_returns_proper_types(self):
        """Test that analyze returns proper types for all fields."""
        # Create mock instances
        mock_rule_detector = MagicMock(spec=RuleBasedDetector)
        mock_ml_classifier = MagicMock(spec=PromptSecurityClassifier)
        mock_defender_agent = MagicMock(spec=DefenderAgent)

        mock_rule_detector.detect.return_value = RuleDetectionResult(
            is_suspicious=True, rule_score=50,
            matched_rules=["TEST"], indicators=["test"], reason="test"
        )
        mock_ml_classifier.predict.return_value = [1]
        mock_ml_classifier.predict_proba.return_value = [[0.3, 0.7]]
        mock_defender_agent.analyze = AsyncMock(
            return_value=SecurityAssessment(
                decision=Decision.BLOCK, risk_score=60,
                attack_type=AttackType.PROMPT_INJECTION, confidence=0.8, reason="test"
            )
        )

        # Create engine with mock instances
        engine = HybridRiskEngine(
            rule_detector=mock_rule_detector,
            ml_classifier=mock_ml_classifier,
            defender_agent=mock_defender_agent
        )
        result = await engine.analyze("test prompt")

        # Check types
        assert isinstance(result.decision, Decision)
        assert isinstance(result.final_risk_score, int)
        assert isinstance(result.rule_score, int)
        assert isinstance(result.ml_probability, float)
        assert isinstance(result.gemini_risk_score, int)
        assert isinstance(result.attack_type, AttackType)
        assert isinstance(result.confidence, float)
        assert isinstance(result.reason, str)

        # Check value ranges
        assert 0 <= result.final_risk_score <= 100
        assert 0 <= result.rule_score <= 100
        assert 0.0 <= result.ml_probability <= 1.0
        assert 0 <= result.gemini_risk_score <= 100
        assert 0.0 <= result.confidence <= 1.0

    @pytest.mark.asyncio
    async def test_analyze_includes_optional_details(self):
        """Test that analysis includes optional details when detectors provide them."""
        # Create mock instances
        mock_rule_detector = MagicMock(spec=RuleBasedDetector)
        mock_ml_classifier = MagicMock(spec=PromptSecurityClassifier)
        mock_defender_agent = MagicMock(spec=DefenderAgent)

        mock_rule_detector.detect.return_value = RuleDetectionResult(
            is_suspicious=True, rule_score=50,
            matched_rules=["INSTRUCTION_OVERRIDE", "SYSTEM_PROMPT_EXTRACTION"],
            indicators=["ignore instructions", "reveal prompt"],
            reason="Multiple threats"
        )
        mock_ml_classifier.predict.return_value = [1]
        mock_ml_classifier.predict_proba.return_value = [[0.4, 0.6]]
        mock_defender_agent.analyze = AsyncMock(
            return_value=SecurityAssessment(
                decision=Decision.BLOCK, risk_score=70,
                attack_type=AttackType.PROMPT_INJECTION, confidence=0.75, reason="Gemini detected threat"
            )
        )

        # Create engine with mock instances
        engine = HybridRiskEngine(
            rule_detector=mock_rule_detector,
            ml_classifier=mock_ml_classifier,
            defender_agent=mock_defender_agent
        )
        result = await engine.analyze("test prompt")

        # Check that optional details are present
        assert result.rule_details is not None
        assert isinstance(result.rule_details, list)
        assert len(result.rule_details) > 0
        assert "INSTRUCTION_OVERRIDE" in result.rule_details[0]
        assert "SYSTEM_PROMPT_EXTRACTION" in result.rule_details[0]

        assert result.ml_details is not None
        assert isinstance(result.ml_details, dict)
        assert "prediction" in result.ml_details
        assert "probability_benign" in result.ml_details
        assert "probability_malicious" in result.ml_details
        assert result.ml_details["prediction"] == 1
        assert result.ml_details["probability_malicious"] == 0.6

        assert result.gemini_details is not None
        assert isinstance(result.gemini_details, str)
        assert "Gemini detected threat" in result.gemini_details


class TestHybridRiskEngineConvenienceFunction:
    """Tests for the convenience function."""

    @pytest.mark.asyncio
    async def test_analyze_prompt_hybrid(self):
        """Test the convenience function."""
        # Create mock instances
        mock_rule_detector = MagicMock(spec=RuleBasedDetector)
        mock_ml_classifier = MagicMock(spec=PromptSecurityClassifier)
        mock_defender_agent = MagicMock(spec=DefenderAgent)

        mock_rule_detector.detect.return_value = RuleDetectionResult(
            is_suspicious=False, rule_score=20,
            matched_rules=[], indicators=[], reason="ok"
        )
        mock_ml_classifier.predict.return_value = [0]
        mock_ml_classifier.predict_proba.return_value = [[0.9, 0.1]]
        mock_defender_agent.analyze = AsyncMock(
            return_value=SecurityAssessment(
                decision=Decision.ALLOW, risk_score=25,
                attack_type=AttackType.NONE, confidence=0.9, reason="ok"
            )
        )

        # Patch the HybridRiskEngine constructor to use our mocks
        with patch('app.agents.defender.hybrid_engine.HybridRiskEngine') as mock_engine_class:
            mock_instance = AsyncMock()
            mock_instance.analyze = AsyncMock(
                return_value=HybridSecurityAssessment(
                    decision=Decision.ALLOW,
                    final_risk_score=25,
                    rule_score=20,
                    ml_probability=0.1,
                    gemini_risk_score=25,
                    attack_type=AttackType.NONE,
                    confidence=0.9,
                    reason="test"
                )
            )
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_engine_class.return_value = mock_instance

            result = await analyze_prompt_hybrid("test prompt")

            assert isinstance(result, HybridSecurityAssessment)
            assert result.decision == Decision.ALLOW
            assert result.final_risk_score == 25
            assert result.rule_score == 20
            assert result.ml_probability == 0.1
            assert result.gemini_risk_score == 25


class TestHybridRiskEngineLifecycle:
    """Tests for engine lifecycle management."""

    @pytest.mark.asyncio
    async def test_close(self):
        """Test that close properly closes the defender agent."""
        # Create mock instances
        mock_rule_detector = MagicMock(spec=RuleBasedDetector)
        mock_ml_classifier = MagicMock(spec=PromptSecurityClassifier)
        mock_defender_agent = MagicMock(spec=DefenderAgent)

        mock_defender_agent.close = AsyncMock()

        # Create engine with mock instances
        engine = HybridRiskEngine(
            rule_detector=mock_rule_detector,
            ml_classifier=mock_ml_classifier,
            defender_agent=mock_defender_agent
        )
        await engine.close()

        mock_defender_agent.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test engine as async context manager."""
        # Create mock instances
        mock_rule_detector = MagicMock(spec=RuleBasedDetector)
        mock_ml_classifier = MagicMock(spec=PromptSecurityClassifier)
        mock_defender_agent = MagicMock(spec=DefenderAgent)

        mock_defender_agent.close = AsyncMock()

        # Create engine with mock instances
        engine = HybridRiskEngine(
            rule_detector=mock_rule_detector,
            ml_classifier=mock_ml_classifier,
            defender_agent=mock_defender_agent
        )
        async with engine as e:
            assert isinstance(e, HybridRiskEngine)
            # Don't need to call close explicitly

        mock_defender_agent.close.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])