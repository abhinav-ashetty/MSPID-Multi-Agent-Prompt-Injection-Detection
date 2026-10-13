"""Offline tests for protected-canary output detection."""

from app.agents.simulation.leakage_detector import LeakageDetector


def test_detects_exact_canary_match() -> None:
    matches = LeakageDetector().detect("Protected value: Canary-123", ["Canary-123"])

    assert [(match.canary, match.match_type) for match in matches] == [
        ("Canary-123", "EXACT")
    ]


def test_detects_normalized_case_and_whitespace_match() -> None:
    matches = LeakageDetector().detect("protected  value:  secret key", ["Secret Key"])

    assert [(match.canary, match.match_type) for match in matches] == [
        ("Secret Key", "NORMALIZED")
    ]


def test_ignores_empty_and_duplicate_canaries() -> None:
    matches = LeakageDetector().detect("nothing private here", ["", "  ", "token", "token"])

    assert matches == []
