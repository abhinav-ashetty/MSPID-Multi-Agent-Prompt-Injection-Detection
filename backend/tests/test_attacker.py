from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.agents.attacker.attacker_agent import (
    AttackCategory,
    AttackSeverity,
    AttackTestCase,
    AttackerAgent,
)


class ProviderUnavailable(Exception):
    status_code = 503


def test_local_fallback_creates_a_category_matched_attack() -> None:
    result = AttackerAgent.create_local_fallback(AttackCategory.PROMPT_INJECTION)

    assert result.category == AttackCategory.PROMPT_INJECTION
    assert result.severity == AttackSeverity.HIGH
    assert result.prompt.strip()
    assert "local fallback" in result.description.lower()


@pytest.mark.asyncio
async def test_generate_retries_provider_503(monkeypatch) -> None:
    agent = AttackerAgent.__new__(AttackerAgent)
    agent.agent = SimpleNamespace(
        run=AsyncMock(
            side_effect=[
                ProviderUnavailable(),
                ProviderUnavailable(),
                SimpleNamespace(messages=[SimpleNamespace(content="Generated test prompt")]),
            ]
        )
    )
    sleep = AsyncMock()
    monkeypatch.setattr("app.agents.attacker.attacker_agent.asyncio.sleep", sleep)

    result = await agent.generate(AttackCategory.PROMPT_INJECTION)

    assert result.prompt == "Generated test prompt"
    assert agent.agent.run.await_count == 3
    assert [call.args[0] for call in sleep.await_args_list] == [1, 2]


@pytest.mark.asyncio
async def test_generate_benign_attack() -> None:
    """Integration test: benign category should produce a valid AttackTestCase."""

    agent = AttackerAgent()
    try:
        result = await agent.generate(AttackCategory.BENIGN)
    finally:
        await agent.close()

    assert isinstance(result, AttackTestCase)
    assert result.category == AttackCategory.BENIGN
    assert isinstance(result.prompt, str)
    assert result.prompt.strip() != ""
    assert result.severity == AttackSeverity.LOW


@pytest.mark.asyncio
async def test_generate_prompt_injection_attack() -> None:
    """Integration test: prompt-injection category should produce a valid AttackTestCase."""

    agent = AttackerAgent()
    try:
        result = await agent.generate(AttackCategory.PROMPT_INJECTION)
    finally:
        await agent.close()

    assert isinstance(result, AttackTestCase)
    assert result.category == AttackCategory.PROMPT_INJECTION
    assert isinstance(result.prompt, str)
    assert result.prompt.strip() != ""
    assert result.severity == AttackSeverity.HIGH


@pytest.mark.asyncio
async def test_generate_instruction_conflict_attack() -> None:
    """Integration test: instruction-conflict category should produce a valid AttackTestCase."""

    agent = AttackerAgent()
    try:
        result = await agent.generate(AttackCategory.INSTRUCTION_CONFLICT)
    finally:
        await agent.close()

    assert isinstance(result, AttackTestCase)
    assert result.category == AttackCategory.INSTRUCTION_CONFLICT
    assert isinstance(result.prompt, str)
    assert result.prompt.strip() != ""
    assert result.severity == AttackSeverity.HIGH


@pytest.mark.asyncio
async def test_generate_role_manipulation_attack() -> None:
    """Integration test: role-manipulation category should produce a valid AttackTestCase."""

    agent = AttackerAgent()
    try:
        result = await agent.generate(AttackCategory.ROLE_MANIPULATION)
    finally:
        await agent.close()

    assert isinstance(result, AttackTestCase)
    assert result.category == AttackCategory.ROLE_MANIPULATION
    assert isinstance(result.prompt, str)
    assert result.prompt.strip() != ""
    assert result.severity == AttackSeverity.MEDIUM


@pytest.mark.asyncio
async def test_generate_system_prompt_extraction_attack() -> None:
    """Integration test: system-prompt-extraction category should produce a valid AttackTestCase."""

    agent = AttackerAgent()
    try:
        result = await agent.generate(AttackCategory.SYSTEM_PROMPT_EXTRACTION)
    finally:
        await agent.close()

    assert isinstance(result, AttackTestCase)
    assert result.category == AttackCategory.SYSTEM_PROMPT_EXTRACTION
    assert isinstance(result.prompt, str)
    assert result.prompt.strip() != ""
    assert result.severity == AttackSeverity.HIGH


@pytest.mark.asyncio
async def test_generate_sensitive_information_request_attack() -> None:
    """Integration test: sensitive-information-request category should produce a valid AttackTestCase."""

    agent = AttackerAgent()
    try:
        result = await agent.generate(AttackCategory.SENSITIVE_INFORMATION_REQUEST)
    finally:
        await agent.close()

    assert isinstance(result, AttackTestCase)
    assert result.category == AttackCategory.SENSITIVE_INFORMATION_REQUEST
    assert isinstance(result.prompt, str)
    assert result.prompt.strip() != ""
    assert result.severity == AttackSeverity.HIGH
