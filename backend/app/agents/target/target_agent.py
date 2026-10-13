"""Target Agent protocol and deterministic local implementation."""

from typing import Protocol

from app.models.simulation import TargetRequest, TargetResponse


class TargetAgent(Protocol):
    """Interface implemented by any AIShield simulation target."""

    async def run(self, request: TargetRequest) -> TargetResponse:
        """Process one prompt and return a structured response."""


class LocalTargetAgent:
    """Deterministic target stub for offline development and tests."""

    def __init__(self, response: str = "Local target response.") -> None:
        self.response = response

    async def run(self, request: TargetRequest) -> TargetResponse:
        """Return the configured response without network or model calls."""

        return TargetResponse(
            response=self.response,
            target_name="local-test-target",
            metadata={"simulation_id": request.simulation_id},
        )
