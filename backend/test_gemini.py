"""Test script to verify Google Gemini connectivity via AutoGen OpenAIChatCompletionClient.

This script:
1. Loads environment variables from backend/.env
2. Uses GEMINI_API_KEY and GEMINI_MODEL from environment
3. Creates an OpenAIChatCompletionClient configured for Gemini
4. Makes a minimal test request
5. Prints the response to verify connectivity

Run from backend/ directory:
    python test_gemini.py

Prerequisites:
    - Copy .env.example to .env and add your GEMINI_API_KEY and GEMINI_MODEL
    - pip install openai (required by OpenAIChatCompletionClient)
"""

import asyncio
import os
import sys
from pathlib import Path


# Add backend to path for imports
BACKEND_DIR = Path(__file__).parent
sys.path.insert(0, str(BACKEND_DIR))

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(BACKEND_DIR / ".env")

from autogen_core.models import ModelFamily, UserMessage
from autogen_ext.models.openai import OpenAIChatCompletionClient


async def test_gemini_connection() -> bool:
    """Test Gemini connectivity via AutoGen's OpenAIChatCompletionClient."""

    # Get configuration from environment
    api_key = os.getenv("GEMINI_API_KEY")
    model = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")

    if not api_key:
        print("ERROR: GEMINI_API_KEY not set in environment")
        print("Please copy .env.example to .env and add your GEMINI_API_KEY")
        return False

    print(f"Testing Gemini connection...")
    print(f"Model: {model}")
    print("API key: configured (value hidden)")
    print("-" * 50)

    # Provide explicit model_info because AutoGen's model catalog may lag the selected Gemini model.
    model_info = {
        "vision": True,
        "function_calling": True,
        "json_output": True,
        "structured_output": True,
        "family": ModelFamily.GEMINI_2_5_FLASH,
        "multiple_system_messages": False,
    }

    # Create model client.
    # AutoGen automatically configures the Gemini OpenAI-compatible base URL
    # (https://generativelanguage.googleapis.com/v1beta/openai/)
    # when the model name starts with "gemini-".
    model_client = OpenAIChatCompletionClient(
        model=model,
        api_key=api_key,
        model_info=model_info,
    )

    try:
        # Make a minimal test request
        result = await model_client.create([
            UserMessage(content="Reply with exactly: Gemini connected", source="user")
        ])

        print(f"Response: {result.content}")
        print("-" * 50)
        print("SUCCESS: Gemini is reachable and responding!")
        return True

    except Exception as e:
        print(f"ERROR: {type(e).__name__}: {e}")
        return False

    finally:
        # Always close the client
        await model_client.close()


if __name__ == "__main__":
    success = asyncio.run(test_gemini_connection())
    sys.exit(0 if success else 1)
