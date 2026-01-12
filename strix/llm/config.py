import os

from strix.config import Config


# Check if using Claude SDK - matches the check in __init__.py
USE_CLAUDE_SDK = os.getenv("STRIX_USE_CLAUDE_SDK", "true").lower() == "true"

# Default model when using Claude SDK
CLAUDE_SDK_DEFAULT_MODEL = "claude-sonnet-4-20250514"


class LLMConfig:
    def __init__(
        self,
        model_name: str | None = None,
        enable_prompt_caching: bool = True,
        skills: list[str] | None = None,
        timeout: int | None = None,
        scan_mode: str = "deep",
    ):
        self.model_name = model_name or Config.get("strix_llm")

        # When using Claude SDK, we can default to a model if STRIX_LLM is not set
        if not self.model_name:
            if USE_CLAUDE_SDK:
                self.model_name = CLAUDE_SDK_DEFAULT_MODEL
            else:
                raise ValueError("STRIX_LLM environment variable must be set and not empty")

        self.enable_prompt_caching = enable_prompt_caching
        self.skills = skills or []

        self.timeout = timeout or int(Config.get("llm_timeout") or "300")

        self.scan_mode = scan_mode if scan_mode in ["quick", "standard", "deep"] else "deep"
