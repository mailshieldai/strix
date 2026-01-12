import logging
import os
import warnings

import litellm

from .config import LLMConfig


logger = logging.getLogger(__name__)

# Check which LLM implementation to use
# Default to Claude SDK if available, fall back to LiteLLM if not installed
USE_CLAUDE_SDK = os.getenv("STRIX_USE_CLAUDE_SDK", "true").lower() == "true"

if USE_CLAUDE_SDK:
    try:
        # Try to use Claude Agent SDK (default)
        from .claude_sdk_llm import ClaudeSDKLLM as LLM
        from .claude_sdk_llm import LLMRequestFailedError

        logger.debug("Using Claude Agent SDK for LLM")
    except ImportError:
        # Fall back to LiteLLM if claude-agent-sdk not installed
        from .llm import LLM, LLMRequestFailedError

        logger.debug("Claude Agent SDK not installed, falling back to LiteLLM")
else:
    # Explicitly use LiteLLM
    from .llm import LLM, LLMRequestFailedError

    logger.debug("Using LiteLLM (STRIX_USE_CLAUDE_SDK=false)")


__all__ = [
    "LLM",
    "LLMConfig",
    "LLMRequestFailedError",
]

litellm._logging._disable_debugging()
logging.getLogger("asyncio").setLevel(logging.CRITICAL)
logging.getLogger("asyncio").propagate = False
warnings.filterwarnings("ignore", category=RuntimeWarning, module="asyncio")
