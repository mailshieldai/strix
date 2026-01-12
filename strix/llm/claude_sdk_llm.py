"""
Claude Agent SDK LLM Adapter

This module provides an adapter that wraps the Claude Agent SDK to work with
Strix's existing LLM interface. It allows Strix to use Claude Code's authentication
and the latest Claude models while maintaining compatibility with the existing codebase.
"""

import logging
import os
from collections.abc import AsyncIterator
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from claude_agent_sdk import AssistantMessage, ClaudeAgentOptions, ClaudeSDKClient, TextBlock
from jinja2 import Environment, FileSystemLoader, select_autoescape

from strix.config import Config
from strix.llm.config import LLMConfig
from strix.llm.memory_compressor import MemoryCompressor
from strix.llm.utils import parse_tool_invocations
from strix.skills import load_skills
from strix.tools import get_tools_prompt


logger = logging.getLogger(__name__)

# Check for custom Anthropic base URL (for local proxy)
_ANTHROPIC_BASE_URL = Config.get("anthropic_base_url")
if _ANTHROPIC_BASE_URL:
    os.environ["ANTHROPIC_BASE_URL"] = _ANTHROPIC_BASE_URL
    logger.info(f"Using custom ANTHROPIC_BASE_URL: {_ANTHROPIC_BASE_URL}")


class LLMRequestFailedError(Exception):
    """Exception raised when LLM request fails."""

    def __init__(self, message: str, details: str | None = None):
        super().__init__(message)
        self.message = message
        self.details = details


class StepRole(str, Enum):
    AGENT = "agent"
    USER = "user"
    SYSTEM = "system"


@dataclass
class LLMResponse:
    """Response from LLM with tool invocations."""

    content: str
    tool_invocations: list[dict[str, Any]] | None = None
    scan_id: str | None = None
    step_number: int = 1
    role: StepRole = StepRole.AGENT
    thinking_blocks: list[dict[str, Any]] | None = None


@dataclass
class RequestStats:
    """Statistics for LLM requests."""

    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    cache_creation_tokens: int = 0
    cost: float = 0.0
    requests: int = 0
    failed_requests: int = 0

    def to_dict(self) -> dict[str, int | float]:
        """Convert stats to dictionary."""
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_tokens": self.cached_tokens,
            "cache_creation_tokens": self.cache_creation_tokens,
            "cost": round(self.cost, 4),
            "requests": self.requests,
            "failed_requests": self.failed_requests,
        }


class ClaudeSDKLLM:
    """
    LLM adapter that uses the Claude Agent SDK.

    This adapter maintains compatibility with Strix's existing LLM interface while
    using Claude Agent SDK under the hood. It supports:
    - Claude Code authentication (no API key needed if Claude Code is authenticated)
    - Latest Claude models (including Sonnet 4)
    - Continuous conversations with context management
    - Existing Strix tool ecosystem
    """

    def __init__(
        self, config: LLMConfig, agent_name: str | None = None, agent_id: str | None = None
    ):
        """
        Initialize the Claude SDK LLM adapter.

        Args:
            config: LLM configuration
            agent_name: Optional agent name for loading prompts
            agent_id: Optional agent ID for identity tracking
        """
        self.config = config
        self.agent_name = agent_name
        self.agent_id = agent_id
        self._total_stats = RequestStats()
        self._last_request_stats = RequestStats()

        self.memory_compressor = MemoryCompressor(
            model_name=self.config.model_name,
            timeout=self.config.timeout,
        )

        # Initialize Claude SDK client (will be created on first use)
        self._client: ClaudeSDKClient | None = None
        self._client_connected = False

        # Load system prompt
        if agent_name:
            prompt_dir = Path(__file__).parent.parent / "agents" / agent_name
            skills_dir = Path(__file__).parent.parent / "skills"

            loader = FileSystemLoader([prompt_dir, skills_dir])
            self.jinja_env = Environment(
                loader=loader,
                autoescape=select_autoescape(enabled_extensions=(), default_for_string=False),
            )

            try:
                skills_to_load = list(self.config.skills or [])
                skills_to_load.append(f"scan_modes/{self.config.scan_mode}")

                skill_content = load_skills(skills_to_load, self.jinja_env)

                def get_skill(name: str) -> str:
                    return skill_content.get(name, "")

                self.jinja_env.globals["get_skill"] = get_skill

                self.system_prompt = self.jinja_env.get_template("system_prompt.jinja").render(
                    get_tools_prompt=get_tools_prompt,
                    loaded_skill_names=list(skill_content.keys()),
                    **skill_content,
                )
            except (FileNotFoundError, OSError, ValueError) as e:
                logger.warning(f"Failed to load system prompt for {agent_name}: {e}")
                self.system_prompt = "You are a helpful AI assistant."
        else:
            self.system_prompt = "You are a helpful AI assistant."

    def set_agent_identity(self, agent_name: str | None, agent_id: str | None) -> None:
        """Set agent identity for message building."""
        if agent_name:
            self.agent_name = agent_name
        if agent_id:
            self.agent_id = agent_id

    def _get_claude_options(self) -> ClaudeAgentOptions:
        """
        Create Claude Agent SDK options.

        Returns:
            ClaudeAgentOptions configured for Strix
        """
        # Determine model name - default to claude-sonnet-4 if not set
        model_name = self.config.model_name or "claude-sonnet-4-20250514"

        # Map common model names to Claude SDK format
        model_mapping = {
            "claude-3-5-sonnet-20241022": "claude-sonnet-4-20250514",
            "claude-3-5-sonnet": "claude-sonnet-4-20250514",
            "claude-sonnet-3-5": "claude-sonnet-4-20250514",
            "claude-sonnet-4-5": "claude-sonnet-4-20250514",
            "claude-sonnet-4.5": "claude-sonnet-4-20250514",
            "sonnet": "claude-sonnet-4-20250514",
            "claude-opus-4": "claude-opus-4-20250514",
            "opus": "claude-opus-4-20250514",
        }

        # Strip provider prefix if present (e.g., "anthropic/claude-sonnet-4")
        if "/" in model_name:
            model_name = model_name.split("/")[-1]

        model_name = model_mapping.get(model_name, model_name)

        logger.info(f"Using Claude model: {model_name}")

        options = ClaudeAgentOptions(
            model=model_name,
            system_prompt=self.system_prompt,
            # Don't load filesystem settings by default for isolation
            setting_sources=None,
            # Allow all tools (Strix's tool system will handle permissions)
            allowed_tools=[],  # Empty means all tools are allowed
        )

        return options

    async def _ensure_client_connected(self) -> None:
        """Ensure the Claude SDK client is connected."""
        if not self._client_connected:
            if self._client is not None:
                try:
                    await self._client.disconnect()
                except Exception as e:  # noqa: BLE001
                    logger.debug(f"Error disconnecting old client: {e}")

            self._client = ClaudeSDKClient(options=self._get_claude_options())
            await self._client.connect()
            self._client_connected = True
            logger.debug("Claude SDK client connected")

    def _build_identity_message(self) -> dict[str, Any] | None:
        """Build identity message for agent."""
        if not (self.agent_name and str(self.agent_name).strip()):
            return None
        identity_name = self.agent_name
        identity_id = self.agent_id
        content = (
            "\n\n"
            "<agent_identity>\n"
            "<meta>Internal metadata: do not echo or reference; "
            "not part of history or tool calls.</meta>\n"
            "<note>You are now assuming the role of this agent. "
            "Act strictly as this agent and maintain self-identity for this step. "
            "Now go answer the next needed step!</note>\n"
            f"<agent_name>{identity_name}</agent_name>\n"
            f"<agent_id>{identity_id}</agent_id>\n"
            "</agent_identity>\n\n"
        )
        return {"role": "user", "content": content}

    async def generate(
        self,
        conversation_history: list[dict[str, Any]],
        scan_id: str | None = None,
        step_number: int = 1,
    ) -> AsyncIterator[LLMResponse]:
        """
        Generate LLM response using Claude Agent SDK.

        Args:
            conversation_history: List of conversation messages
            scan_id: Optional scan ID
            step_number: Current step number

        Yields:
            LLMResponse with content and optional tool invocations

        Raises:
            LLMRequestFailedError: If the request fails
        """
        try:
            # Ensure client is connected
            await self._ensure_client_connected()

            # Compress conversation history
            compressed_history = list(self.memory_compressor.compress_history(conversation_history))
            conversation_history.clear()
            conversation_history.extend(compressed_history)

            # Get the last user message
            last_user_message = ""
            for msg in reversed(compressed_history):
                if msg.get("role") == "user":
                    content = msg.get("content", "")
                    if isinstance(content, str):
                        last_user_message = content
                    elif isinstance(content, list):
                        # Handle content blocks
                        text_parts = [
                            block.get("text", "")
                            for block in content
                            if isinstance(block, dict) and block.get("type") == "text"
                        ]
                        last_user_message = "\n".join(text_parts)
                    break

            if not last_user_message:
                last_user_message = "Continue"

            # Add identity message if present
            identity_msg = self._build_identity_message()
            if identity_msg:
                last_user_message = identity_msg["content"] + "\n" + last_user_message

            logger.debug(f"Sending query to Claude SDK: {last_user_message[:100]}...")

            # Send query to Claude SDK
            if self._client is None:
                raise LLMRequestFailedError("Claude SDK client not initialized")

            await self._client.query(last_user_message)
            self._total_stats.requests += 1
            self._last_request_stats = RequestStats(requests=1)

            # Collect response with streaming
            response_text = ""
            async for message in self._client.receive_response():
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            response_text += block.text

                            # Yield intermediate responses for streaming
                            yield LLMResponse(
                                scan_id=scan_id,
                                step_number=step_number,
                                role=StepRole.AGENT,
                                content=response_text,
                                tool_invocations=None,
                            )

            logger.debug(f"Received response from Claude SDK: {response_text[:100]}...")

            # Parse tool invocations from the final response
            tool_invocations = parse_tool_invocations(response_text)

            # Update stats (approximate values since SDK doesn't expose token counts directly)
            self._total_stats.input_tokens += len(last_user_message) // 4
            self._total_stats.output_tokens += len(response_text) // 4
            self._last_request_stats.input_tokens = len(last_user_message) // 4
            self._last_request_stats.output_tokens = len(response_text) // 4

            # Yield final response with tool invocations
            yield LLMResponse(
                scan_id=scan_id,
                step_number=step_number,
                role=StepRole.AGENT,
                content=response_text,
                tool_invocations=tool_invocations if tool_invocations else None,
            )

        except LLMRequestFailedError:
            raise
        except Exception as e:
            self._total_stats.failed_requests += 1
            self._last_request_stats.failed_requests = 1
            error_msg = f"Claude SDK request failed: {type(e).__name__}"
            logger.exception(error_msg)
            raise LLMRequestFailedError(error_msg, str(e)) from e

    @property
    def usage_stats(self) -> dict[str, dict[str, int | float]]:
        """Get usage statistics."""
        return {
            "total": self._total_stats.to_dict(),
            "last_request": self._last_request_stats.to_dict(),
        }

    def get_cache_config(self) -> dict[str, bool]:
        """Get cache configuration."""
        return {
            "enabled": True,  # Claude SDK handles caching automatically
            "supported": True,
        }

    async def cleanup(self) -> None:
        """Cleanup resources."""
        if self._client is not None and self._client_connected:
            try:
                await self._client.disconnect()
                self._client_connected = False
                logger.debug("Claude SDK client disconnected")
            except Exception as e:  # noqa: BLE001
                logger.debug(f"Error disconnecting client: {e}")
