"""Provider-agnostic LLM client interface and implementations (Anthropic & OpenAI-compatible)."""

import asyncio
import json
import os
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import openai
from dotenv import load_dotenv

load_dotenv()


@dataclass
class ToolCallItem:
    """Standardized tool call emitted by an LLM."""

    id: str
    name: str
    arguments: Dict[str, Any]


@dataclass
class LLMResponse:
    """Standardized response from an LLM chat turn."""

    content: Optional[str] = None
    tool_calls: List[ToolCallItem] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    raw_message: Optional[Any] = None


class LLMClient(ABC):
    """Abstract interface for tool-calling chat completions."""

    @abstractmethod
    async def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        system_prompt: str,
    ) -> LLMResponse:
        """Execute a single turn of chat completion with tool schemas."""
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name of the provider (e.g., 'anthropic', 'openai_compatible')."""
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Model identifier."""
        pass


class AnthropicClient(LLMClient):
    """Anthropic Claude provider client."""

    def __init__(
        self,
        model: str = "claude-3-5-haiku-20241022",
        api_key: Optional[str] = None,
        max_retries: int = 3,
        base_backoff: float = 2.0,
    ) -> None:
        self._model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.max_retries = max_retries
        self.base_backoff = base_backoff

        if not self.api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY is not set in environment or .env. "
                "Configure ANTHROPIC_API_KEY or use --provider openai_compatible."
            )

        import anthropic
        self._client = anthropic.AsyncAnthropic(api_key=self.api_key)

    @property
    def provider_name(self) -> str:
        return "anthropic"

    @property
    def model_name(self) -> str:
        return self._model

    def _convert_tools(self, mcp_tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert MCP tool schemas into Anthropic tools format."""
        tools = []
        for t in mcp_tools:
            tools.append(
                {
                    "name": t["name"],
                    "description": t["description"],
                    "input_schema": t["inputSchema"],
                }
            )
        return tools

    async def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        system_prompt: str,
    ) -> LLMResponse:
        anthropic_tools = self._convert_tools(tools)
        # Filter out system message if in messages list since Anthropic accepts top-level system parameter
        chat_messages = [m for m in messages if m.get("role") != "system"]

        last_error = None
        for attempt in range(self.max_retries + 1):
            try:
                response = await self._client.messages.create(
                    model=self._model,
                    max_tokens=1024,
                    system=system_prompt,
                    messages=chat_messages,
                    tools=anthropic_tools,
                )

                tool_calls: List[ToolCallItem] = []
                text_content: Optional[str] = None

                text_blocks = [b.text for b in response.content if b.type == "text"]
                if text_blocks:
                    text_content = " ".join(text_blocks)

                for b in response.content:
                    if b.type == "tool_use":
                        tool_calls.append(
                            ToolCallItem(id=b.id, name=b.name, arguments=b.input)
                        )

                return LLMResponse(
                    content=text_content,
                    tool_calls=tool_calls,
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                    raw_message=response.content,
                )

            except Exception as err:
                last_error = err
                err_str = str(err).lower()
                is_rate_limit = "429" in err_str or "rate limit" in err_str or "overloaded" in err_str
                if attempt < self.max_retries and is_rate_limit:
                    sleep_time = self.base_backoff * (2**attempt) + random.uniform(0.1, 0.5)
                    await asyncio.sleep(sleep_time)
                else:
                    raise err

        raise last_error or RuntimeError("Anthropic chat request failed")


class OpenAICompatibleClient(LLMClient):
    """
    OpenAI-compatible client supporting Google Gemini, Groq, Ollama, etc.
    """

    def __init__(
        self,
        base_url: str = "https://generativelanguage.googleapis.com/v1beta/openai/",
        model: str = "gemini-2.5-flash",
        api_key_env_var: str = "GEMINI_API_KEY",
        api_key: Optional[str] = None,
        max_retries: int = 4,
        base_backoff: float = 2.0,
    ) -> None:
        self.base_url = base_url
        self._model = model
        self.api_key_env_var = api_key_env_var
        self.max_retries = max_retries
        self.base_backoff = base_backoff

        resolved_key = api_key or os.environ.get(api_key_env_var) or os.environ.get("OPENAI_API_KEY")
        if not resolved_key:
            # For local Ollama, allow dummy key
            if "localhost" in base_url or "127.0.0.1" in base_url:
                resolved_key = "ollama"
            else:
                raise ValueError(
                    f"API key for {api_key_env_var} not found in environment or .env. "
                    f"Please set {api_key_env_var} in .env."
                )

        self._client = openai.AsyncOpenAI(base_url=self.base_url, api_key=resolved_key)

    @property
    def provider_name(self) -> str:
        return "openai_compatible"

    @property
    def model_name(self) -> str:
        return self._model

    def _convert_tools(self, mcp_tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert MCP tool schemas into OpenAI tools format."""
        tools = []
        for t in mcp_tools:
            tools.append(
                {
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t["description"],
                        "parameters": t["inputSchema"],
                    },
                }
            )
        return tools

    async def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        system_prompt: str,
    ) -> LLMResponse:
        openai_tools = self._convert_tools(tools)

        # Ensure system prompt is first message if not already present
        chat_messages = []
        has_system = False
        for m in messages:
            role = m.get("role") if isinstance(m, dict) else getattr(m, "role", None)
            if role == "system":
                has_system = True
                chat_messages.append(m)
            else:
                chat_messages.append(m)

        if not has_system and system_prompt:
            chat_messages = [{"role": "system", "content": system_prompt}] + chat_messages

        last_error = None
        for attempt in range(self.max_retries + 1):
            try:
                response = await self._client.chat.completions.create(
                    model=self._model,
                    messages=chat_messages,
                    tools=openai_tools,
                    temperature=0.0,
                )

                choice = response.choices[0]
                message = choice.message

                tool_calls: List[ToolCallItem] = []
                if message.tool_calls:
                    for tc in message.tool_calls:
                        args = {}
                        if tc.function.arguments:
                            try:
                                args = json.loads(tc.function.arguments)
                            except Exception:
                                args = {"raw": tc.function.arguments}
                        tool_calls.append(
                            ToolCallItem(id=tc.id, name=tc.function.name, arguments=args)
                        )

                usage = response.usage
                in_tokens = usage.prompt_tokens if usage else 0
                out_tokens = usage.completion_tokens if usage else 0

                return LLMResponse(
                    content=message.content,
                    tool_calls=tool_calls,
                    input_tokens=in_tokens,
                    output_tokens=out_tokens,
                    raw_message=message,
                )

            except Exception as err:
                last_error = err
                err_str = str(err).lower()
                is_rate_limit = "429" in err_str or "rate limit" in err_str or "quota" in err_str or "503" in err_str
                if attempt < self.max_retries and is_rate_limit:
                    sleep_time = self.base_backoff * (2**attempt) + random.uniform(0.5, 1.5)
                    await asyncio.sleep(sleep_time)
                else:
                    raise err

        raise last_error or RuntimeError("OpenAI-compatible chat request failed")
