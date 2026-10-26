"""Trace data structures for agent execution runs."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ToolCallRecord:
    """Record of a tool call executed during an agent run."""

    name: str
    arguments: Dict[str, Any]
    result: Any
    is_error: bool = False


@dataclass
class AgentTrace:
    """Complete trace of an agent's execution on a scenario."""

    task: str
    model: str
    system_prompt: str
    tool_calls: List[ToolCallRecord] = field(default_factory=list)
    final_output: Optional[str] = None
    input_tokens: int = 0
    output_tokens: int = 0
    wall_time_seconds: float = 0.0
    error: Optional[str] = None
    raw_completions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task": self.task,
            "model": self.model,
            "system_prompt": self.system_prompt,
            "tool_calls": [
                {
                    "name": tc.name,
                    "arguments": tc.arguments,
                    "result": tc.result,
                    "is_error": tc.is_error,
                }
                for tc in self.tool_calls
            ],
            "final_output": self.final_output,
            "raw_completions": self.raw_completions,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "wall_time_seconds": self.wall_time_seconds,
            "error": self.error,
        }
