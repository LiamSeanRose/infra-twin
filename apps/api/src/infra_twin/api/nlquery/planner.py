"""Compile a natural-language question to a templated query plan via Claude tool-use.

The planner exposes each whitelisted template as a tool and forces the model to call exactly
one (``tool_choice: any``), plus an ``unsupported`` escape hatch. The model therefore can only
*select a template and fill typed arguments* — it never produces a query string. The Anthropic
client is injectable so the planner is unit-testable without network access.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol

import anthropic

from infra_twin.api.nlquery.templates import REGISTRY

DEFAULT_MODEL = "claude-sonnet-4-6"
UNSUPPORTED = "unsupported"

_SYSTEM = (
    "You translate a user's natural-language question about their cloud infrastructure into "
    "exactly one of the provided query tools. Pick the single best tool and fill its arguments "
    "from the question. If no tool fits the question, call the `unsupported` tool. You only "
    "select a tool — never assert any infrastructure facts yourself."
)


@dataclass
class QueryPlan:
    """A chosen template name and the arguments to validate against its parameter model."""

    name: str
    args: dict


class Planner(Protocol):
    def plan(self, question: str) -> QueryPlan | None: ...


class ClaudePlanner:
    """Planner backed by the Anthropic API."""

    def __init__(
        self, client: anthropic.Anthropic | None = None, model: str | None = None
    ) -> None:
        self._client = client or anthropic.Anthropic()
        self._model = model or os.environ.get("INFRA_TWIN_NL_MODEL", DEFAULT_MODEL)

    def _tools(self) -> list[dict]:
        tools = [
            {
                "name": template.name,
                "description": template.description,
                "input_schema": template.params_model.model_json_schema(),
            }
            for template in REGISTRY.values()
        ]
        tools.append(
            {
                "name": UNSUPPORTED,
                "description": "Use when the question cannot be answered by any other tool.",
                "input_schema": {"type": "object", "properties": {}},
            }
        )
        return tools

    def plan(self, question: str) -> QueryPlan | None:
        message = self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            system=_SYSTEM,
            tools=self._tools(),
            tool_choice={"type": "any"},
            messages=[{"role": "user", "content": question}],
        )
        for block in message.content:
            if block.type == "tool_use":
                return QueryPlan(name=block.name, args=dict(block.input))
        return None
