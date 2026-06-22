"""Validate a query plan and execute its template, grounding the answer in real results."""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID

import psycopg
from pydantic import ValidationError

from infra_twin.api.nlquery.planner import Planner
from infra_twin.api.nlquery.templates import REGISTRY

DECLINE = "I can't answer that with the available queries."


@dataclass
class Answer:
    question: str
    answered: bool
    template: str | None = None
    params: dict = field(default_factory=dict)
    data: dict = field(default_factory=dict)
    summary: str = DECLINE


def answer_question(
    conn: psycopg.Connection, tenant_id: UUID, question: str, planner: Planner
) -> Answer:
    plan = planner.plan(question)
    if plan is None or plan.name not in REGISTRY:
        return Answer(question=question, answered=False)

    template = REGISTRY[plan.name]
    try:
        params = template.params_model(**plan.args)
    except ValidationError:
        # The model picked a real template but supplied invalid arguments — decline rather
        # than guess.
        return Answer(question=question, answered=False, template=plan.name)

    data = template.handler(conn, tenant_id, params)
    return Answer(
        question=question,
        answered=True,
        template=plan.name,
        params=params.model_dump(mode="json"),
        data=data,
        summary=template.summarize(params, data),
    )
