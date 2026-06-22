"""Natural-language → graph query.

A question is compiled to exactly one whitelisted, parameter-validated query template — never
to free-form SQL/cypher. The LLM only *selects* a template and fills typed arguments; all
execution goes through the same tenant-scoped repositories and query functions the rest of the
platform uses, and every answer is grounded in real query results.
"""

from infra_twin.api.nlquery.engine import Answer, answer_question
from infra_twin.api.nlquery.planner import ClaudePlanner, Planner, QueryPlan
from infra_twin.api.nlquery.templates import REGISTRY

__all__ = [
    "Answer",
    "ClaudePlanner",
    "Planner",
    "QueryPlan",
    "REGISTRY",
    "answer_question",
]
