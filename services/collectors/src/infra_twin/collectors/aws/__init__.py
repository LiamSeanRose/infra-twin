"""AWS connector."""

from infra_twin.collectors.aws.connector import AwsConnector
from infra_twin.collectors.aws.events import (
    EVENT_SOURCE,
    UnsupportedEventError,
    parse_event,
)
from infra_twin.collectors.aws.flowlogs import (
    FLOWLOG_SOURCE,
    DEFAULT_FLOW_CONFIDENCE,
    FlowLogParseError,
    parse_flow_logs,
)

__all__ = [
    "AwsConnector",
    "DEFAULT_FLOW_CONFIDENCE",
    "EVENT_SOURCE",
    "FLOWLOG_SOURCE",
    "FlowLogParseError",
    "UnsupportedEventError",
    "parse_event",
    "parse_flow_logs",
]
