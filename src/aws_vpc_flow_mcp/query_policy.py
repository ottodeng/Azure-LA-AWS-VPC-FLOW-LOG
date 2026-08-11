from __future__ import annotations

import re
from dataclasses import dataclass


class QueryPolicyError(ValueError):
    pass


ALLOWED_TABLE = "AWSVPCFlow"
BLOCKED_PATTERNS = {
    "cross-workspace function": r"\b(workspace|app|resource)\s*\(",
    "cross-cluster function": r"\b(cluster|database)\s*\(",
    "external data access": r"\b(externaldata|external_table)\b",
    "cross-table operator": r"\b(union|join|lookup|search|find)\b",
    "plugin invocation": r"\bevaluate\b",
    "stored function invocation": r"\binvoke\b",
    "tabular indirection": r"\b(toscalar|materialize|table|macro_expand|entity_group)\s*\(",
    "nested tabular subquery": r"\([^)]*\|",
    "render operator": r"\brender\b",
    "multiple KQL statements": r";",
    "Kusto management command": r"(?m)^\s*\.",
}


@dataclass(frozen=True)
class QueryLimits:
    max_timespan_hours: int
    max_rows: int


def validate_kql(query: str) -> str:
    normalized = query.strip()
    if not normalized:
        raise QueryPolicyError("KQL query is empty.")
    without_comments = re.sub(r"/\*.*?\*/", "", normalized, flags=re.DOTALL)
    without_comments = re.sub(r"(?m)//.*$", "", without_comments).lstrip()
    if not re.match(r"(?i)AWSVPCFlow(?:\s|\|)", without_comments):
        raise QueryPolicyError("KQL must start from AWSVPCFlow.")
    if not re.search(r"(?i)\|\s*where\s+TimeGenerated\b", without_comments):
        raise QueryPolicyError("KQL must include an explicit TimeGenerated filter.")
    for label, pattern in BLOCKED_PATTERNS.items():
        if re.search(pattern, without_comments, re.IGNORECASE):
            raise QueryPolicyError(f"KQL contains a blocked {label}.")
    return normalized


def hours_to_timespan(hours: int, maximum: int) -> str:
    if hours < 1:
        raise QueryPolicyError("hours must be at least 1.")
    if hours > maximum:
        raise QueryPolicyError(f"hours exceeds the allowed maximum of {maximum}.")
    return f"PT{hours}H"


def parse_timespan_hours(timespan: str) -> int:
    value = timespan.strip().upper()
    hour_match = re.fullmatch(r"PT(\d+)H", value)
    if hour_match:
        return int(hour_match.group(1))
    day_match = re.fullmatch(r"P(\d+)D", value)
    if day_match:
        return int(day_match.group(1)) * 24
    raise QueryPolicyError("timespan must use PT<n>H or P<n>D.")


def validate_timespan(timespan: str, maximum: int) -> str:
    hours = parse_timespan_hours(timespan)
    if hours < 1 or hours > maximum:
        raise QueryPolicyError(f"timespan must be between 1 and {maximum} hours for this role.")
    return timespan.upper()


def validate_limit(limit: int, maximum: int) -> int:
    if limit < 1 or limit > maximum:
        raise QueryPolicyError(f"limit must be between 1 and {maximum}.")
    return limit
