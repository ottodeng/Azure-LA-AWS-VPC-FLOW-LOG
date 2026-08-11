from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class AccessDenied(PermissionError):
    pass


ANALYST_TOOLS = frozenset(
    {
        "service_status",
        "get_schema",
        "security_summary",
        "top_talkers",
        "detect_port_scans",
        "detect_brute_force",
        "detect_large_egress",
        "investigate_ip",
        "collection_health",
        "query_aws_vpc_flow",
    }
)
SUPPORTED_ROLE = "security_analyst"


@dataclass(frozen=True)
class Principal:
    subject: str
    client_id: str
    groups: tuple[str, ...] = ()
    role_claims: tuple[str, ...] = ()
    upn: str | None = None


@dataclass(frozen=True)
class RolePolicy:
    tools: frozenset[str]
    max_timespan_hours: int
    max_rows: int
    allow_custom_kql: bool


class AccessPolicy:
    def __init__(
        self,
        *,
        default_role: str | None,
        roles: dict[str, RolePolicy],
        group_role_mappings: dict[str, str],
        role_claim_mappings: dict[str, str],
    ) -> None:
        self.default_role = default_role
        self.roles = roles
        self.group_role_mappings = group_role_mappings
        self.role_claim_mappings = role_claim_mappings
        if default_role is not None:
            raise ValueError("defaultRole must be null so unmapped users are denied.")
        if set(roles) != {SUPPORTED_ROLE}:
            raise ValueError("Only the security_analyst role is supported.")
        role = roles[SUPPORTED_ROLE]
        unknown_tools = role.tools - ANALYST_TOOLS
        if unknown_tools:
            raise ValueError(
                f"Unsupported tools in security_analyst policy: {sorted(unknown_tools)}"
            )
        if role.max_timespan_hours < 1 or role.max_rows < 1:
            raise ValueError("security_analyst limits must be positive.")
        mappings = [*group_role_mappings.values(), *role_claim_mappings.values()]
        if any(mapped_role != SUPPORTED_ROLE for mapped_role in mappings):
            raise ValueError("All identity mappings must target security_analyst.")

    @classmethod
    def default(cls) -> AccessPolicy:
        roles = {
            "security_analyst": RolePolicy(
                tools=ANALYST_TOOLS,
                max_timespan_hours=24 * 30,
                max_rows=2000,
                allow_custom_kql=True,
            ),
        }
        return cls(
            default_role=None,
            roles=roles,
            group_role_mappings={},
            role_claim_mappings={
                "AWSVPCFlow.SecurityAnalyst": "security_analyst",
            },
        )

    @classmethod
    def load(cls, path: Path | None, inline_json: str | None = None) -> AccessPolicy:
        if inline_json:
            raw = json.loads(inline_json)
        elif path is not None:
            raw = json.loads(path.read_text(encoding="utf-8"))
        else:
            return cls.default()
        roles: dict[str, RolePolicy] = {}
        for name, definition in raw["roles"].items():
            roles[name] = RolePolicy(
                tools=frozenset(definition["tools"]),
                max_timespan_hours=int(definition["maxTimespanHours"]),
                max_rows=int(definition["maxRows"]),
                allow_custom_kql=bool(definition.get("allowCustomKql", False)),
            )
        return cls(
            default_role=raw.get("defaultRole"),
            roles=roles,
            group_role_mappings=dict(raw.get("groupRoleMappings", {})),
            role_claim_mappings=dict(raw.get("roleClaimMappings", {})),
        )

    def resolve_role(self, principal: Principal, local_role: str | None = None) -> str:
        if principal.subject == "local" and local_role:
            if local_role not in self.roles:
                raise AccessDenied(f"Configured local role {local_role!r} does not exist.")
            return local_role
        for claim in principal.role_claims:
            mapped = self.role_claim_mappings.get(claim)
            if mapped:
                return mapped
        for group in principal.groups:
            mapped = self.group_role_mappings.get(group)
            if mapped:
                return mapped
        if self.default_role is None:
            raise AccessDenied("The authenticated principal is not mapped to security_analyst.")
        return self.default_role

    def authorize(
        self, principal: Principal, tool: str, *, local_role: str | None = None
    ) -> tuple[str, RolePolicy]:
        role_name = self.resolve_role(principal, local_role)
        role = self.roles[role_name]
        if tool not in role.tools:
            raise AccessDenied(f"Role {role_name!r} is not allowed to call {tool!r}.")
        return role_name, role

    def public_summary(self) -> dict[str, Any]:
        return {
            "defaultRole": self.default_role,
            "roles": {
                name: {
                    "tools": sorted(role.tools),
                    "maxTimespanHours": role.max_timespan_hours,
                    "maxRows": role.max_rows,
                    "allowCustomKql": role.allow_custom_kql,
                }
                for name, role in self.roles.items()
            },
            "configuredGroupMappings": len(self.group_role_mappings),
            "configuredRoleClaimMappings": sorted(self.role_claim_mappings),
        }
