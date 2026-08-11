from __future__ import annotations

import hashlib
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .access import Principal

logger = logging.getLogger("aws_vpc_flow_mcp.audit")


def _hash(value: str | None) -> str | None:
    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class AuditLogger:
    def __init__(
        self, path: Path | None, workspace_id: str | None, include_upn: bool = False
    ) -> None:
        self.path = path
        self.workspace_hash = _hash(workspace_id)
        self.include_upn = include_upn
        self._lock = threading.Lock()

    def record(
        self,
        *,
        principal: Principal,
        role: str,
        tool: str,
        status: str,
        duration_ms: int,
        row_count: int = 0,
        query: str | None = None,
        error_type: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        event: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "subject": principal.subject,
            "clientId": principal.client_id,
            "role": role,
            "tool": tool,
            "status": status,
            "durationMs": duration_ms,
            "rowCount": row_count,
            "querySha256": _hash(query),
            "workspaceSha256": self.workspace_hash,
        }
        if self.include_upn and principal.upn:
            event["upn"] = principal.upn
        if error_type:
            event["errorType"] = error_type
        if details:
            event["details"] = details
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        logger.info(line)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._lock, self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
