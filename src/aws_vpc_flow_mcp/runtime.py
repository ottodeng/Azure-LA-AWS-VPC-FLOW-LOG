from __future__ import annotations

from .config import Settings
from .service import ToolService

_service: ToolService | None = None


def get_service() -> ToolService:
    global _service
    if _service is None:
        _service = ToolService(Settings.from_env(require_workspace=False))
    return _service


def set_service(service: ToolService | None) -> None:
    global _service
    _service = service
