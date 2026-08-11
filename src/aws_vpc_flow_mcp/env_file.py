from __future__ import annotations

import os
import re
import shlex
from pathlib import Path


class EnvironmentFileError(ValueError):
    pass


KEY_PATTERN = re.compile(r"[A-Z][A-Z0-9_]*")
FORBIDDEN_KEY_PARTS = ("SECRET", "TOKEN", "PASSWORD", "PRIVATE_KEY")


def read_environment_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line.removeprefix("export ").lstrip()
        if "=" not in line:
            raise EnvironmentFileError(f"{path}:{line_number}: expected KEY=VALUE.")
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not KEY_PATTERN.fullmatch(key):
            raise EnvironmentFileError(f"{path}:{line_number}: invalid environment key.")
        if any(part in key for part in FORBIDDEN_KEY_PARTS):
            raise EnvironmentFileError(
                f"{path}:{line_number}: secret-bearing keys are not allowed."
            )
        try:
            parsed = shlex.split(raw_value, comments=True, posix=True)
        except ValueError as exc:
            raise EnvironmentFileError(f"{path}:{line_number}: {exc}") from exc
        if len(parsed) > 1:
            raise EnvironmentFileError(f"{path}:{line_number}: quote values containing whitespace.")
        values[key] = parsed[0] if parsed else ""
    return values


def apply_environment_file(path: Path) -> dict[str, str]:
    values = read_environment_file(path)
    for key, value in values.items():
        os.environ.setdefault(key, value)
    return values
