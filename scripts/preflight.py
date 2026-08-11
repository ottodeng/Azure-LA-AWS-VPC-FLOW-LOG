#!/usr/bin/env python3
"""Run MCP prerequisite checks without installing the MCP package."""

# ruff: noqa: E402, I001

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aws_vpc_flow_mcp.preflight import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
