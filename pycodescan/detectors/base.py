"""Base classes shared by all detectors."""
from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import List


@dataclass
class Vulnerability:
    name: str
    description: str
    line: int
    col: int
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    recommendation: str


class BaseDetector:
    """Every detector must implement detect()."""

    def detect(self, tree: ast.AST, source_lines: List[str]) -> List[Vulnerability]:
        raise NotImplementedError
