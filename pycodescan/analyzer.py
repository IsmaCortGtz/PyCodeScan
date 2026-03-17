"""Orchestrates all detectors over one Python source file."""
from __future__ import annotations

import ast
from pathlib import Path
from typing import List

from .detectors.base import Vulnerability
from .detectors.hardcoded_secrets import HardcodedSecretsDetector
from .detectors.dangerous_functions import DangerousFunctionsDetector


class Analyzer:
    def __init__(self) -> None:
        self._detectors = [
            HardcodedSecretsDetector(),
            DangerousFunctionsDetector(),
        ]

    def analyze_file(self, filepath: str) -> List[Vulnerability]:
        path = Path(filepath)

        if not path.exists():
            raise FileNotFoundError(f"Archivo no encontrado: {filepath}")
        if path.suffix != ".py":
            raise ValueError(f"No es un archivo fuente Python: {filepath}")

        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            raise SyntaxError(f"No se pudo parsear {filepath}: {exc}") from exc

        source_lines = source.splitlines()
        vulns: List[Vulnerability] = []

        for detector in self._detectors:
            vulns.extend(detector.detect(tree, source_lines))

        vulns.sort(key=lambda v: (v.line, v.col))
        return vulns
