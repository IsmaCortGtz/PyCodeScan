"""Detector for hardcoded secrets: passwords, API keys, tokens, etc."""
from __future__ import annotations

import ast
from typing import List

from .base import BaseDetector, Vulnerability

# Variable / parameter names that suggest a secret value
SECRET_KEYWORDS = [
    "password", "passwd", "pwd", "passphrase",
    "secret", "secret_key", "signing_key", "encryption_key", "master_key",
    "api_key", "apikey", "api_secret",
    "token", "auth_token", "access_token", "refresh_token",
    "private_key", "privkey",
    "credential", "credentials",
    "access_key", "aws_key", "aws_secret",
    "db_password", "db_pass", "database_password",
    "smtp_password", "ftp_password",
    "jwt_secret", "oauth_secret",
]

RECOMMENDATION = (
    "Never hardcode secrets in source code. "
    "Load sensitive values from environment variables (os.environ.get) or a "
    "secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager, .env files "
    "excluded from version control). "
    "Rotate any exposed credentials immediately and audit commit history."
)


def _matches_keyword(name: str) -> bool:
    name_lower = name.lower()
    return any(kw in name_lower for kw in SECRET_KEYWORDS)


def _is_non_empty_string(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and len(node.value.strip()) > 0
    )


def _redact(value: str) -> str:
    """Show a short redacted preview of the secret."""
    preview = value[:20].replace("\n", "\\n")
    suffix = "..." if len(value) > 20 else ""
    return f'"{preview}{suffix}"'


class HardcodedSecretsDetector(BaseDetector):
    """Detects hardcoded secrets assigned to variables or passed as keyword args."""

    def detect(self, tree: ast.AST, source_lines: List[str]) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        for node in ast.walk(tree):

            # --- Simple assignment:  password = "s3cr3t" ---
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and _matches_keyword(target.id):
                        if _is_non_empty_string(node.value):
                            vulns.append(Vulnerability(
                                name="Hardcoded Secret",
                                description=(
                                    f"Variable '{target.id}' contains a hardcoded "
                                    f"secret value: {_redact(node.value.value)}"
                                ),
                                line=node.lineno,
                                col=node.col_offset,
                                severity="HIGH",
                                recommendation=RECOMMENDATION,
                            ))

            # --- Annotated assignment:  password: str = "s3cr3t" ---
            elif isinstance(node, ast.AnnAssign):
                if (
                    isinstance(node.target, ast.Name)
                    and _matches_keyword(node.target.id)
                    and node.value is not None
                    and _is_non_empty_string(node.value)
                ):
                    vulns.append(Vulnerability(
                        name="Hardcoded Secret",
                        description=(
                            f"Variable '{node.target.id}' contains a hardcoded "
                            f"secret value: {_redact(node.value.value)}"
                        ),
                        line=node.lineno,
                        col=node.col_offset,
                        severity="HIGH",
                        recommendation=RECOMMENDATION,
                    ))

            # --- Keyword argument in a call:  connect(password="s3cr3t") ---
            elif isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg and _matches_keyword(kw.arg) and _is_non_empty_string(kw.value):
                        vulns.append(Vulnerability(
                            name="Hardcoded Secret in Function Call",
                            description=(
                                f"Keyword argument '{kw.arg}' contains a hardcoded "
                                f"secret value: {_redact(kw.value.value)}"
                            ),
                            line=kw.value.lineno,
                            col=kw.value.col_offset,
                            severity="HIGH",
                            recommendation=RECOMMENDATION,
                        ))

        return vulns
