"""Detector for calls to dangerous or security-sensitive functions."""
from __future__ import annotations

import ast
from typing import List, Optional, Tuple

from .base import BaseDetector, Vulnerability

# ---------------------------------------------------------------------------
# Dangerous built-in functions (no module prefix)
# ---------------------------------------------------------------------------
DANGEROUS_BUILTINS: dict[str, dict] = {
    "eval": {
        "severity": "CRITICAL",
        "description": (
            "eval() executes arbitrary Python code contained in a string. "
            "If any user-controlled data reaches this call, it enables "
            "Remote Code Execution (RCE)."
        ),
        "recommendation": (
            "Remove eval() entirely. For parsing data literals use "
            "ast.literal_eval(). Rewrite dynamic-dispatch logic using "
            "explicit dictionaries or conditionals."
        ),
    },
    "exec": {
        "severity": "CRITICAL",
        "description": (
            "exec() executes a string as Python code at runtime. "
            "Any user-supplied content reaching this call results in RCE."
        ),
        "recommendation": (
            "Avoid exec(). Refactor the logic to use explicit code paths. "
            "If a plugin system is required, use importlib with strict "
            "allowlisting."
        ),
    },
    "compile": {
        "severity": "HIGH",
        "description": (
            "compile() converts a string into a code object that can later "
            "be executed by eval() or exec(). Often used as a precursor to "
            "arbitrary code execution."
        ),
        "recommendation": (
            "Avoid compile() with dynamic strings. Restrict its use to "
            "fully static, trusted source (e.g., embedded scripts)."
        ),
    },
    "__import__": {
        "severity": "HIGH",
        "description": (
            "__import__() with a dynamic module name argument can be abused "
            "to import arbitrary modules, enabling code execution or "
            "information disclosure."
        ),
        "recommendation": (
            "Use importlib.import_module() with strict allowlist validation "
            "of the module name instead of __import__() with dynamic input."
        ),
    },
}

# ---------------------------------------------------------------------------
# Dangerous attribute calls  (module.function)
# ---------------------------------------------------------------------------
DANGEROUS_ATTRIBUTES: dict[Tuple[str, str], dict] = {
    # -- Shell / OS execution --
    ("os", "system"): {
        "severity": "HIGH",
        "description": (
            "os.system() passes a string directly to the system shell. "
            "Inserting user-controlled data enables OS Command Injection."
        ),
        "recommendation": (
            "Replace with subprocess.run() using a list of arguments "
            "and shell=False (the default). Validate all inputs."
        ),
    },
    ("os", "popen"): {
        "severity": "HIGH",
        "description": (
            "os.popen() opens a pipe to a shell command. "
            "User-controlled input in the command string leads to "
            "Command Injection."
        ),
        "recommendation": (
            "Replace with subprocess.run(..., stdout=PIPE) using an "
            "argument list. Avoid shell=True."
        ),
    },
    ("subprocess", "run"): {
        "severity": "MEDIUM",
        "description": (
            "subprocess.run() can spawn shell commands. Passing shell=True "
            "or concatenating user input into the command string is dangerous."
        ),
        "recommendation": (
            "Pass the command as a list (e.g., ['ls', path]) instead of a "
            "shell string. Keep shell=False and validate all arguments."
        ),
    },
    ("subprocess", "call"): {
        "severity": "MEDIUM",
        "description": (
            "subprocess.call() executes a command, with the same risks as "
            "subprocess.run() when shell=True or with unsanitized input."
        ),
        "recommendation": (
            "Use argument lists and shell=False. Prefer subprocess.run() "
            "which offers more control over input/output."
        ),
    },
    ("subprocess", "Popen"): {
        "severity": "MEDIUM",
        "description": (
            "subprocess.Popen() spawns a new process. Using shell=True or "
            "building the command from user input enables Command Injection."
        ),
        "recommendation": (
            "Pass arguments as a list, set shell=False, and strictly "
            "validate all user-provided values before use."
        ),
    },
    ("subprocess", "getoutput"): {
        "severity": "HIGH",
        "description": (
            "subprocess.getoutput() passes a raw string to the shell and "
            "returns its output. It is inherently vulnerable to "
            "Command Injection via user input."
        ),
        "recommendation": (
            "Replace with subprocess.run(['cmd', arg], capture_output=True) "
            "using an argument list. Avoid all shell-string APIs."
        ),
    },
    ("subprocess", "getstatusoutput"): {
        "severity": "HIGH",
        "description": (
            "subprocess.getstatusoutput() passes a raw string to the shell, "
            "enabling Command Injection if any part is user-controlled."
        ),
        "recommendation": (
            "Replace with subprocess.run() using an argument list and "
            "capture_output=True."
        ),
    },
    # -- Insecure deserialization --
    ("pickle", "loads"): {
        "severity": "CRITICAL",
        "description": (
            "pickle.loads() deserializes arbitrary Python objects. "
            "Deserializing data from an untrusted source leads to RCE "
            "because pickle can invoke __reduce__ to execute code."
        ),
        "recommendation": (
            "Never deserialize untrusted data with pickle. "
            "Use JSON, MessagePack, or a schema-validated format. "
            "If pickle is required, verify data integrity with an HMAC "
            "before loading."
        ),
    },
    ("pickle", "load"): {
        "severity": "CRITICAL",
        "description": (
            "pickle.load() deserializes Python objects from a file. "
            "A tampered or malicious file leads to arbitrary code execution."
        ),
        "recommendation": (
            "Do not use pickle with untrusted files. "
            "Prefer JSON or another safe serialization format."
        ),
    },
    ("marshal", "loads"): {
        "severity": "CRITICAL",
        "description": (
            "marshal.loads() deserializes raw Python bytecode. "
            "Malicious bytecode can execute arbitrary code."
        ),
        "recommendation": (
            "Avoid marshal.loads() with untrusted input. "
            "Use JSON or another safe, structured format."
        ),
    },
    # -- Unsafe YAML --
    ("yaml", "load"): {
        "severity": "HIGH",
        "description": (
            "yaml.load() without an explicit safe Loader deserializes "
            "arbitrary Python objects, leading to RCE via specially "
            "crafted YAML input."
        ),
        "recommendation": (
            "Replace yaml.load(data) with yaml.safe_load(data), or pass "
            "Loader=yaml.SafeLoader explicitly."
        ),
    },
    # -- Weak cryptography --
    ("hashlib", "md5"): {
        "severity": "MEDIUM",
        "description": (
            "MD5 is a cryptographically broken hash function vulnerable "
            "to collision attacks. It must not be used for password hashing, "
            "digital signatures, or integrity verification."
        ),
        "recommendation": (
            "Replace MD5 with SHA-256 (hashlib.sha256) or SHA-3. "
            "For password hashing, use bcrypt, scrypt, or Argon2."
        ),
    },
    ("hashlib", "sha1"): {
        "severity": "MEDIUM",
        "description": (
            "SHA-1 is cryptographically weak and should not be used for "
            "security-sensitive operations such as certificate signing or "
            "password hashing."
        ),
        "recommendation": (
            "Replace SHA-1 with SHA-256 or stronger. "
            "For passwords use bcrypt, scrypt, or Argon2."
        ),
    },
    # -- Insecure randomness --
    ("random", "random"): {
        "severity": "LOW",
        "description": (
            "random.random() uses a Mersenne Twister PRNG which is not "
            "cryptographically secure. Its output can be predicted by "
            "an attacker observing enough values."
        ),
        "recommendation": (
            "Use the secrets module for security-sensitive random values "
            "(tokens, session IDs, nonces)."
        ),
    },
    ("random", "randint"): {
        "severity": "LOW",
        "description": (
            "random.randint() is not cryptographically secure and "
            "should not be used to generate tokens, OTPs, or secret keys."
        ),
        "recommendation": (
            "Replace with secrets.randbelow() or secrets.token_bytes() "
            "for any security-sensitive purpose."
        ),
    },
    ("random", "choice"): {
        "severity": "LOW",
        "description": (
            "random.choice() uses a non-cryptographic PRNG. "
            "Predictable output makes it unsuitable for security use cases."
        ),
        "recommendation": (
            "Use secrets.choice() from the secrets module when the "
            "selected value has security implications."
        ),
    },
    # -- TOCTOU / insecure temp files --
    ("tempfile", "mktemp"): {
        "severity": "MEDIUM",
        "description": (
            "tempfile.mktemp() returns a filename without creating the file, "
            "introducing a TOCTOU race condition. An attacker can create a "
            "symlink at the returned path before your code opens it."
        ),
        "recommendation": (
            "Replace with tempfile.mkstemp() or tempfile.NamedTemporaryFile() "
            "which atomically create and open the file."
        ),
    },
    # -- Shelve (uses pickle internally) --
    ("shelve", "open"): {
        "severity": "LOW",
        "description": (
            "shelve.open() uses pickle internally for serialization. "
            "Opening a shelve database from an untrusted source is dangerous."
        ),
        "recommendation": (
            "Do not open shelve databases from untrusted sources. "
            "Consider SQLite with parameterized queries as a safer alternative."
        ),
    },
}


def _resolve_call(node: ast.Call) -> Tuple[Optional[str], Optional[str]]:
    """Return (module, function) from a Call node, or (None, name) for builtins."""
    func = node.func
    if isinstance(func, ast.Name):
        return None, func.id
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id, func.attr
    return None, None


class DangerousFunctionsDetector(BaseDetector):
    """Detects calls to known dangerous or security-sensitive functions."""

    def detect(self, tree: ast.AST, source_lines: List[str]) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            module, func_name = _resolve_call(node)
            if func_name is None:
                continue

            if module is None:
                info = DANGEROUS_BUILTINS.get(func_name)
                if info:
                    vulns.append(Vulnerability(
                        name=f"Dangerous Function: {func_name}()",
                        description=info["description"],
                        line=node.lineno,
                        col=node.col_offset,
                        severity=info["severity"],
                        recommendation=info["recommendation"],
                    ))
            else:
                info = DANGEROUS_ATTRIBUTES.get((module, func_name))
                if info:
                    vulns.append(Vulnerability(
                        name=f"Dangerous Function: {module}.{func_name}()",
                        description=info["description"],
                        line=node.lineno,
                        col=node.col_offset,
                        severity=info["severity"],
                        recommendation=info["recommendation"],
                    ))

        return vulns
