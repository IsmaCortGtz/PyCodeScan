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
            "eval() ejecuta código Python arbitrario contenido en una cadena. "
            "Si datos controlados por usuario llegan a esta llamada, habilita "
            "Remote Code Execution (RCE)."
        ),
        "recommendation": (
            "Elimina eval() por completo. Para parsear literales usa "
            "ast.literal_eval(). Reescribe la lógica dinámica con "
            "diccionarios explícitos o condicionales."
        ),
    },
    "exec": {
        "severity": "CRITICAL",
        "description": (
            "exec() ejecuta una cadena como código Python en tiempo de ejecución. "
            "Cualquier contenido suministrado por usuario que llegue aquí provoca RCE."
        ),
        "recommendation": (
            "Evita exec(). Refactoriza la lógica para usar rutas de código explícitas. "
            "Si necesitas un sistema de plugins, usa importlib con allowlist "
            "estricto."
        ),
    },
    "compile": {
        "severity": "HIGH",
        "description": (
            "compile() convierte una cadena en un objeto de código que luego "
            "puede ejecutarse con eval() o exec(). Suele ser un precursor de "
            "ejecución arbitraria de código."
        ),
        "recommendation": (
            "Evita compile() con cadenas dinámicas. Restringe su uso a "
            "fuentes totalmente estáticas y confiables (p. ej., scripts embebidos)."
        ),
    },
    "__import__": {
        "severity": "HIGH",
        "description": (
            "__import__() con un nombre de módulo dinámico puede abusarse "
            "para importar módulos arbitrarios, habilitando ejecución de código "
            "o divulgación de información."
        ),
        "recommendation": (
            "Usa importlib.import_module() con validación estricta por allowlist "
            "del nombre del módulo, en lugar de __import__() con entrada dinámica."
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
            "os.system() pasa una cadena directamente al shell del sistema. "
            "Insertar datos controlados por usuario habilita OS Command Injection."
        ),
        "recommendation": (
            "Reemplaza por subprocess.run() usando una lista de argumentos "
            "y shell=False (valor por defecto). Valida todas las entradas."
        ),
    },
    ("os", "popen"): {
        "severity": "HIGH",
        "description": (
            "os.popen() abre una tubería a un comando de shell. "
            "La entrada controlada por usuario dentro de la cadena del comando "
            "provoca Command Injection."
        ),
        "recommendation": (
            "Reemplaza por subprocess.run(..., stdout=PIPE) usando una "
            "lista de argumentos. Evita shell=True."
        ),
    },
    ("subprocess", "run"): {
        "severity": "MEDIUM",
        "description": (
            "subprocess.run() puede ejecutar comandos de shell. Pasar shell=True "
            "o concatenar entrada de usuario en la cadena de comando es peligroso."
        ),
        "recommendation": (
            "Pasa el comando como lista (p. ej., ['ls', path]) en lugar de una "
            "cadena de shell. Mantén shell=False y valida todos los argumentos."
        ),
    },
    ("subprocess", "call"): {
        "severity": "MEDIUM",
        "description": (
            "subprocess.call() ejecuta un comando, con los mismos riesgos que "
            "subprocess.run() cuando se usa shell=True o entrada no saneada."
        ),
        "recommendation": (
            "Usa listas de argumentos y shell=False. Prefiere subprocess.run(), "
            "que ofrece mayor control sobre entrada/salida."
        ),
    },
    ("subprocess", "Popen"): {
        "severity": "MEDIUM",
        "description": (
            "subprocess.Popen() crea un proceso nuevo. Usar shell=True o "
            "construir el comando con entrada de usuario habilita Command Injection."
        ),
        "recommendation": (
            "Pasa argumentos como lista, define shell=False y valida de forma "
            "estricta todos los valores proporcionados por el usuario antes de usarlos."
        ),
    },
    ("subprocess", "getoutput"): {
        "severity": "HIGH",
        "description": (
            "subprocess.getoutput() pasa una cadena cruda al shell y "
            "devuelve su salida. Es intrínsecamente vulnerable a "
            "Command Injection por entrada de usuario."
        ),
        "recommendation": (
            "Reemplaza por subprocess.run(['cmd', arg], capture_output=True) "
            "usando una lista de argumentos. Evita todas las APIs con cadenas de shell."
        ),
    },
    ("subprocess", "getstatusoutput"): {
        "severity": "HIGH",
        "description": (
            "subprocess.getstatusoutput() pasa una cadena cruda al shell, "
            "habilitando Command Injection si cualquier parte la controla el usuario."
        ),
        "recommendation": (
            "Reemplaza por subprocess.run() usando una lista de argumentos y "
            "capture_output=True."
        ),
    },
    # -- Insecure deserialization --
    ("pickle", "loads"): {
        "severity": "CRITICAL",
        "description": (
            "pickle.loads() deserializa objetos Python arbitrarios. "
            "Deserializar datos de una fuente no confiable conduce a RCE "
            "porque pickle puede invocar __reduce__ para ejecutar código."
        ),
        "recommendation": (
            "Nunca deserialices datos no confiables con pickle. "
            "Usa JSON, MessagePack o un formato validado por esquema. "
            "Si pickle es obligatorio, verifica la integridad con un HMAC "
            "antes de cargar."
        ),
    },
    ("pickle", "load"): {
        "severity": "CRITICAL",
        "description": (
            "pickle.load() deserializa objetos Python desde un archivo. "
            "Un archivo manipulado o malicioso conduce a ejecución arbitraria de código."
        ),
        "recommendation": (
            "No uses pickle con archivos no confiables. "
            "Prefiere JSON u otro formato de serialización seguro."
        ),
    },
    ("marshal", "loads"): {
        "severity": "CRITICAL",
        "description": (
            "marshal.loads() deserializa bytecode Python crudo. "
            "Bytecode malicioso puede ejecutar código arbitrario."
        ),
        "recommendation": (
            "Evita marshal.loads() con entradas no confiables. "
            "Usa JSON u otro formato estructurado y seguro."
        ),
    },
    # -- Unsafe YAML --
    ("yaml", "load"): {
        "severity": "HIGH",
        "description": (
            "yaml.load() sin un Loader seguro explícito deserializa "
            "objetos Python arbitrarios, provocando RCE mediante "
            "entrada YAML especialmente construida."
        ),
        "recommendation": (
            "Reemplaza yaml.load(data) por yaml.safe_load(data), o pasa "
            "Loader=yaml.SafeLoader de forma explícita."
        ),
    },
    # -- Weak cryptography --
    ("hashlib", "md5"): {
        "severity": "MEDIUM",
        "description": (
            "MD5 es una función hash criptográficamente rota y vulnerable "
            "a ataques de colisión. No debe usarse para hash de contraseñas, "
            "firmas digitales ni verificación de integridad."
        ),
        "recommendation": (
            "Reemplaza MD5 por SHA-256 (hashlib.sha256) o SHA-3. "
            "Para contraseñas usa bcrypt, scrypt o Argon2."
        ),
    },
    ("hashlib", "sha1"): {
        "severity": "MEDIUM",
        "description": (
            "SHA-1 es criptográficamente débil y no debe usarse en "
            "operaciones sensibles de seguridad como firmado de certificados "
            "o hash de contraseñas."
        ),
        "recommendation": (
            "Reemplaza SHA-1 por SHA-256 o superior. "
            "Para contraseñas usa bcrypt, scrypt o Argon2."
        ),
    },
    # -- Insecure randomness --
    ("random", "random"): {
        "severity": "LOW",
        "description": (
            "random.random() usa un PRNG Mersenne Twister que no es "
            "criptográficamente seguro. Su salida puede predecirse si "
            "un atacante observa suficientes valores."
        ),
        "recommendation": (
            "Usa el módulo secrets para valores aleatorios sensibles de seguridad "
            "(tokens, IDs de sesión, nonces)."
        ),
    },
    ("random", "randint"): {
        "severity": "LOW",
        "description": (
            "random.randint() no es criptográficamente seguro y "
            "no debe usarse para generar tokens, OTPs ni claves secretas."
        ),
        "recommendation": (
            "Reemplaza por secrets.randbelow() o secrets.token_bytes() "
            "para cualquier propósito sensible de seguridad."
        ),
    },
    ("random", "choice"): {
        "severity": "LOW",
        "description": (
            "random.choice() usa un PRNG no criptográfico. "
            "La salida predecible lo hace inadecuado para casos de seguridad."
        ),
        "recommendation": (
            "Usa secrets.choice() del módulo secrets cuando "
            "el valor elegido tenga implicaciones de seguridad."
        ),
    },
    # -- TOCTOU / insecure temp files --
    ("tempfile", "mktemp"): {
        "severity": "MEDIUM",
        "description": (
            "tempfile.mktemp() devuelve un nombre de archivo sin crearlo, "
            "introduciendo una condición de carrera TOCTOU. Un atacante puede crear "
            "un symlink en esa ruta antes de que tu código lo abra."
        ),
        "recommendation": (
            "Reemplaza por tempfile.mkstemp() o tempfile.NamedTemporaryFile(), "
            "que crean y abren el archivo de forma atómica."
        ),
    },
    # -- Shelve (uses pickle internally) --
    ("shelve", "open"): {
        "severity": "LOW",
        "description": (
            "shelve.open() usa pickle internamente para serializar. "
            "Abrir una base shelve desde una fuente no confiable es peligroso."
        ),
        "recommendation": (
            "No abras bases shelve desde fuentes no confiables. "
            "Considera SQLite con consultas parametrizadas como alternativa más segura."
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
                        name=f"Función peligrosa: {func_name}()",
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
                        name=f"Función peligrosa: {module}.{func_name}()",
                        description=info["description"],
                        line=node.lineno,
                        col=node.col_offset,
                        severity=info["severity"],
                        recommendation=info["recommendation"],
                    ))

        return vulns
