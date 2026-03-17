# PyCodeScan

Herramienta de línea de comandos que analiza archivos fuente Python en busca de
vulnerabilidades de seguridad comunes, utilizando el módulo estándar `ast` (Abstract
Syntax Tree). No requiere dependencias externas.

---

## Tabla de contenidos

1. [Requisitos](#requisitos)
2. [Instalación](#instalación)
3. [Uso básico](#uso-básico)
4. [Opciones de línea de comandos](#opciones-de-línea-de-comandos)
5. [Códigos de salida](#códigos-de-salida)
6. [Vulnerabilidades detectadas](#vulnerabilidades-detectadas)
   - [Secretos hardcodeados](#1-secretos-hardcodeados)
   - [Funciones peligrosas](#2-funciones-peligrosas)
7. [Arquitectura técnica](#arquitectura-técnica)
   - [Cómo funciona el análisis AST](#cómo-funciona-el-análisis-ast)
   - [Estructura de módulos](#estructura-de-módulos)
   - [Modelo de datos: Vulnerability](#modelo-de-datos-vulnerability)
   - [Flujo de ejecución](#flujo-de-ejecución)
8. [Ejemplos incluidos](#ejemplos-incluidos)
9. [Extender PyCodeScan: escribir un detector nuevo](#extender-pycodescan-escribir-un-detector-nuevo)
10. [Limitaciones conocidas](#limitaciones-conocidas)
11. [Integración en CI/CD](#integración-en-cicd)

---

## Requisitos

- Python **3.9** o superior
- Sin dependencias de terceros (únicamente librería estándar)

---

## Instalación

### Opción A — ejecutar directamente desde el repositorio (recomendado para desarrollo)

```bash
git clone <url-del-repo>
cd PyCodeScan
python3 -m pycodescan --help
```

### Opción B — instalar como paquete en un entorno virtual

```bash
python3 -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\activate           # Windows

pip install -e .
pycodescan --help
```

La opción `-e` (editable) hace que los cambios en el código fuente se reflejen
inmediatamente sin reinstalar.

---

## Uso básico

```bash
# Analizar un solo archivo
python3 -m pycodescan script.py

# Analizar varios archivos en una sola pasada
python3 -m pycodescan app.py utils.py models.py

# Usar el comando instalado (tras pip install -e .)
pycodescan src/main.py

# Deshabilitar colores ANSI (útil en CI o al redirigir a un fichero)
python3 -m pycodescan script.py --no-color

# Guardar el informe en un fichero de texto
python3 -m pycodescan script.py --no-color > informe.txt
```

### Ejemplo de salida

```
========================================================================
  PyCodeScan — Security Analysis
========================================================================
  File  : examples/insecure_web_app.py
  Found : 13 issues
------------------------------------------------------------------------

  [ 1]  HIGH      Hardcoded Secret
         Location    : line 12, col 0
         Description :
           Variable 'DB_PASSWORD' contains a hardcoded secret value:
           "super_secret_db_pass..."

         Recommendation:
           Never hardcode secrets in source code. Load sensitive values
           from environment variables (os.environ.get) or a secrets
           manager (e.g., HashiCorp Vault, AWS Secrets Manager, .env
           files excluded from version control). Rotate any exposed
           credentials immediately and audit commit history.
  ----------------------------------------------------------------------

  ...

  Summary:
    CRITICAL: 2
    HIGH: 7
    MEDIUM: 4
========================================================================
```

---

## Opciones de línea de comandos

| Opción | Descripción |
|---|---|
| `FILE [FILE ...]` | Uno o más archivos `.py` a analizar (obligatorio) |
| `--no-color` | Desactiva los códigos de escape ANSI. Usar cuando la salida se redirige a un fichero o en entornos sin soporte de color |
| `--help` / `-h` | Muestra la ayuda y sale |

---

## Códigos de salida

| Código | Significado |
|---|---|
| `0` | Análisis completado sin vulnerabilidades |
| `1` | Se encontraron una o más vulnerabilidades |
| `2` | Error de entrada: archivo no existe, no es `.py` o tiene errores de sintaxis |

Los códigos de salida permiten integrar PyCodeScan en pipelines de CI/CD con
comprobaciones automáticas (`if [ $? -ne 0 ]; then …`).

---

## Vulnerabilidades detectadas

### 1. Secretos hardcodeados

**Detector:** `HardcodedSecretsDetector`  
**Severidad:** `HIGH`

Detecta cadenas de texto no vacías asignadas a variables, atributos o argumentos de
función cuyo nombre sugiere que contienen información sensible.

#### Palabras clave vigiladas

El detector compara (sin distinguir mayúsculas/minúsculas) el nombre de la variable o
parámetro contra la siguiente lista. Una coincidencia parcial es suficiente (p.ej.
`my_db_password` coincide con `password`).

| Grupo | Palabras clave |
|---|---|
| Contraseñas | `password`, `passwd`, `pwd`, `passphrase` |
| Secretos genéricos | `secret`, `secret_key`, `signing_key`, `encryption_key`, `master_key` |
| API / tokens | `api_key`, `apikey`, `api_secret`, `token`, `auth_token`, `access_token`, `refresh_token` |
| Claves privadas | `private_key`, `privkey` |
| Credenciales | `credential`, `credentials` |
| Cloud / acceso | `access_key`, `aws_key`, `aws_secret` |
| Bases de datos | `db_password`, `db_pass`, `database_password` |
| Servicios de correo/FTP | `smtp_password`, `ftp_password` |
| JWT / OAuth | `jwt_secret`, `oauth_secret` |

#### Patrones de código analizados

```python
# Asignación simple
password = "mi_clave_secreta"

# Asignación con anotación de tipo
api_key: str = "sk-xxxxxxxxxxxx"

# Argumento de función con nombre sensible
db.connect(host="localhost", password="hunter2")
```

#### Por qué es peligroso

Si el archivo se sube a un repositorio (público o privado), cualquier persona con
acceso al historial de commits puede extraer las credenciales. Los secretos expuestos
deben rotarse de inmediato.

#### Recomendación general

Cargar los valores desde variables de entorno o un gestor de secretos:

```python
import os
password = os.environ.get("DB_PASSWORD")
```

---

### 2. Funciones peligrosas

**Detector:** `DangerousFunctionsDetector`  
**Severidades:** `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`

Detecta llamadas a funciones conocidas por introducir riesgos de seguridad si se usan
con datos no confiables.

#### Tabla completa de funciones vigiladas

| Función | Categoría | Severidad | Riesgo principal |
|---|---|---|---|
| `eval()` | Ejecución de código | CRITICAL | Remote Code Execution (RCE) |
| `exec()` | Ejecución de código | CRITICAL | RCE |
| `compile()` | Ejecución de código | HIGH | Precursor de RCE |
| `__import__()` | Importación dinámica | HIGH | Importación arbitraria de módulos |
| `os.system()` | Shell | HIGH | OS Command Injection |
| `os.popen()` | Shell | HIGH | OS Command Injection |
| `subprocess.run()` | Proceso externo | MEDIUM | Command Injection con `shell=True` |
| `subprocess.call()` | Proceso externo | MEDIUM | Command Injection con `shell=True` |
| `subprocess.Popen()` | Proceso externo | MEDIUM | Command Injection con `shell=True` |
| `subprocess.getoutput()` | Shell | HIGH | Command Injection directo |
| `subprocess.getstatusoutput()` | Shell | HIGH | Command Injection directo |
| `pickle.loads()` | Deserialización | CRITICAL | Deserialización insegura → RCE |
| `pickle.load()` | Deserialización | CRITICAL | Deserialización insegura → RCE |
| `marshal.loads()` | Deserialización | CRITICAL | Bytecode arbitrario → RCE |
| `yaml.load()` | YAML | HIGH | Deserialización de objetos Python arbitrarios |
| `hashlib.md5()` | Criptografía débil | MEDIUM | Hash roto, vulnerable a colisiones |
| `hashlib.sha1()` | Criptografía débil | MEDIUM | Hash débil para firmas y contraseñas |
| `random.random()` | PRNG inseguro | LOW | Salida predecible, no apto para criptografía |
| `random.randint()` | PRNG inseguro | LOW | Salida predecible |
| `random.choice()` | PRNG inseguro | LOW | Salida predecible |
| `tempfile.mktemp()` | Race condition | MEDIUM | Condición TOCTOU en ficheros temporales |
| `shelve.open()` | Deserialización | LOW | Usa pickle internamente |

#### Cómo se resuelve la llamada en el AST

El detector distingue dos formas de llamada:

- **Builtin sin prefijo:** `eval(x)` → nodo `ast.Call` con `func` de tipo `ast.Name`
- **Atributo de módulo:** `subprocess.run(x)` → nodo `ast.Call` con `func` de tipo
  `ast.Attribute` cuyo `value` es un `ast.Name`

Esto significa que alias no estándar (`import subprocess as sp; sp.run(...)`) **no se
detectan** (ver [Limitaciones](#limitaciones-conocidas)).

---

## Arquitectura técnica

### Cómo funciona el análisis AST

Python incluye en su librería estándar el módulo `ast`, que convierte código fuente en
un árbol de nodos tipados sin necesidad de ejecutar el código. PyCodeScan opera en
tres fases:

```
Archivo .py
    │
    ▼
ast.parse()          ← construye el árbol sintáctico abstracto
    │
    ▼
ast.walk(tree)       ← recorre todos los nodos del árbol en orden
    │
    ├─ HardcodedSecretsDetector.detect()   ← busca Assign / AnnAssign / Call con keywords
    └─ DangerousFunctionsDetector.detect() ← busca ast.Call con nombres peligrosos
    │
    ▼
Lista de Vulnerability (ordenada por línea y columna)
    │
    ▼
reporter.print_report()   ← formatea con ANSI y muestra en stdout
```

El árbol nunca se ejecuta: el análisis es completamente estático. Esto garantiza que
analizar código malicioso no pone en riesgo la máquina del analista.

### Estructura de módulos

```
pycodescan/
│
├── __init__.py              Versión del paquete (__version__ = "0.1.0")
│
├── __main__.py              Punto de entrada CLI. Define el parser de argparse,
│                            itera sobre los archivos recibidos y delega en
│                            Analyzer y print_report.
│
├── analyzer.py              Clase Analyzer. Responsabilidades:
│                              · Validar que el archivo existe y es .py
│                              · Leer el contenido UTF-8
│                              · Llamar a ast.parse()
│                              · Invocar cada detector
│                              · Ordenar y devolver la lista de Vulnerability
│
├── reporter.py              Función print_report(). Responsabilidades:
│                              · Formatear cada Vulnerability con sangría uniforme
│                              · Aplicar colores ANSI según severidad
│                              · Mostrar el resumen final por severidad
│                              · Respetar el flag --no-color / isatty()
│
└── detectors/
    │
    ├── __init__.py          Re-exporta todos los detectores para importación limpia
    │
    ├── base.py              Dataclass Vulnerability y clase abstracta BaseDetector
    │
    ├── hardcoded_secrets.py HardcodedSecretsDetector
    │                          · Lista SECRET_KEYWORDS (coincidencia parcial, case-insensitive)
    │                          · Nodos analizados: ast.Assign, ast.AnnAssign, ast.Call (keywords)
    │                          · Solo reporta cadenas no vacías
    │                          · Muestra preview redactado de máximo 20 caracteres
    │
    └── dangerous_functions.py DangerousFunctionsDetector
                               · Diccionario DANGEROUS_BUILTINS (funciones sin prefijo)
                               · Diccionario DANGEROUS_ATTRIBUTES (módulo.función)
                               · Función _resolve_call() extrae (módulo, función) del nodo Call
                               · Un único ast.walk() recorre todo el árbol
```

### Modelo de datos: Vulnerability

Definido en `pycodescan/detectors/base.py`:

```python
@dataclass
class Vulnerability:
    name: str           # Nombre corto de la vulnerabilidad
    description: str    # Descripción técnica de por qué es peligrosa
    line: int           # Línea en el archivo fuente (1-indexed)
    col: int            # Columna (0-indexed, igual que el AST de Python)
    severity: str       # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    recommendation: str # Consejo de remediación específico para esta vuln.
```

Los detectores devuelven `List[Vulnerability]`. `Analyzer` los combina y ordena por
`(line, col)` antes de pasarlos al reporter.

### Flujo de ejecución

```
python3 -m pycodescan archivo.py
        │
        ▼
__main__.main()
  ├─ argparse: parsea --no-color y la lista de archivos
  └─ para cada archivo:
       ├─ Analyzer.analyze_file(filepath)
       │    ├─ Path(filepath).read_text()
       │    ├─ ast.parse(source)
       │    ├─ HardcodedSecretsDetector.detect(tree, lines)
       │    ├─ DangerousFunctionsDetector.detect(tree, lines)
       │    └─ sorted(vulnerabilities, key=(line, col))
       │
       └─ print_report(filepath, vulns, use_color)
            ├─ Cabecera con nombre de archivo y total
            ├─ Bloque por vulnerabilidad: severidad + ubicación + descripción + recomendación
            └─ Resumen de conteos por severidad
```

---

## Colores ANSI en el output

| Severidad | Color |
|---|---|
| `CRITICAL` | Rojo brillante |
| `HIGH` | Rojo |
| `MEDIUM` | Amarillo |
| `LOW` | Azul |

El uso de color se activa automáticamente solo si `stdout` es una terminal
(`sys.stdout.isatty() == True`). Al redirigir la salida (`> fichero.txt` o `| grep`)
los códigos ANSI se omiten automáticamente en este caso si se pasa `--no-color`.
Sin el flag `--no-color` la detección de si es TTY no es automática; use `--no-color`
explícitamente cuando redirija la salida a un fichero.

---

## Ejemplos incluidos

Los tres scripts en `examples/` contienen vulnerabilidades intencionales para
verificar el funcionamiento de la herramienta. **No deben usarse en producción.**

| Archivo | Vulnerabilidades | Descripción |
|---|---|---|
| `examples/insecure_web_app.py` | 13 | Contraseñas hardcodeadas, `eval()`, `pickle.loads()`, `yaml.load()`, `hashlib.md5/sha1`, `subprocess.getoutput()` |
| `examples/insecure_shell.py` | 13 | Secretos hardcodeados, `os.system()`, `os.popen()`, `subprocess.*`, `tempfile.mktemp()`, `random.*` |
| `examples/insecure_all.py` | 32 | Cubre todas las categorías: secretos, eval/exec/compile, shell, deserialización, criptografía débil, PRNG inseguro, race condition |

```bash
# Escanear todos los ejemplos de una vez
python3 -m pycodescan examples/insecure_web_app.py examples/insecure_shell.py examples/insecure_all.py
```

---

## Extender PyCodeScan: escribir un detector nuevo

1. **Crear el archivo** `pycodescan/detectors/mi_detector.py`

```python
from __future__ import annotations
import ast
from typing import List
from .base import BaseDetector, Vulnerability

class MiDetector(BaseDetector):
    def detect(self, tree: ast.AST, source_lines: List[str]) -> List[Vulnerability]:
        vulns = []
        for node in ast.walk(tree):
            # Inspeccionar nodos del árbol
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "telnetlib":
                        vulns.append(Vulnerability(
                            name="Protocolo inseguro: telnetlib",
                            description="telnetlib transmite datos en texto plano, incluyendo credenciales.",
                            line=node.lineno,
                            col=node.col_offset,
                            severity="HIGH",
                            recommendation="Reemplazar con paramiko o subprocess sobre SSH.",
                        ))
        return vulns
```

2. **Registrar el detector** en `pycodescan/detectors/__init__.py`:

```python
from .mi_detector import MiDetector
__all__ = [..., "MiDetector"]
```

3. **Añadir al Analyzer** en `pycodescan/analyzer.py`:

```python
from .detectors.mi_detector import MiDetector

class Analyzer:
    def __init__(self) -> None:
        self._detectors = [
            HardcodedSecretsDetector(),
            DangerousFunctionsDetector(),
            MiDetector(),          # ← nuevo detector
        ]
```

El detector recibirá el mismo `ast.AST` y `source_lines` que los demás. Las líneas
del fuente están disponibles para contexto adicional (p.ej. mostrar el fragmento de
código). El orden de los detectores en la lista determina el orden relativo de los
hallazgos antes del ordenamiento final por línea.

---

## Limitaciones conocidas

| Limitación | Explicación |
|---|---|
| **Alias de módulo no detectados** | `import subprocess as sp; sp.run(...)` no se detecta porque el detector solo reconoce el nombre canónico del módulo. |
| **Alias de función no detectados** | `from os import system as run_cmd; run_cmd(x)` tampoco se detecta. |
| **Análisis estático únicamente** | No se ejecuta el código: los flujos de datos dinámicos (variables que llegan a `eval` desde otra función) no se rastrean. Se detecta la llamada, no si el argumento es realmente controlado por el usuario. |
| **Contexto de importación no verificado** | El detector de funciones peligrosas asume que `yaml` es `PyYAML`. Si el código usa un módulo homónimo diferente, puede haber falsos positivos. |
| **Un solo archivo por invocación** | No existe soporte para escaneo recursivo de directorios todavía. Se puede suplir con shell: `find src -name "*.py" | xargs python3 -m pycodescan`. |
| **No detecta inyección SQL** | Las consultas SQL construidas con concatenación de cadenas no están cubiertas en esta versión. |
| **No flow-sensitive** | No sigue el flujo de datos entre funciones ni módulos distintos. |

---

## Integración en CI/CD

PyCodeScan devuelve código de salida `1` cuando encuentra vulnerabilidades, lo que
permite usarlo como comprobación de calidad en cualquier pipeline.

### GitHub Actions

```yaml
- name: Ejecutar PyCodeScan
  run: |
    python3 -m pycodescan src/ --no-color
  # El paso fallará automáticamente si exit code != 0
```

### GitLab CI

```yaml
security-scan:
  script:
    - find src -name "*.py" | xargs python3 -m pycodescan --no-color
  allow_failure: false
```

### Pre-commit hook

```bash
# .git/hooks/pre-commit
#!/bin/bash
set -e
FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.py$' || true)
if [ -n "$FILES" ]; then
    python3 -m pycodescan $FILES --no-color
fi
```
