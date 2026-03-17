"""
Insecure "all-in-one" example — covers every vulnerability category.
DO NOT USE IN PRODUCTION — intentional vulnerabilities for PyCodeScan testing.
"""
import os
import subprocess
import pickle
import marshal
import hashlib
import yaml
import random
import tempfile
import shelve


# ── Hardcoded secrets ────────────────────────────────────────────────────────
password          = "P@ssw0rd_SuperSecure"
api_key           = "AIzaSyFAKEGoogleAPIKeyXXXXXXXXXXXXXXXX"
secret_key        = "django-insecure-hardcoded-secret-key-12345"
jwt_secret        = "myjwtsecretdonotshare"
db_password       = "root_db_password_2024"
aws_secret        = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
smtp_password     = "smtp_pass_hunter2"
credentials       = "user:plaintext_password"
access_token      = "ya29.FakeGoogleOAuthAccessToken"
signing_key       = "hmac-sha256-signing-key-plaintext"


# ── eval / exec / compile ────────────────────────────────────────────────────
def calculate(expression: str):
    """User-supplied math — CRITICAL: eval() enables RCE."""
    return eval(expression)


def run_dynamic_code(code: str):
    """Execute code from string — CRITICAL: exec() enables RCE."""
    exec(code)


def load_plugin(source: str):
    """Compile and run plugin code — HIGH: compile() + exec()."""
    code_obj = compile(source, "<plugin>", "exec")
    exec(code_obj)


def import_module_dynamic(name: str):
    """Import module by name — HIGH: __import__() with dynamic arg."""
    module = __import__(name)
    return module


# ── OS / shell commands ──────────────────────────────────────────────────────
def check_host(host: str):
    """Ping a host — HIGH: os.system() Command Injection."""
    os.system("ping -c1 " + host)


def read_remote_file(path: str):
    """Read file via shell — HIGH: os.popen() Command Injection."""
    return os.popen("cat " + path).read()


def run_query(query: str):
    """Run a grep — HIGH: subprocess.getoutput() Command Injection."""
    return subprocess.getoutput("grep " + query + " access.log")


def build_image(tag: str):
    """Docker build — MEDIUM: subprocess.run() with shell=True."""
    subprocess.run(f"docker build -t {tag} .", shell=True)


def deploy(service: str):
    """Deploy service — MEDIUM: subprocess.call() with shell=True."""
    subprocess.call("systemctl restart " + service, shell=True)


def stream_logs(container: str):
    """Stream logs — MEDIUM: subprocess.Popen() with shell=True."""
    proc = subprocess.Popen(
        f"docker logs -f {container}",
        shell=True,
        stdout=subprocess.PIPE,
    )
    return proc


# ── Insecure deserialization ─────────────────────────────────────────────────
def load_session(blob: bytes):
    """Restore session from bytes — CRITICAL: pickle.loads()."""
    return pickle.loads(blob)


def restore_cache(fh):
    """Load cache from file — CRITICAL: pickle.load()."""
    return pickle.load(fh)


def load_bytecode(raw: bytes):
    """Load marshal bytecode — CRITICAL: marshal.loads()."""
    return marshal.loads(raw)


def open_store(path: str):
    """Open shelve database — LOW: uses pickle internally."""
    return shelve.open(path)


# ── Unsafe YAML ──────────────────────────────────────────────────────────────
def parse_config(stream) -> dict:
    """Parse YAML config — HIGH: yaml.load() without SafeLoader."""
    return yaml.load(stream)


# ── Weak cryptography ────────────────────────────────────────────────────────
def legacy_checksum(data: bytes) -> str:
    """MD5 checksum — MEDIUM: collision-vulnerable."""
    return hashlib.md5(data).hexdigest()


def old_signature(data: bytes) -> str:
    """SHA-1 signature — MEDIUM: cryptographically weak."""
    return hashlib.sha1(data).hexdigest()


# ── Insecure randomness ──────────────────────────────────────────────────────
def make_token() -> float:
    """Generate a float token — LOW: non-CSPRNG."""
    return random.random()


def pick_winner(participants: list):
    """Pick a winner — LOW: predictable PRNG."""
    return random.choice(participants)


def otp_code() -> int:
    """Generate OTP — LOW: predictable PRNG."""
    return random.randint(100000, 999999)


# ── TOCTOU race condition ────────────────────────────────────────────────────
def save_upload(data: str) -> str:
    """Save uploaded data to temp file — MEDIUM: mktemp() race condition."""
    name = tempfile.mktemp()
    with open(name, "w") as fh:
        fh.write(data)
    return name
