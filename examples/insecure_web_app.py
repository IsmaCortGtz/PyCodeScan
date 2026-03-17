"""
Insecure web application example.
DO NOT USE IN PRODUCTION — intentional vulnerabilities for PyCodeScan testing.
"""
import hashlib
import pickle
import subprocess
import yaml


# --- Hardcoded credentials (BAD) ---
DB_PASSWORD     = "super_secret_db_pass_2024!"
API_KEY         = "sk-abcdef1234567890abcdef1234567890"
SECRET_KEY      = "my_jwt_signing_secret_key"
smtp_password   = "email_pass_hunter2"
access_token    = "ghp_RealLookingGitHubTokenXXXXXXXXXXXX"


def get_db_connection(host: str, user: str):
    """Connect to the database — hardcoded password passed as keyword arg."""
    import sqlite3
    # Hardcoded password in keyword argument (BAD)
    conn = sqlite3.connect(database=host)
    return conn


def authenticate_user(username: str, password_input: str) -> bool:
    """Check credentials — uses MD5 for password hashing (BAD)."""
    stored_hash = hashlib.md5(DB_PASSWORD.encode()).hexdigest()   # weak hash
    input_hash  = hashlib.md5(password_input.encode()).hexdigest()
    return stored_hash == input_hash


def evaluate_user_expression(expr: str):
    """Evaluate a math expression submitted via a web form — RCE risk (BAD)."""
    result = eval(expr)   # CRITICAL: user input reaches eval()
    return result


def run_report(report_name: str):
    """Generate a report by running an external script — Command Injection (BAD)."""
    output = subprocess.getoutput("python3 reports/" + report_name)
    return output


def load_user_profile(raw_bytes: bytes):
    """Deserialise a user profile from a cookie — insecure deserialisation (BAD)."""
    return pickle.loads(raw_bytes)   # CRITICAL: untrusted data


def load_app_config(config_path: str) -> dict:
    """Load YAML config without a safe loader (BAD)."""
    with open(config_path) as fh:
        return yaml.load(fh)   # HIGH: no Loader specified


def search_logs(keyword: str):
    """Search application logs — shell injection (BAD)."""
    subprocess.run("grep " + keyword + " /var/log/app.log", shell=True)


def hash_api_key(raw_key: str) -> str:
    """Hash an API key for storage — SHA-1 is too weak (BAD)."""
    return hashlib.sha1(raw_key.encode()).hexdigest()
