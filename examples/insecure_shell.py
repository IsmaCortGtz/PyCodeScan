"""
Insecure shell / system operations example.
DO NOT USE IN PRODUCTION — intentional vulnerabilities for PyCodeScan testing.
"""
import os
import subprocess
import tempfile
import random


# --- Hardcoded secrets (BAD) ---
private_key    = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAFAKEKEY..."
AUTH_TOKEN     = "Bearer eyJhbGciOiJIUzI1NiJ9.fakepayload.fakesig"
ftp_password   = "Ftp$Passw0rd!"
encryption_key = "aes256-hardcoded-key-do-not-ship"


def ping_host(hostname: str):
    """Ping a host supplied by the user — Command Injection (BAD)."""
    os.system("ping -c 4 " + hostname)


def read_file(filepath: str) -> str:
    """Read a file via shell — os.popen Command Injection (BAD)."""
    handle = os.popen("cat " + filepath)
    return handle.read()


def run_user_script(script_name: str) -> str:
    """Run a user-provided script name — subprocess Command Injection (BAD)."""
    return subprocess.getoutput("bash " + script_name)


def list_directory(path: str) -> bytes:
    """List a directory using Popen with shell=True (BAD)."""
    proc = subprocess.Popen(
        f"ls -la {path}",
        shell=True,
        stdout=subprocess.PIPE,
    )
    return proc.stdout.read()


def grep_logs(query: str):
    """Search logs — shell=True Command Injection (BAD)."""
    subprocess.call("grep " + query + " /var/log/syslog", shell=True)


def get_disk_info(device: str):
    """Get disk usage — subprocess.getstatusoutput Command Injection (BAD)."""
    status, output = subprocess.getstatusoutput("df " + device)
    return status, output


def write_temp_config(content: str) -> str:
    """Write to a temp file — TOCTOU race via mktemp (BAD)."""
    tmpname = tempfile.mktemp(suffix=".cfg")  # race condition
    with open(tmpname, "w") as fh:
        fh.write(content)
    return tmpname


def generate_session_token(length: int = 32) -> str:
    """Generate a session token — insecure PRNG (BAD)."""
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(random.choice(chars) for _ in range(length))


def roll_otp() -> int:
    """Generate a one-time password — insecure PRNG (BAD)."""
    return random.randint(100000, 999999)
