# -*- coding: utf-8 -*-
import os
import csv
from netmiko import ConnectHandler
from ftplib import FTP
from pathlib import Path
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from typing import List, Dict

load_dotenv()

# --- Encryption Setup ---
KEY_FILE = "secret.key"
if not Path(KEY_FILE).exists():
    key = Fernet.generate_key()
    Path(KEY_FILE).write_bytes(key)
else:
    key = Path(KEY_FILE).read_bytes()
CIPHER = Fernet(key)

def encrypt_if_plain(text: str) -> str:
    """Encrypt only if value is plain text (non-empty)."""
    if not text:
        return text
    # basic check for fernet token prefix
    if text.startswith("gAAAA"):
        return text
    return CIPHER.encrypt(text.encode()).decode()

def decrypt_if_needed(text: str) -> str:
    if text and text.startswith("gAAAA"):
        return CIPHER.decrypt(text.encode()).decode()
    return text

# --- Load and update .env ---
ENV_FILE = ".env"

def update_env_var(key, value):
    """Update .env file safely (create if missing)."""
    lines = []
    found = False
    if Path(ENV_FILE).exists():
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith(f"{key}="):
                    lines.append(f"{key}={value}\n")
                    found = True
                else:
                    lines.append(line)
    if not found:
        lines.append(f"{key}={value}\n")
    with open(ENV_FILE, "w", encoding="utf-8") as f:
        f.writelines(lines)

# Read FTP settings from env
FTP_HOST = os.getenv("FTP_HOST") or ""
FTP_USER = os.getenv("FTP_USERNAME") or ""
FTP_PASS_RAW = os.getenv("FTP_PASSWORD") or ""
FTP_DIR = os.getenv("FTP_UPLOAD_DIR", "/")

# If FTP password is plain, encrypt and update .env
FTP_PASS_ENC = encrypt_if_plain(FTP_PASS_RAW)
if FTP_PASS_ENC and FTP_PASS_ENC != FTP_PASS_RAW:
    update_env_var("FTP_PASSWORD", FTP_PASS_ENC)

# Final FTP password for use (decrypted if needed)
FTP_PASS = decrypt_if_needed(FTP_PASS_ENC)

def upload_via_ftp(local_path: Path) -> None:
    if not FTP_HOST:
        raise ValueError("FTP_HOST is not set in .env")
    with FTP(FTP_HOST, timeout=30) as ftp:
        ftp.login(FTP_USER, FTP_PASS)
        if FTP_DIR and FTP_DIR != "/":
            try:
                ftp.cwd(FTP_DIR)
            except Exception:
                ftp.mkd(FTP_DIR)
                ftp.cwd(FTP_DIR)
        with open(local_path, "rb") as f:
            remote_name = os.path.basename(local_path)
            ftp.storbinary(f"STOR {remote_name}", f)

def backup_switch(hostname: str, ip: str, username: str, password: str) -> Dict:
    """Connect to a single Huawei switch, save config, upload via FTP.
       Returns a dict with result info."""
    # Ensure we have plain password for Netmiko
    password_plain = decrypt_if_needed(encrypt_if_plain(password))

    device = {
        "device_type": "huawei",  # if you encounter issues try 'huawei_vrp'
        "host": ip,
        "username": username,
        "password": password_plain,
        "fast_cli": True,
        "conn_timeout": 30,
        "banner_timeout": 30,
        "auth_timeout": 30,
    }

    result = {"hostname": hostname, "ip": ip, "ok": False, "message": ""}

    try:
        print(f"[*] Connecting to {hostname} ({ip})...")
        with ConnectHandler(**device) as conn:
            # make sure no paged output
            conn.send_command("screen-length 0 temporary", read_timeout=10)
            config = conn.send_command("display current-configuration", read_timeout=120)

        # Save locally
        fname = f"{hostname}.cfg"
        out_dir = Path("backups")
        out_dir.mkdir(exist_ok=True)
        local_path = out_dir / fname
        local_path.write_text(config, encoding="utf-8")

        # Upload
        upload_via_ftp(local_path)

        result["ok"] = True
        result["message"] = f"Backup saved and uploaded: {fname}"
        print(f"[OK] {result['message']}")
    except Exception as e:
        result["message"] = str(e)
        print(f"[!] Failed {hostname} ({ip}): {e}")

    return result

def run_backup(csv_file: str = "switches.csv") -> List[Dict]:
    """Read CSV, encrypt passwords in CSV (if needed), perform backups,
       rewrite CSV with encrypted passwords, and return result list."""
    updated_rows = []
    results = []

    if not Path(csv_file).exists():
        raise FileNotFoundError(f"{csv_file} not found")

    with open(csv_file, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        fieldnames = reader.fieldnames or ["hostname", "ip", "username", "password"]
        for row in reader:
            # make sure expected keys exist
            hostname = row.get("hostname", "").strip()
            ip = row.get("ip", "").strip()
            username = row.get("username", "").strip()
            passwd = row.get("password", "").strip()

            # encrypt in-memory and for saving back to CSV
            passwd_enc = encrypt_if_plain(passwd)
            row["password"] = passwd_enc
            updated_rows.append(row)

            # run backup using possibly-encrypted password (function will decrypt)
            res = backup_switch(hostname=hostname, ip=ip, username=username, password=passwd_enc)
            results.append(res)

    # rewrite CSV with encrypted passwords
    with open(csv_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(updated_rows)

    return results

# Provide a simple CLI entrypoint
if __name__ == "__main__":
    import pprint
    results = run_backup()
    pprint.pprint(results)
