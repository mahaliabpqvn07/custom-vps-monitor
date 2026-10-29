#!/usr/bin/env python3
"""Create configuration for a self-registering VPS monitor over plain HTTP."""
import getpass, json, secrets
from pathlib import Path
host = input("Bind host [0.0.0.0]: ").strip() or "0.0.0.0"
port = int(input("HTTP port [8080]: ").strip() or "8080")
admin_user = input("Dashboard username [admin]: ").strip() or "admin"
admin_password = input("Set a strong dashboard password (16+ chars): ").strip()
if len(admin_password) < 16:
    raise SystemExit("Password must be at least 16 characters.")
enrollment_key = secrets.token_urlsafe(40)
last_block_api_url = input("Last Block API URL [http://157.230.45.47:22825/api/1.0]: ").strip() or "http://157.230.45.47:22825/api/1.0"
last_block_api_key = getpass.getpass("Last Block API_KEY (input hidden): ").strip()
last_block_from_block = input("Fallback fromBlockId [184846]: ").strip() or "184846"
config = {"host": host, "port": port, "offline_after_seconds": 180,
          "admin_user": admin_user, "admin_password": admin_password,
          "enrollment_key": enrollment_key,
          "last_block_api_url": last_block_api_url,
          "last_block_api_key": last_block_api_key,
          "last_block_file": str(Path(__file__).resolve().parent / "lastBlock.txt"),
          "last_block_from_block": last_block_from_block}
Path("config.json").write_text(json.dumps(config, indent=2) + "\n")
Path("config.json").chmod(0o600)
Path("enrollment-key.txt").write_text(enrollment_key + "\n")
Path("enrollment-key.txt").chmod(0o600)
print("Created config.json and enrollment-key.txt. Keep both private.")
print("Pass the enrollment key to agent.sh as argument 2 or set VPSMON_ENROLLMENT_KEY externally.")
print("Last Block API settings are stored in config.json (permissions 0600).")
print("Dashboard URL: http://PUBLIC_IP:%d/ (replace PUBLIC_IP with this server's public IP)" % port)
print("WARNING: HTTP is unencrypted. Restrict port %d to trusted IPs or use a VPN." % port)
