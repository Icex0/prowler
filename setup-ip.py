#!/usr/bin/env python3
"""Configure Prowler to bind to a specific IP address.

Updates .env, Caddyfile, and docker-compose.yml so that all services
are accessible on the given IP through a Caddy reverse proxy.

Usage:
    python3 setup-ip.py <IP_ADDRESS>
    python3 setup-ip.py 172.25.1.3
"""

import re
import sys
from pathlib import Path


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <IP_ADDRESS>")
        sys.exit(1)

    ip = sys.argv[1]

    # Basic IP validation
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        print(f"Error: '{ip}' is not a valid IPv4 address")
        sys.exit(1)

    base = Path(__file__).parent

    # --- .env ---
    env_file = base / ".env"
    if not env_file.exists():
        print("Error: .env not found. Copy .env from the Prowler repo first.")
        sys.exit(1)

    env = env_file.read_text()

    replacements = {
        r"^AUTH_URL=.*$": f"AUTH_URL=http://{ip}",
        r"^DJANGO_ALLOWED_HOSTS=.*$": f"DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1,prowler-api,{ip}",
    }

    for pattern, replacement in replacements.items():
        env = re.sub(pattern, replacement, env, flags=re.MULTILINE)

    # Ensure NEXT_PUBLIC_API_BASE_URL is explicit (not a variable reference)
    env = re.sub(
        r"^NEXT_PUBLIC_API_BASE_URL=.*$",
        "NEXT_PUBLIC_API_BASE_URL=http://prowler-api:8080/api/v1",
        env,
        flags=re.MULTILINE,
    )

    env_file.write_text(env)
    print(f"Updated .env")

    # --- docker-compose.yml ---
    compose_file = base / "docker-compose.yml"
    if not compose_file.exists():
        print("Error: docker-compose.yml not found.")
        sys.exit(1)

    compose = compose_file.read_text()

    # Replace BIND_IP default
    compose = re.sub(
        r'\$\{BIND_IP:-[\d.]+\}',
        f'${{BIND_IP:-{ip}}}',
        compose,
    )

    compose_file.write_text(compose)
    print(f"Updated docker-compose.yml")

    # --- Caddyfile ---
    caddyfile = base / "Caddyfile"
    caddyfile.write_text(
        """:80 {
\thandle /api/v1/* {
\t\treverse_proxy prowler-api:8080 {
\t\t\theader_up Host prowler-api:8080
\t\t\theader_up Origin http://localhost
\t\t}
\t}

\thandle {
\t\treverse_proxy ui:3000
\t}
}
"""
    )
    print(f"Created Caddyfile")

    print(f"\nDone. Services will bind to {ip}.")
    print("Run: docker compose down && docker compose up -d")


if __name__ == "__main__":
    main()
