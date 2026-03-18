from __future__ import annotations

import hashlib
import secrets


def build_key() -> str:
    return secrets.token_urlsafe(24)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def main() -> None:
    roles = ["viewer", "analyst", "admin"]
    raw = {role: build_key() for role in roles}
    hashed = {role: sha256_hex(token) for role, token in raw.items()}

    print("Raw API keys:")
    for role in roles:
        print(f"- {role}: {raw[role]}")

    print("\nSHA-256 digests:")
    for role in roles:
        print(f"- {role}: {hashed[role]}")

    joined = ",".join(f"{role}:{hashed[role]}" for role in roles)
    print("\nEnvironment example:")
    print(f'SHADOWLAB_API_KEYS_SHA256="{joined}"')


if __name__ == "__main__":
    main()
