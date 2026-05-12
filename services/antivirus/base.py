from __future__ import annotations

from pathlib import Path
from typing import Any


class AntivirusProvider:
    provider_key = "provider"
    display_name = "Provider"

    def status(self) -> dict[str, Any]:
        raise NotImplementedError

    def scan_file(self, path: Path, *, policy: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

