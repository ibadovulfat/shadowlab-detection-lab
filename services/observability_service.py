from __future__ import annotations

import json
import time
from contextlib import nullcontext
from pathlib import Path
from typing import Any

try:
    import etwtrace as _etwtrace  # type: ignore[import-not-found]
except Exception:  # pragma: no cover
    _etwtrace = None


class ObservabilityService:
    def __init__(self, out_dir: Path):
        self.out_dir = Path(out_dir)
        self.log_path = self.out_dir / "observability.jsonl"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log_event(self, event_type: str, **payload: Any) -> None:
        entry = {"ts": time.time(), "event_type": event_type, **payload}
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=True) + "\n")
        self.mark(event_type)

    def etwtrace_available(self) -> bool:
        return _etwtrace is not None

    def etwtrace_active(self) -> bool:
        return bool(_etwtrace is not None and _etwtrace.is_active())

    def mark(self, name: str) -> None:
        if _etwtrace is None or not self.etwtrace_active():
            return
        try:
            _etwtrace.mark(str(name))
        except Exception:
            return

    def span(self, name: str):
        if _etwtrace is None or not self.etwtrace_active():
            return nullcontext()
        try:
            return _etwtrace.mark_range(str(name))
        except Exception:
            return nullcontext()

    def summary(self, limit: int = 200) -> dict[str, Any]:
        events = self.tail(limit=limit)
        counts: dict[str, int] = {}
        for item in events:
            key = str(item.get("event_type", "unknown"))
            counts[key] = counts.get(key, 0) + 1
        return {
            "log_path": str(self.log_path),
            "event_count": len(events),
            "by_type": counts,
            "recent": events[-20:],
            "etwtrace_available": self.etwtrace_available(),
            "etwtrace_active": self.etwtrace_active(),
        }

    def tail(self, limit: int = 200) -> list[dict[str, Any]]:
        if not self.log_path.exists():
            return []
        lines = self.log_path.read_text(encoding="utf-8").splitlines()[-limit:]
        events: list[dict[str, Any]] = []
        for line in lines:
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                events.append(parsed)
        return events
