"""JSON log formatter + `configure_json_logging()` entrypoint.

The default stdlib formatter produces human-readable text that's great
in a dev tail but terrible to parse downstream. For anyone forwarding
the app's stdout into Loki / ELK / Splunk, we want one JSON object per
log line with a stable schema.

`configure_json_logging()` is idempotent — calling it twice does not
attach the handler twice. We guard via a sentinel attribute on the root
logger so re-imports during test collection don't produce duplicate
entries.
"""
from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any


_CONFIGURED_SENTINEL = "_shadowlab_json_logging_configured"

# Record attributes that the stdlib sets on every `LogRecord`. Anything
# NOT in this set is user-provided via `logger.info(..., extra={...})`
# and gets included in the JSON output as top-level fields.
_STDLIB_RECORD_ATTRS = frozenset({
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "asctime", "taskName",
})


class JsonLogFormatter(logging.Formatter):
    """Render each `LogRecord` as a single-line JSON object.

    Output schema:
        {"ts": "<iso8601 UTC>", "level": "INFO", "logger": "...",
         "message": "...", "<extra-key>": <value>, ...}

    Exception info (when present) lands under `"exception"` as a single
    joined string — consumers can split on `\\n` if they need the
    structured frames. Storing it verbatim keeps the log schema flat.
    """

    def format(self, record: logging.LogRecord) -> str:
        # Resolve %s-style args before serialization.
        message = record.getMessage()
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": message,
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = record.stack_info
        # Promote any `extra=` kwargs onto the top-level JSON object.
        for key, value in record.__dict__.items():
            if key in _STDLIB_RECORD_ATTRS or key.startswith("_"):
                continue
            # Best-effort JSON serialization — fall back to str() for
            # objects without a dict/list representation.
            try:
                json.dumps(value)
                payload[key] = value
            except (TypeError, ValueError):
                payload[key] = str(value)
        return json.dumps(payload, ensure_ascii=False)


def configure_json_logging(
    *,
    level: int = logging.INFO,
    stream=None,
) -> None:
    """Install `JsonLogFormatter` on the root logger. Idempotent.

    The sentinel flag on the root logger prevents duplicate handler
    attachment if this function is called twice (e.g. once from
    `api.main` import and once from a test fixture). Production code
    should call this once from the process entrypoint.
    """
    root = logging.getLogger()
    if getattr(root, _CONFIGURED_SENTINEL, False):
        root.setLevel(level)
        return

    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(JsonLogFormatter())
    # Replace any default handler that stdlib auto-added during import.
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)
    setattr(root, _CONFIGURED_SENTINEL, True)
