from __future__ import annotations

import logging
import os

import uvicorn


def configure_logging() -> None:
    level_name = (os.environ.get("SHADOWLAB_LOG_LEVEL", "INFO") or "INFO").strip().upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}',
    )


def main() -> None:
    configure_logging()
    host = os.environ.get("SHADOWLAB_HOST", "127.0.0.1")
    port = int(os.environ.get("SHADOWLAB_PORT", "8000"))
    uvicorn.run("api.main:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()

