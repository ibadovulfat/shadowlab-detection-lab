from __future__ import annotations

import os

import uvicorn


def main() -> None:
    host = os.environ.get("SHADOWLAB_HOST", "127.0.0.1")
    port = int(os.environ.get("SHADOWLAB_PORT", "8000"))
    uvicorn.run("api.main:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()

