from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.die_binding_service import DieBindingService


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"status": "error", "summary": "Missing file path argument."}))
        return 2

    target = Path(sys.argv[1]).expanduser()
    service = DieBindingService()
    result = service.scan_file(str(target))
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
