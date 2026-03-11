from __future__ import annotations

from pathlib import Path


YARA_AVAILABLE = False
try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    yara = None


BASE_DIR = Path(__file__).resolve().parent.parent
RULES_DIR = Path(__file__).resolve().parent / "rules"
VENDOR_DIR = Path(__file__).resolve().parent / "vendor" / "signature_base" / "yara"


PACK_FILES: dict[str, list[Path]] = {
    "basic": [RULES_DIR / "basic.yar"],
    "curated": sorted(VENDOR_DIR.glob("*.yar")),
    "hybrid": [RULES_DIR / "basic.yar", *sorted(VENDOR_DIR.glob("*.yar"))],
}


def available_packs() -> list[str]:
    packs: list[str] = []
    for pack, files in PACK_FILES.items():
        existing = [rule for rule in files if rule.exists()]
        if existing:
            packs.append(pack)
    return packs


def compile_rules(pack: str = "basic"):
    if not YARA_AVAILABLE:
        return None

    chosen = pack if pack in PACK_FILES else "basic"
    files = [rule for rule in PACK_FILES.get(chosen, []) if rule.exists()]
    if not files:
        return None

    try:
        if len(files) == 1:
            return yara.compile(filepath=str(files[0]))
        return yara.compile(filepaths={f"ns_{idx}": str(rule) for idx, rule in enumerate(files)})
    except Exception:
        return None


def scan_file(filepath, rules):
    """
    Scans a file with compiled YARA rules.
    """
    if not YARA_AVAILABLE or not rules or not filepath:
        return []

    try:
        matches = rules.match(filepath)
        return [match.rule for match in matches]
    except Exception:
        return []


def scan_process_memory(pid, rules):
    """
    Placeholder for future process-memory scanning path.
    """
    return []

