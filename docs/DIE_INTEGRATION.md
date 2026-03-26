# Detect It Easy (DiE) Integration

> ShadowLab uses Detect It Easy for automated packer, cryptor, and compiler detection inside the `Static Analysis` workspace.

## Backend Priority

| Priority | Backend | Source | Requires |
|----------|---------|--------|----------|
| 1 | Native binding | `die-python` | `pip install die-python` |
| 2 | Subprocess | `diec.exe` / `die.exe` | `SHADOWLAB_DIEC_PATH` or `PATH` |
| 3 | pefile-only | `pefile` | Always available |

The system automatically selects the highest-priority backend available. If the native binding fails mid-scan, ShadowLab falls back to subprocess, then to `pefile`.

## Native Binding

The preferred backend uses `die-python`, which provides:

- bundled native DiE library
- bundled DiE signature database
- Python API access without requiring an external `.exe`
- worker-isolated execution so the main API process is not taken down by native binding faults

Installation:

```powershell
pip install die-python
```

ShadowLab wraps the binding in [services/die_binding_service.py](/C:/Users/ulfat/Documents/shadowlab-detection-lab/services/die_binding_service.py).

## Optional Subprocess Backend

If you still want to use the CLI backend, set `SHADOWLAB_DIEC_PATH` or place `diec.exe` / `die.exe` on `PATH`.

Discovery order:

1. `SHADOWLAB_DIEC_PATH`
2. `diec` / `die` on `PATH`
3. `%LocalAppData%\Programs\Detect It Easy\diec.exe`
4. `C:\Program Files\Detect It Easy\diec.exe`

## Status Endpoint

`GET /malware-analyst/status` reports:

- overall `status`
- selected `backend`
- native binding availability
- native database path
- optional subprocess path

## Packaging

[desktop/shadowlab.spec](/C:/Users/ulfat/Documents/shadowlab-detection-lab/desktop/shadowlab.spec) bundles the `die-python` database automatically when the package is installed.

No `tools/die/` companion folder is required anymore.

## Reliability Notes

- the desktop `Refresh DIE Status` action now preserves the last analysis result instead of overwriting the summary/output panes
- embedded marker scanning is streamed in chunks instead of loading the entire target file into memory at once
