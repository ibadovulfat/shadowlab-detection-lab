# Detect It Easy Integration

ShadowLab uses Detect It Easy in the `Static Analysis` workspace for packer, cryptor, compiler, and structural file inspection.

## Backend Order

| Priority | Backend | Source | Requirement |
|----------|---------|--------|-------------|
| 1 | Native binding | `die-python` | `pip install die-python` |
| 2 | Subprocess | `diec.exe` or `die.exe` | `SHADOWLAB_DIEC_PATH` or `PATH` |
| 3 | Fallback | `pefile` | built-in fallback |

ShadowLab always tries the highest-priority backend available.

## Native Binding

The preferred path is `die-python`, which provides:

- an embedded native DiE library
- the DiE signature database
- direct Python access without an external executable
- worker-isolated execution so a native fault does not take down the main API process

Install it with:

```powershell
pip install die-python
```

Implementation lives in [services/die_binding_service.py](/C:/Users/ulfat/Documents/shadowlab-detection-lab/services/die_binding_service.py).

## Optional CLI Backend

If you still want the external binary path, provide `diec.exe` or `die.exe` through `SHADOWLAB_DIEC_PATH` or `PATH`.

## Status Endpoint

`GET /malware-analyst/status` reports:

- current status
- selected backend
- native binding availability
- native database path
- optional subprocess path

In the desktop client, a native-ready state is shown as `Runtime: ready (native)`. That is expected even when `diec.exe` is not installed, because the preferred path is the native binding rather than the external CLI.

## Packaging Notes

[desktop/shadowlab.spec](/C:/Users/ulfat/Documents/shadowlab-detection-lab/desktop/shadowlab.spec) bundles the `die-python` database when the package is installed.
