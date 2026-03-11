# ShadowLab Platform Upgrade

ShadowLab is transitioning from a single-file Streamlit lab app into a layered detection platform.

## Target shape

- `core/`
  Domain models and normalized event schema.
- `services/`
  Orchestration logic for telemetry, detections, and incident artifacts.
- `detections/`
  Rule packs and correlation logic.
- `plugins/`
  Host-native modules for forensic, deception, and response operations.
- `app.py`
  Transitional UI shell until a dedicated Windows desktop client replaces it.

## Strategic direction

The strongest path for this project is a Windows-first desktop security workstation:

- Local agent behavior
- Host-native privileges
- Event log visibility
- Process/network response actions
- Forensics and evidence capture

Web/SaaS can still be layered later for fleet reporting and historical analytics, but local desktop remains the operational control plane.

## New building blocks

### Normalized event model

All detections should converge on a shared structure:

- telemetry sample
- security event
- detection finding
- incident record

This allows the same backend logic to feed:

- current Streamlit UI
- future PySide6 desktop UI
- future API or fleet backend

### Rule engine

`detections/default_rules.yaml` introduces a YAML-driven detection pack so new behaviors can be added without editing the UI layer.

### Incident bundle

`services/incident_service.py` writes a machine-readable incident bundle that can later feed:

- case management
- desktop incident views
- SOC reporting
- fleet sync

## Recommended next phases

1. Replace direct plugin calls in `app.py` with service interfaces.
2. Add Windows persistence coverage beyond macOS-only checks.
3. Move response actions into a dedicated `response_service`.
4. Add a PySide6 desktop shell.
5. Add a lightweight agent mode and local IPC.
6. Add rule packs for LOLBins, ransomware chains, and suspicious parent-child execution.

