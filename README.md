# ShadowLab

> Note: Use only in owned, isolated, lab environments.

**Created by [Ulfat Ibadov](https://www.linkedin.com/in/ibadovulfat/)**

![banner](static/shadowlab_banner.png)

ShadowLab is an API-first cybersecurity research platform focused on:

- behavioral telemetry collection
- Windows event visibility
- process investigation
- persistence hunting
- deception controls
- threat-intelligence enrichment
- incident artifact generation
- advanced hunt workflows across local host telemetry and forensic modules

The project is now **API-first**. Streamlit has been removed from runtime. Current architecture:

- `FastAPI` backend for Docker and automation
- `desktop/` PySide6 client for the Windows EXE path
- modular `services/`, `core/`, and `detections/` layers

## Focus Areas

- local host visibility
- investigation workflows
- detection scoring and rule correlation
- safer response actions
- operator-driven triage and case handling
- portable backend for Docker or future UI clients

## Key Capabilities

- Telemetry monitoring with CPU, memory, thread, handle, file, TCP, and bandwidth metrics
- Windows Defender and Sysmon event summarization
- Rule-based and scored behavioral detections
- Incident bundle generation
- Incident and case lifecycle storage
- Timeline, host inventory, and quarantine tracking
- Process intelligence with command line, SHA-256, and signature status
- Persistence discovery on Windows and macOS
- Persistence remediation for supported Windows startup mechanisms
- Response orchestration with audited `suspend`, `resume`, and `kill`
- Advanced response actions including `kill-tree` and `quarantine`
- Threat intel enrichment with VirusTotal, MalwareBazaar, and AbuseIPDB
- Simulated memory-forensics workflow
- Auto triage endpoint for one-shot process investigation
- Host inventory, timeline, quarantine center, and webhook alerting
- Process internals review for open handles and loaded modules
- Binary string extraction with keyword hit surfacing
- YARA scanning of on-disk process executables
- Curated external YARA pack sourced from Neo23x0 Signature-Base plus local basic rules
- Sandbox-style trace of new file and network activity
- Process tree and AI-analyst summaries
- Honeypot, ransomware canary, and evidence-locker controls
- ARP discovery and lab-only network warfare controls
- PySide6 desktop client with overview, hunt, threat intel, network, incidents, artifacts, and FAQ views

## Project Layout

```text
api/         FastAPI entrypoint and routes
core/        Domain models and normalization
services/    Telemetry, detection, process, response, incident services
detections/  YAML rule packs and rule engine
plugins/     Host-native forensic, persistence, sniffer, and lab modules
desktop/     PySide6 desktop client
static/      Branding, banner, and icon assets
```

## Quickstart

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux / macOS
source venv/bin/activate

pip install -r requirements.txt
python app.py
```

API starts on `http://127.0.0.1:8000`.

Desktop client:

```bash
python desktop/main.py
```

Windows EXE packaging:

```powershell
pip install pyinstaller
desktop\build_exe.ps1
```

## Docker

```bash
docker build -t shadowlab-api .
docker run --rm -p 8000:8000 --name shadowlab shadowlab-api
```

## Main API Endpoints

```text
GET  /health
GET  /config
POST /monitor/run
GET  /processes
GET  /processes/{pid}
POST /processes/{pid}/scan
GET  /processes/{pid}/memory-analysis?process_name=...
GET  /processes/{pid}/tree
GET  /processes/{pid}/internals
POST /processes/{pid}/strings
GET  /processes/{pid}/yara
POST /processes/{pid}/sandbox-trace
GET  /processes/{pid}/ai-analysis
POST /processes/{pid}/actions/{action}?process_name=...
GET  /persistence
GET  /threat-intel/ip/{ip}
GET  /threat-intel/hash/{sha256}
GET  /history/telemetry
GET  /history/responses
GET  /incidents
PATCH /incidents/{incident_id}
POST /persistence/remediate
GET  /quarantine
POST /quarantine/{quarantine_id}/restore
DELETE /quarantine/{quarantine_id}
GET  /timeline
GET  /hosts
POST /alerts/test
POST /alerts/configure
POST /triage/{pid}
POST /scenario/run
POST /deception/honeypot/deploy
GET  /deception/honeypot/status
DELETE /deception/honeypot
POST /deception/canary/deploy
GET  /deception/canary/status
DELETE /deception/canary
POST /evidence/capture
GET  /evidence
DELETE /evidence/{filename}
GET  /network/connections
POST /network/sniff
POST /network/warfare/scan
POST /network/warfare/block
DELETE /network/warfare/block
GET  /artifacts
GET  /artifacts/{filename}
```

## Example Requests

Run a monitor session:

```bash
curl -X POST http://127.0.0.1:8000/monitor/run ^
  -H "Content-Type: application/json" ^
  -d "{\"duration\": 30, \"interval\": 1.0}"
```

List processes:

```bash
curl http://127.0.0.1:8000/processes
```

Query a hash in MalwareBazaar:

```bash
curl http://127.0.0.1:8000/threat-intel/hash/<sha256>
```

Run deeper hunt on a process:

```bash
curl http://127.0.0.1:8000/processes/<pid>/internals
curl -X POST http://127.0.0.1:8000/processes/<pid>/strings -H "Content-Type: application/json" -d "{\"min_length\": 4, \"patterns\": [\"http\", \"password\"]}"
curl http://127.0.0.1:8000/processes/<pid>/yara
```

Run one-click auto triage:

```bash
curl -X POST http://127.0.0.1:8000/triage/<pid> ^
  -H "Content-Type: application/json" ^
  -d "{\"yara_pack\": \"hybrid\", \"trace_duration\": 3, \"strings_min_length\": 4, \"strings_patterns\": [\"http\", \"password\"]}"
```

## Environment Variables

Optional threat-intelligence configuration:

- `ABUSEIPDB_API_KEY`
- `MALWAREBAZAAR_AUTH_KEY`

Per-request configuration:

- VirusTotal API key is currently supplied to `POST /processes/{pid}/scan`

Runtime configuration:

- `SHADOWLAB_HOST`
- `SHADOWLAB_PORT`

## Desktop Path

The future EXE route starts in:

- [desktop/main.py](desktop/main.py)
- [desktop/README.md](desktop/README.md)

The desktop now exposes:

- Overview with monitor output and CPU trend chart
- Processes with profile, response actions, memory analysis, internals, strings, YARA, sandbox trace, process tree, AI analyst, and auto triage
- Persistence with remediation actions
- Threat Intel with lookup history and process auto-fill
- Network, Hosts, Timeline, Quarantine, History, Artifacts, Scenarios
- Deception tab for honeypot, canary, and evidence locker workflows
- toolbar shortcuts with custom button support

This keeps the backend reusable while allowing a native Windows client and packaged EXE path.

## YARA Packs

ShadowLab supports three YARA pack modes:

- `basic`: local project rules only
- `curated`: selected external rules vendored from Neo23x0 Signature-Base
- `hybrid`: local `basic` rules plus the curated external pack

The desktop client exposes this as the `YARA Rule Pack` selector.

Vendored curated rules live in:

- `plugins/vendor/signature_base/yara/`

Source attribution:

- [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)
- license mirrored in `plugins/vendor/signature_base/LICENSE`

## Verification Status

Latest local validation completed for:

- FastAPI app import
- route registration
- Python syntax compilation of key modules
- backend health check
- smoke tests for `/hosts`, `/timeline`, `/incidents`, and `/triage/{pid}`

## Safety

This repository includes research-oriented and lab-only capabilities. Do not use offensive or disruptive network features outside systems and networks you own and control.
