# ShadowLab

> Note: Use only in owned, isolated, lab environments.

**Created by [Ulfat Ibadov](https://www.linkedin.com/in/ibadovulfat/)**

ShadowLab is an API-first cybersecurity research platform focused on:

- behavioral telemetry collection
- Windows event visibility
- process investigation
- persistence hunting
- deception controls
- threat-intelligence enrichment
- incident artifact generation
- advanced hunt workflows across local host telemetry and forensic modules

## Demo Video

A full walkthrough of ShadowLab is available on YouTube:

[Watch the demo](https://www.youtube.com/watch?v=tnK1ilsuWpo)

Detailed operator and feature usage guide:

- `docs/USAGE_GUIDE.md`

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
- ShadowLab telemetry fabric integration for enterprise telemetry export

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
- YARAify-backed hash lookups for on-disk process executables
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
config/      Telemetry fabric runtime and builder manifests
scripts/     Build and operational helper scripts
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

Recommended secure local launch:

```bash
export SHADOWLAB_API_KEYS_SHA256="viewer:<viewer_sha256>,analyst:<analyst_sha256>,admin:<admin_sha256>"
export SHADOWLAB_REQUIRE_AUTH=true
export SHADOWLAB_ALLOWED_ORIGINS="http://127.0.0.1,http://localhost"
python app.py
```

Detailed operational usage:

```text
docs/USAGE_GUIDE.md
```

Desktop client:

```bash
python desktop/main.py
```

Windows EXE packaging:

```powershell
pip install pyinstaller
desktop\build_exe.ps1
```

## Landing Site

A standalone product showcase site is included in:

```text
site/
```

Open it directly:

```text
site/index.html
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
POST /processes/{pid}/yara
POST /processes/{pid}/sandbox-trace
GET  /processes/{pid}/ai-analysis
POST /processes/{pid}/actions/{action}?process_name=...
GET  /persistence
GET  /threat-intel/ip/{ip}
GET  /threat-intel/hash/{sha256}
GET  /history/telemetry
GET  /history/responses
GET  /history/alerts
GET  /history/remediations
GET  /incidents
PATCH /incidents/{incident_id}
POST /persistence/remediate
POST /persistence/rollback/{remediation_id}
GET  /quarantine
POST /quarantine/{quarantine_id}/restore
DELETE /quarantine/{quarantine_id}
GET  /timeline
GET  /timeline/graph
GET  /hosts
GET  /graph/entity-map
GET  /graph/entity-map/html
POST /alerts/test
POST /alerts/configure
POST /agents/register
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
GET  /reports/html
GET  /artifacts
GET  /artifacts/{filename}
GET  /integrations/telemetry-fabric/status
POST /integrations/telemetry-fabric/start
POST /integrations/telemetry-fabric/stop
POST /integrations/telemetry-fabric/export/incidents/{incident_id}
GET  /integrations/telemetry-fabric/exports
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
curl -X POST http://127.0.0.1:8000/processes/<pid>/yara -H "Content-Type: application/json" -d "{\"yaraify_auth_key\": \"<key>\"}"
```

Run one-click auto triage:

```bash
curl -X POST http://127.0.0.1:8000/triage/<pid> ^
  -H "Content-Type: application/json" ^
  -d "{\"virustotal_api_key\": \"<vt>\", \"malwarebazaar_auth_key\": \"<mb>\", \"yaraify_auth_key\": \"<yaraify>\", \"trace_duration\": 3, \"strings_min_length\": 4, \"strings_patterns\": [\"http\", \"password\"]}"
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
- `SHADOWLAB_API_KEY`
- `SHADOWLAB_API_KEY_SHA256`
- `SHADOWLAB_API_KEYS` (format: `viewer:key,analyst:key,admin:key`)
- `SHADOWLAB_API_KEYS_SHA256` (format: `viewer:sha256,analyst:sha256,admin:sha256`)
- `SHADOWLAB_REQUIRE_AUTH`
- `SHADOWLAB_ALLOWED_ORIGINS`
- `SHADOWLAB_ENABLE_DANGEROUS_ACTIONS`
- `SHADOWLAB_ENABLE_NETWORK_WARFARE`
- `SHADOWLAB_ALLOW_FILE_DELETE`
- `SHADOWLAB_OTLP_HTTP_ENDPOINT`
- `SHADOWLAB_OTELCOL_BIN`
- `SHADOWLAB_OTELCOL_CONFIG`
- `SHADOWLAB_OTEL_ZPAGES_URL`

## Telemetry Fabric Integration

ShadowLab now exports monitor-session metrics, incident logs, and run traces to its telemetry fabric over OTLP/HTTP while keeping ShadowLab as the primary platform.

Bundled telemetry runtime configuration:

```text
config/telemetry-fabric-runtime.yaml
```

Bundled telemetry builder manifest:

```text
config/telemetry-fabric-builder.yaml
```

Windows build helper:

```text
scripts/build_telemetry_fabric.ps1
```

Default integration flow:

- ShadowLab continues generating telemetry, detections, and incident artifacts locally.
- `POST /monitor/run` automatically pushes OTLP metrics, logs, and traces when `telemetry_fabric.enabled` is true.
- Export attempts are audited in the `integration_export_log` table and exposed via `GET /integrations/telemetry-fabric/exports`.
- Telemetry fabric lifecycle can be managed through the new API start, stop, and status endpoints.
- A custom Windows telemetry binary can be generated from the upstream collector builder with `scripts/build_telemetry_fabric.ps1`.

## Desktop Path

The future EXE route starts in:

- [desktop/main.py](desktop/main.py)
- [desktop/README.md](desktop/README.md)
- `docs/USAGE_GUIDE.md`

The desktop now exposes:

- Overview with monitor output and CPU trend chart
- Processes with profile, response actions, memory analysis, internals, strings, YARA, sandbox trace, process tree, AI analyst, and auto triage
- Persistence with remediation actions
- Threat Intel with lookup history and process auto-fill
- Network, Hosts, Timeline, Quarantine, History, Artifacts, Scenarios
- Deception tab for honeypot, canary, and evidence locker workflows
- toolbar shortcuts with custom button support

This keeps the backend reusable while allowing a native Windows client and packaged EXE path.

## YARAify

ShadowLab currently uses `YARAify` for YARA-backed enrichment and hash lookups.

Current behavior:

- `POST /processes/{pid}/yara` resolves the process hash and queries YARAify
- `POST /triage/{pid}` includes YARAify enrichment when a `yaraify_auth_key` is supplied
- `POST /threat-intel/hash/lookup` can query YARAify directly by hash

Desktop usage:

- put only your abuse.ch `Auth Key` into the `YARAify Auth-Key` field
- do not paste `curl`, `wget`, `Auth-Key:` labels, or quotes

## Verification Status

Latest local validation completed for:

- FastAPI app import
- route registration
- Python syntax compilation of backend, services, desktop, and scripts
- backend health check
- telemetry fabric runtime validation
- smoke checks for monitor export and integration status

## Safety

This repository includes research-oriented and lab-only capabilities. Do not use offensive or disruptive network features outside systems and networks you own and control.
