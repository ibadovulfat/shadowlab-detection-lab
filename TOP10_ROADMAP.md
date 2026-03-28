# ShadowLab Roadmap

The core platform is already in place. The next stage is less about adding tabs and more about making the existing workflow deeper, faster, and more reliable.

## Already In Place

- FastAPI backend with RBAC and policy gates
- PySide6 desktop client
- `WHIDS` and `OSSEC/HIDS` integration layer
- process investigation and triage
- persistence review and remediation
- graph, timeline, host, artifact, and history views
- deception, evidence, and quarantine workflows
- enterprise case workflow
- ATT&CK lifecycle and export support
- security-operations posture and reporting
- validation helpers for runtime, auth, integrations, and performance
- layered local YARA with telemetry and tuning

## Next 10 Priorities

### 1. Real-Time Event Delivery

Move more of the operator experience from polling to event-driven refresh where it makes sense.

### 2. Better Entity Modeling

Tighten the links between cases, incidents, hosts, processes, hashes, IPs, tasks, and evidence so graph and timeline output becomes more precise.

### 3. Reporting Quality

Improve PDF and HTML exports so they read better in handoff and leadership review.

### 4. Search And Filter UX

Make large enterprise datasets easier to work with through safer and more expressive filtering.

### 5. Notification Routing

Extend the local notification model into clearer alerting and escalation paths.

### 6. Workspace Recall

Remember more desktop state between sessions so operators can resume work faster.

### 7. Performance Hardening

Reduce heavy refresh paths and improve rendering of large tables and graphs.

### 8. Database Maturity

Deepen PostgreSQL validation and keep migration tooling predictable as datasets grow.

### 9. Packaging And Release Hardening

Improve EXE packaging, diagnostics, versioning, and local update guidance.

### 10. Test Coverage Expansion

Broaden regression coverage around enterprise workflows, security-sensitive paths, and desktop behavior.
