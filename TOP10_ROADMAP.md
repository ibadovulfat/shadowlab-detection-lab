# ShadowLab Roadmap

The core platform is already in place. The next stage is less about adding more tabs and more about making the existing investigation, containment, reporting, and enterprise workflows deeper, faster, safer, and easier to operate.

## Already In Place

- FastAPI backend with RBAC, policy gates, signing, middleware, and route modules
- PySide6 desktop client with current workspaces: `Dashboards`, `WHIDS`, `HIDS`, `Overview`, `Processes`, `Persistence`, `File Analysis`, `Network`, `Graph`, `Timeline`, `Antivirus`, `History`, `Artifacts`, `Enterprise`, `Security Ops`, and `About / FAQ`
- WHIDS and OSSEC/HIDS integration layer
- process investigation, risk scoring, and triage
- persistence review and remediation
- file analysis with Detect It Easy and PE fallback
- network telemetry, packet capture, ARP discovery, graph, and timeline
- antivirus verdict, quarantine, response, watcher, webhook, rules, and list workflows
- enterprise case workflow and ATT&CK lifecycle/export support
- security-operations posture, integrity, observability, secrets, and reporting
- validation helpers for runtime, auth, integrations, network ops, detection corpus, and performance
- layered local YARA with telemetry and tuning

## Next 10 Priorities

### 1. Real-Time Event Delivery

Move more of the operator experience from polling to event-driven refresh where it makes sense, especially for antivirus verdicts, timeline events, connector queue state, and high-severity incident changes.

### 2. Better Entity Modeling

Tighten the links between cases, incidents, hosts, processes, hashes, IPs, files, antivirus verdicts, tasks, and evidence so graph and timeline output becomes more precise.

### 3. Reporting Quality

Improve PDF, HTML, security-ops, and enterprise exports so they read better in handoff and leadership review.

### 4. Search And Filter UX

Make large process, antivirus, enterprise, audit, and artifact datasets easier to work with through safer and more expressive filtering.

### 5. Notification Routing

Extend the local notification model into clearer alerting and escalation paths.

### 6. Workspace Recall

Remember more desktop state between sessions so operators can resume work faster without re-entering every filter and panel choice.

### 7. Performance Hardening

Reduce heavy refresh paths and improve rendering of large tables, graphs, timeline views, and antivirus histories.

### 8. Database Maturity

Deepen PostgreSQL validation and keep migration tooling predictable as datasets grow.

### 9. Packaging And Release Hardening

Improve EXE packaging, diagnostics, versioning, SBOM generation, dependency scanning, and local update guidance.

### 10. Test Coverage Expansion

Broaden regression coverage around enterprise workflows, security-sensitive paths, antivirus containment, network actions, signed requests, and desktop behavior.
