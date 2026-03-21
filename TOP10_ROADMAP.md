# ShadowLab Roadmap

This roadmap is updated for the current product state. A large part of the original core build is already in place, so the next wave is more about depth, resilience, and operator polish than basic capability coverage.

## Completed Foundation

These are already present in the project:

- FastAPI backend with RBAC and feature gating
- PySide6 desktop client
- WHIDS and OSSEC/HIDS integration layer
- process investigation and auto triage
- persistence review and remediation workflow
- graph, timeline, host, artifact, and history surfaces
- deception, evidence, and quarantine workflows
- enterprise case workflow with assignments, tasks, notes, stories, pins, timeline, notifications, and report export
- enterprise MITRE ATT&CK lifecycle, coverage, Navigator export, Workbench export, and technique-aware response mapping
- security-ops workspace with integrity, observability, readiness, secrets, and reporting
- deployment validation, RBAC smoke testing, live integration smoke testing, and performance/dedupe probes

## Next 10 Priorities

## 1. Real-Time Event Delivery

- move from timed refresh to event-driven updates where practical
- reduce full workspace reloads
- improve operator awareness during active investigations

## 2. Stronger Entity Relationship Modeling

- formalize links between case, incident, task, note, story, pin, host, process, IP, and hash
- make linked-entity views more precise
- improve case-scoped graph quality

## 3. Richer Executive Reporting

- improve PDF and HTML layout quality
- add clearer management summary sections
- tighten language for handoff and review use cases

## 4. Advanced Search And Filter UX

- deepen enterprise filtering beyond simple text matches
- add safer structured query options
- improve fast drill-down on large case/task/activity datasets

## 5. Notification Routing

- extend local notification center into alert routing and escalation paths
- support richer connector-aware notifications
- distinguish informational, warning, and urgent items more clearly

## 6. State Persistence And Workspace Recall

- remember more desktop context between sessions
- preserve preferred layouts and filters
- shorten resume time for repeat operators

## 7. Performance Hardening

- reduce expensive UI refresh paths
- optimize large table population and graph rendering
- make enterprise-heavy workflows smoother on lower-end systems

## 8. Database Maturity

- deepen PostgreSQL runtime validation
- tighten migration tooling and data consistency checks
- prepare for larger investigation datasets

## 9. Packaging And Release Hardening

- finalize cleaner EXE shipping path
- improve packaging diagnostics and version metadata
- document safer local installation and update flows

## 10. Test Coverage Expansion

- add more regression coverage around enterprise workflows
- broaden auth and approval tests
- add UI smoke coverage where practical

## Recommended Build Order

1. Real-Time Event Delivery
2. Stronger Entity Relationship Modeling
3. Performance Hardening
4. Richer Executive Reporting
5. Test Coverage Expansion
