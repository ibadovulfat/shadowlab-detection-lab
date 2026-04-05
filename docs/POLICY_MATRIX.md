# Policy Matrix

ShadowLab policy profiles are now backed by a shared matrix so the API, enterprise services, and future operator UX can enforce the same security posture.

## Profiles

- `lab`: canary and deception workflows allowed, destructive controls available, approval optional.
- `corp`: canary remains available in the existing deception area, but destructive controls and remote-impacting actions require approval.
- `prod`: offensive-style controls and deception are off by default, approval remains mandatory, and workspace isolation should be explicit.

## Workspace Direction

- enterprise records should carry `workspace_id`
- local single-node labs can continue to use `default`
- corp and prod should pass explicit workspace IDs from API and desktop flows

This is the first enforcement layer for `7-8` roadmap work: formal policy governance and the start of workspace-aware persistence.

updated

