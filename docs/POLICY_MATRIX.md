# Policy Matrix

ShadowLab policy profiles are backed by a shared matrix so the API, enterprise services, desktop capability state, and future operator UX can enforce the same security posture.

## Profiles

- `lab`: investigation, integration, and controlled lab workflows are available; dangerous actions and network warfare are still disabled unless explicit feature flags are enabled.
- `corp`: shared-team posture; approval remains important, workspace scoping should be explicit, and offensive-style controls should stay disabled.
- `prod`: production posture; offensive-style controls are disabled, approval remains mandatory, and workspace isolation should be explicit.

## Feature Flags

- `SHADOWLAB_ENABLE_DANGEROUS_ACTIONS`: enables dangerous response categories when the active policy permits them.
- `SHADOWLAB_ENABLE_NETWORK_WARFARE`: enables network-warfare routes only when dangerous actions and policy also allow them.
- `SHADOWLAB_ALLOW_FILE_DELETE`: enables destructive evidence/quarantine file deletion only when the caller is admin and policy allows it.

## Capability Examples

- `can_run_sniffer`: analyst/admin packet capture workflow.
- `can_run_hunt`: analyst/admin investigation and discovery workflow.
- `can_manage_network_warfare`: admin-only network blocker workflow with dangerous actions and network warfare enabled.
- `can_manage_process_actions`: admin-only process response workflow with dangerous actions enabled.
- `can_manage_integrations`: admin integration management workflow.

## Workspace Direction

- enterprise records should carry `workspace_id`
- local single-node labs can continue to use `default`
- corp and prod should pass explicit workspace IDs from API and desktop flows
- secrets, exports, audit streams, and connector activity should remain scoped to the correct workspace

This is the enforcement layer for formal policy governance and workspace-aware persistence.
