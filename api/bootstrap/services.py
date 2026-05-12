"""Singleton service construction for the ShadowLab API.

Every long-lived orchestrator / service / bridge is instantiated exactly
once at process start. Keeping the wiring here (rather than at the top of
`api/main.py`) shrinks `main.py` and makes the dependency graph explicit:
one function, one place to look for which services exist and how they
compose.

Tests patch individual services via `mock.patch.object(api.main, ...)`, so
`api/main.py` still re-binds each attribute from the returned container
after calling `build_services()`.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from services.alerting_service import AlertingService
from services.antivirus import FolderWatcher, ScanJobQueue
from services.antivirus.credentials import CredentialStore, install_credential_store
from services.antivirus_service import AntivirusService
from services.detection_service import DetectionOrchestrator
from services.enterprise_service import EnterpriseService
from services.fleet_service import FleetService
from services.graph_service import GraphService
from services.hids_integration_service import HidsIntegrationService
from services.incident_service import IncidentArtifactService
from services.integrity_service import IntegrityService
from services.investigation_service import InvestigationService
from services.malware_analyst_service import MalwareAnalystService
from services.migration_service import MigrationService
from services.mitre_service import MitreAttackService
from services.observability import MetricsRegistry, get_registry
from services.observability_service import ObservabilityService
from services.process_intelligence_service import ProcessIntelligenceService
from services.response_service import ResponseOrchestrator
from services.telemetry_service import CollectorTelemetryBridge
from services.timeline_service import TimelineService
from services.webhook_dispatcher import WebhookDispatcher


@dataclass
class ServiceContainer:
    """Holds every singleton service wired at startup."""
    process_intel_service: ProcessIntelligenceService
    response_service: ResponseOrchestrator
    detection_service: DetectionOrchestrator
    artifact_service: IncidentArtifactService
    alert_service: AlertingService
    fleet_service: FleetService
    timeline_service: TimelineService
    investigation_service: InvestigationService
    graph_service: GraphService
    collector_bridge: CollectorTelemetryBridge
    enterprise_service: EnterpriseService
    antivirus_service: AntivirusService
    mitre_service: MitreAttackService
    malware_analyst_service: MalwareAnalystService
    hids_integration_service: HidsIntegrationService
    integrity_service: IntegrityService
    observability_service: ObservabilityService
    migration_service: MigrationService
    # Wave-3 ops services.
    metrics_registry: MetricsRegistry
    scan_job_queue: ScanJobQueue
    webhook_dispatcher: WebhookDispatcher
    folder_watcher: FolderWatcher


def build_services(
    *,
    config: dict[str, Any],
    base_dir: Path,
    out_dir: Path,
    db: Any,
) -> ServiceContainer:
    """Construct every singleton service. Order matters for the services
    that accept others in their constructor (HIDS integration depends on
    enterprise/investigation/response/mitre; enterprise depends on
    process-intel + fleet)."""
    process_intel_service = ProcessIntelligenceService()
    response_service = ResponseOrchestrator()
    detection_service = DetectionOrchestrator()
    artifact_service = IncidentArtifactService(out_dir)
    alert_service = AlertingService()
    fleet_service = FleetService(db)
    timeline_service = TimelineService()
    investigation_service = InvestigationService(timeline_service)
    graph_service = GraphService(out_dir)
    collector_bridge = CollectorTelemetryBridge(config, out_dir)
    enterprise_service = EnterpriseService(base_dir, process_intel_service, fleet_service)
    antivirus_service = AntivirusService(base_dir, db=db)
    mitre_service = MitreAttackService(base_dir, db)
    malware_analyst_service = MalwareAnalystService(base_dir, process_intel_service)
    hids_integration_service = HidsIntegrationService(
        db,
        enterprise_service=enterprise_service,
        investigation_service=investigation_service,
        response_service=response_service,
        mitre_service=mitre_service,
    )
    integrity_service = IntegrityService(base_dir, out_dir)
    observability_service = ObservabilityService(out_dir)
    migration_service = MigrationService(base_dir)
    migration_service.ensure_applied()
    # Wave-3 ops wiring — metrics registry first so the webhook dispatcher
    # can publish into it; the job queue uses the antivirus service we
    # just built; the folder watcher delegates to the queue.
    metrics_registry = get_registry()
    scan_job_queue = ScanJobQueue(antivirus_service, db=db, max_workers=4)
    webhook_dispatcher = WebhookDispatcher(db=db, metrics_registry=metrics_registry)
    folder_watcher = FolderWatcher(scan_submit=scan_job_queue.submit, db=db)
    # Process-shared credential store so every cloud provider reads keys
    # from a single canonical source — desktop-pasted, encrypted-at-rest,
    # restored from `app_settings` on every server boot. Without this,
    # operators who paste keys into the Advanced Hunt panel get no
    # cloud-intel coverage because the providers only saw env vars.
    try:
        from services.secret_store import secret_store as _ss
    except Exception:
        _ss = None
    install_credential_store(CredentialStore(db=db, secret_store=_ss))
    # Hook the metrics registry into the antivirus service so every fused
    # scan emits scan_total + duration histogram + engine status gauges.
    if hasattr(antivirus_service, "attach_metrics"):
        try:
            antivirus_service.attach_metrics(metrics_registry)
        except Exception:
            pass
    return ServiceContainer(
        process_intel_service=process_intel_service,
        response_service=response_service,
        detection_service=detection_service,
        artifact_service=artifact_service,
        alert_service=alert_service,
        fleet_service=fleet_service,
        timeline_service=timeline_service,
        investigation_service=investigation_service,
        graph_service=graph_service,
        collector_bridge=collector_bridge,
        enterprise_service=enterprise_service,
        antivirus_service=antivirus_service,
        mitre_service=mitre_service,
        malware_analyst_service=malware_analyst_service,
        hids_integration_service=hids_integration_service,
        integrity_service=integrity_service,
        observability_service=observability_service,
        migration_service=migration_service,
        metrics_registry=metrics_registry,
        scan_job_queue=scan_job_queue,
        webhook_dispatcher=webhook_dispatcher,
        folder_watcher=folder_watcher,
    )
