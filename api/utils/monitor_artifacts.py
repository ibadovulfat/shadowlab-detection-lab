"""Monitor-run artifact writer.

Produces the canonical artifact set for a completed monitor run: telemetry
CSV, Defender/Sysmon event summaries, final score, incident bundle, PDF +
HTML reports, and a refreshed integrity manifest.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from report_export import generate_html, generate_pdf
from services.incident_service import IncidentArtifactService


_TELEMETRY_COLUMNS = (
    "ts",
    "cpu",
    "mem_percent",
    "proc_threads",
    "proc_handles",
    "open_files",
    "tcp_conns",
    "bytes_sent_rate",
    "bytes_recv_rate",
    "remote_ips",
)


def write_monitor_artifacts(
    target_dir: Path,
    telemetry_rows: list[dict[str, Any]],
    defender_summary: dict[str, Any],
    sysmon_summary: dict[str, Any],
    final: dict[str, Any],
    report_sections: list[str],
    incident: Any,
    *,
    integrity_service: Any,
    report_author: str = "Ulfat Ibadov",
) -> None:
    """Write all monitor-run artifacts into `target_dir` and refresh the integrity manifest."""
    target_dir.mkdir(parents=True, exist_ok=True)
    with (target_dir / "telemetry.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(list(_TELEMETRY_COLUMNS))
        for row in telemetry_rows:
            writer.writerow(
                [
                    row["ts"],
                    row["cpu"],
                    row["mem_percent"],
                    row["proc_threads"],
                    row["proc_handles"] or "",
                    row["open_files"],
                    row["tcp_conns"],
                    row["bytes_sent_rate"],
                    row["bytes_recv_rate"],
                    row.get("remote_ips", []),
                ]
            )

    (target_dir / "events_defender.json").write_text(
        json.dumps({"summary": defender_summary}, indent=2), encoding="utf-8"
    )
    (target_dir / "events_sysmon.json").write_text(
        json.dumps({"summary": sysmon_summary}, indent=2), encoding="utf-8"
    )
    (target_dir / "score.json").write_text(json.dumps(final, indent=2), encoding="utf-8")
    IncidentArtifactService(target_dir).write_incident_bundle(incident, final, telemetry_rows)
    generate_pdf(target_dir, author=report_author, sections=report_sections)
    generate_html(target_dir, author=report_author)
    integrity_service.refresh_manifest()
