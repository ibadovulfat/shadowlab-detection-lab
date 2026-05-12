from __future__ import annotations


class MonitorWorkspaceController:
    def __init__(self, app) -> None:
        self.app = app

    def refresh_overview(self) -> None:
        app = self.app
        app.refresh_history()
        app.refresh_artifacts()
        app.refresh_network()
        try:
            items = app._get("/processes").json()
            app.metric_proc.setText(f"Processes: {len(items)}")
        except Exception:
            app.metric_proc.setText("Processes: unavailable")
        try:
            app.refresh_entity_graph()
        except Exception:
            pass
        if hasattr(app, "dash_metrics"):
            app._refresh_dashboard_panels()
        if hasattr(app, "dashboard_controller"):
            app.dashboard_controller.refresh_overview_widgets()

    def run_monitor(self) -> None:
        app = self.app
        payload = {"duration": app.duration.value(), "interval": app.interval.value()}
        try:
            response = app._post("/monitor/run", json=payload, timeout=payload["duration"] + 60)
            result = app._json_response(response)
        except Exception as exc:
            app._show_error(app.monitor_out, "Monitor failed", exc)
            return
        incident = result.get("incident", {})
        telemetry_rows = result.get("telemetry_rows", [])
        app.latest_monitor_rows = telemetry_rows
        app.latest_monitor_result = result
        self.update_cpu_chart(telemetry_rows)
        app.monitor_out.setHtml(app._render_monitor_brief(result, incident))
        if hasattr(app, "dashboard_controller"):
            app.dashboard_controller.refresh_overview_widgets(result)
        app.metric_tel.setText(f"Telemetry Rows: {result.get('telemetry_count','-')}")
        severity = incident.get("severity", "unknown")
        app.metric_inc.setStyleSheet(
            "background:#121b27;border:1px solid #2c4260;border-radius:10px;padding:6px 10px;"
            f"color:{app._severity_color(severity).name()};font-weight:700;font-size:11px;"
        )
        app.metric_inc.setText(f"Last Incident: {incident.get('incident_id','-')} ({severity})")
        app.refresh_history()
        app.refresh_artifacts()
        app._switch_to_tab("Overview")

    def update_cpu_chart(self, rows) -> None:
        app = self.app
        app.cpu_series.clear()
        if rows:
            recent = self.sanitize_telemetry_rows(rows[-60:])
            for idx, item in enumerate(recent):
                app.cpu_series.append(idx, float(item.get("cpu", 0) or 0))
            app.cpu_axis_x.setRange(0, max(1, len(recent) - 1))
            max_cpu = max(float(item.get("cpu", 0) or 0) for item in recent)
            app.cpu_axis_y.setRange(0, max(25, min(100, max_cpu + 10)))
            avg_cpu = sum(float(item.get("cpu", 0) or 0) for item in recent) / max(1, len(recent))
            app.cpu_chart.setTitle(f"Telemetry CPU Trend - {len(recent)} samples | avg {avg_cpu:.1f}%")
        else:
            app.cpu_axis_x.setRange(0, 1)
            app.cpu_axis_y.setRange(0, 100)
            app.cpu_chart.setTitle("Telemetry CPU Trend - no telemetry collected yet")
        if hasattr(app, "dashboard_controller"):
            app.dashboard_controller.refresh_overview_widgets()

    def sanitize_telemetry_rows(self, rows) -> list[dict]:
        cleaned: list[dict] = []
        cpu_values: list[float] = []
        for item in rows:
            value = float(item.get("cpu", 0) or 0)
            cpu_values.append(max(0.0, min(100.0, value)))
        for index, item in enumerate(rows):
            value = cpu_values[index]
            if 0 < index < len(cpu_values) - 1:
                prev_value = cpu_values[index - 1]
                next_value = cpu_values[index + 1]
                if value <= 1.0 and prev_value >= 8.0 and next_value >= 8.0:
                    value = (prev_value + next_value) / 2.0
                elif abs(value - prev_value) >= 20 and abs(value - next_value) >= 20 and abs(prev_value - next_value) <= 8:
                    value = (prev_value + next_value) / 2.0
            normalized = dict(item)
            normalized["cpu"] = round(value, 2)
            cleaned.append(normalized)
        return cleaned
