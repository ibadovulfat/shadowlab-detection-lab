from __future__ import annotations

import html
import json
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QAction, QColor, QDesktopServices, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QListWidget,
    QMenu,
    QMessageBox,
    QInputDialog,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QTextEdit,
    QToolBar,
    QToolButton,
    QTreeWidget,
    QVBoxLayout,
    QWidget,
    QGridLayout,
)


class DesktopShellController:
    def __init__(self, app) -> None:
        self.app = app

    # SCENARIO_PROFILES / build_scenario_tab / run_scenario / _update_scenario_profile_summary
    # were removed in 2026-05; the Scenario Lab tab was dropped from
    # the desktop UI because production EDR products don't carry an
    # in-app adversary simulation harness; the equivalent telemetry
    # noise generator workflow is served by
    # `python scripts/perf_stability_probe.py` for CI smoke tests.

    def has_active_access(self) -> bool:
        role = str(self.app.auth_context.get("role", "locked") or "locked").lower()
        return bool(getattr(self.app, "auth_session_ready", False)) and role in {"viewer", "analyst", "admin"}

    def _request_allowed(self, path: str) -> bool:
        normalized = str(path or "").strip().lower()
        if normalized in {"/health", "/auth/context"}:
            return True
        return self.has_active_access()

    def _auth_block_message(self) -> str:
        return "Read-only until a valid key is applied. Enter a viewer, analyst, or admin API key and press OK."

    def apply_theme(self) -> None:
        self.app.setStyleSheet(
            "QMainWindow,QWidget{background:#10151d;color:#e5edf5;font-family:'Segoe UI',Arial,sans-serif;}"
            "QLineEdit,QSpinBox,QDoubleSpinBox,QComboBox{background:#16202c;color:#eef4fb;border:1px solid #243446;border-radius:8px;padding:2px 7px;}"
            "QLineEdit:focus,QSpinBox:focus,QDoubleSpinBox:focus,QComboBox:focus{border:1px solid #1d7df2;}"
            "QTextEdit,QTextBrowser,QTableWidget,QListWidget{background:#16202c;color:#eef4fb;border:1px solid #243446;border-radius:8px;padding:6px;}"
            "QPushButton{background:#1a2a3d;color:#c8d8ea;border:1px solid #2c4260;border-radius:8px;padding:6px 12px;font-weight:600;font-size:12px;} "
            "QPushButton:hover{background:#1d7df2;color:white;border-color:#1d7df2;} QPushButton:pressed{background:#155bc2;}"
            "QTabWidget::tab-bar{alignment:center;}"
            "QTabWidget::pane{border:1px solid #243446;border-radius:6px;} "
            "QTabBar::tab{background:#16202c;color:#96a5b8;padding:8px 10px;border:1px solid transparent;border-bottom:none;border-radius:6px 6px 0 0;margin-right:2px;font-size:12px;} "
            "QTabBar::tab:selected{background:#1d7df2;color:white;border-color:#1d7df2;} QTabBar::tab:hover{color:#eef4fb;background:#1d2a3a;}"
            "QHeaderView::section{background:#121b27;color:#96a5b8;border:none;border-right:1px solid #243446;border-bottom:1px solid #243446;padding:6px 8px;font-size:11px;font-weight:600;letter-spacing:0.5px;}"
            "QTableWidget{gridline-color:#1e2e40;alternate-background-color:#121b27;selection-background-color:#1a3558;}"
            "QFrame[card='true']{background:#121b27;border:1px solid #1e3050;border-radius:10px;}"
            "QTextEdit[role='brief'],QTextBrowser[role='brief']{background:#0e1720;border:1px solid #2b425b;border-radius:10px;padding:12px;color:#eef4fb;font-size:13px;}"
            "QScrollBar:vertical{background:#0e1720;width:8px;border-radius:4px;margin:0;} QScrollBar::handle:vertical{background:#2a3d55;border-radius:4px;min-height:24px;} QScrollBar::handle:vertical:hover{background:#3b5878;} QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0;}"
            "QScrollBar:horizontal{background:#0e1720;height:8px;border-radius:4px;margin:0;} QScrollBar::handle:horizontal{background:#2a3d55;border-radius:4px;min-width:24px;} QScrollBar::handle:horizontal:hover{background:#3b5878;} QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal{width:0;}"
            "QSplitter::handle{background:#1e3050;} QSplitter::handle:horizontal{width:2px;} QSplitter::handle:vertical{height:2px;}"
            "QCheckBox{spacing:6px;color:#96a5b8;} QCheckBox::indicator{width:14px;height:14px;border:1px solid #2c4260;border-radius:3px;background:#16202c;} QCheckBox::indicator:checked{background:#1d7df2;border-color:#1d7df2;}"
            "QListWidget::item:selected{background:#1a3558;color:#eef4fb;border-radius:4px;} QListWidget::item:hover{background:#1a2a3d;}"
            "QTreeWidget{background:#16202c;color:#eef4fb;border:1px solid #243446;border-radius:8px;} QTreeWidget::item:selected{background:#1a3558;}"
            "QStatusBar{background:#0a1018;border-top:1px solid #1e3050;color:#96a5b8;font-size:11px;}"
            "QToolTip{background:#121b27;color:#eef4fb;border:1px solid #2b425b;border-radius:6px;padding:4px 8px;}"
        )

    def build_toolbar(self) -> None:
        self.app.toolbar = QToolBar("Primary")
        self.app.toolbar.setMovable(False)
        self.app.toolbar.setFloatable(False)
        self.app.toolbar.setStyleSheet(
            "QToolBar{spacing:6px;padding:4px;border:none;background:#0f1823;}"
            "QToolButton{background:#16202c;color:#e5edf5;border:1px solid #243446;border-radius:7px;padding:6px 10px;font-size:12px;}"
            "QToolButton:hover{background:#1d7df2;border-color:#1d7df2;}"
        )
        self.app.addToolBar(self.app.toolbar)
        rebuild_toolbar = getattr(self.app, "_rebuild_toolbar", None)
        if callable(rebuild_toolbar):
            rebuild_toolbar()

    def rebuild_toolbar(self) -> None:
        """Rebuild the custom-shortcut toolbar at the top of the window.

        The seed `Add Button` / `Reset Buttons` actions used to be debug
        chrome that shipped to every user - they made the console look
        like a developer tool. Now we only show the toolbar when the
        operator has actually configured at least one custom shortcut,
        and we move the add/reset operations into the View menu instead
        of pinning them to the toolbar."""
        toolbar = getattr(self.app, "toolbar", None)
        if toolbar is None:
            return
        toolbar.clear()
        custom_buttons = getattr(self.app, "custom_toolbar_buttons", [])
        if not custom_buttons:
            toolbar.setVisible(False)
            return
        toolbar.setVisible(True)
        for entry in custom_buttons:
            label = str(entry.get("label", "") or "").strip()
            target = str(entry.get("target", "") or "").strip()
            if not label or not target:
                continue
            action = QAction(label, self.app)
            action.triggered.connect(lambda _checked=False, t=target: self.run_custom_toolbar_target(t))
            toolbar.addAction(action)

    def add_custom_toolbar_button(self) -> None:
        label, ok = QInputDialog.getText(self.app, "Add Toolbar Button", "Button label:")
        if not ok or not str(label).strip():
            return
        target, ok = QInputDialog.getText(
            self.app,
            "Add Toolbar Button",
            "Target tab name or URL (example: Processes or https://example.com):",
        )
        if not ok or not str(target).strip():
            return
        self.app.custom_toolbar_buttons.append({"label": str(label).strip(), "target": str(target).strip()})
        self.save_settings()
        self.rebuild_toolbar()

    def reset_custom_toolbar_buttons(self) -> None:
        self.app.custom_toolbar_buttons = []
        self.save_settings()
        self.rebuild_toolbar()

    def run_custom_toolbar_target(self, target: str) -> None:
        value = str(target or "").strip()
        if not value:
            return
        if value.lower().startswith(("http://", "https://")):
            QDesktopServices.openUrl(QUrl(value))
            return
        self.switch_to_tab(value)

    def get(self, path: str, **kwargs):
        if not self._request_allowed(path):
            raise RuntimeError(self._auth_block_message())
        return self.app.api_client.get(path, **kwargs)

    def post(self, path: str, **kwargs):
        if not self._request_allowed(path):
            raise RuntimeError(self._auth_block_message())
        return self.app.api_client.post(path, **kwargs)

    def show_error(self, target: QWidget | None, title: str, exc: Exception) -> None:
        message = self.app.api_client.format_api_exception(exc)
        if isinstance(target, (QTextBrowser, QTextEdit)):
            target.setPlainText(f"{title}\n\n{message}")
            return
        QMessageBox.critical(self.app, title, message)

    def show_json(self, target: QWidget, payload) -> None:
        # Central redaction layer - every tab eventually pipes mutating-
        # response payloads through this helper, so masking secrets here
        # neutralises the "Detail pane leaks fresh credentials" risk
        # without touching each call site individually. Redaction is a
        # no-op for payloads that don't contain matching keys, so the
        # cost is a recursive dict-walk per render - negligible
        # versus the JSON serialisation that already runs.
        try:
            from _panel_kit import redact_payload as _redact
        except ImportError:
            try:
                from desktop._panel_kit import redact_payload as _redact
            except Exception:
                _redact = lambda x: x  # noqa: E731 - failsafe identity
        rendered = json.dumps(_redact(payload), indent=2, ensure_ascii=False, default=str)
        if isinstance(target, (QTextBrowser, QTextEdit)):
            target.setPlainText(rendered)

    def style_table(self, table: QTableWidget) -> None:
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)

    def severity_color(self, severity: str) -> QColor:
        value = str(severity or "").lower()
        if value in {"critical", "high"}:
            return QColor("#5c1f2d")
        if value in {"medium", "warning"}:
            return QColor("#59461f")
        if value in {"low", "info"}:
            return QColor("#183247")
        return QColor("#16202c")

    def paint_row(self, table: QTableWidget, row: int, color: QColor) -> None:
        for col in range(table.columnCount()):
            item = table.item(row, col)
            if item is not None:
                item.setBackground(color)

    # Inline tooltips for every named panel - `?` button surfaces a
    # one-line description so operators don't have to grep docs to learn
    # what "Integrity Drift" or "Dead Letters" mean. Keyed on the panel
    # title so the same registry serves every tab.
    PANEL_HELP: dict[str, str] = {
        "Security Ops Posture":   "Headline integrity status, signature validity, dead-letter queue depth, observability event count, and YARA compile health.",
        "Integrity Drift":         "SHA-256 verified vs modified / missing / untracked files in the signed manifest. Modified or missing rows indicate tamper or restore drift.",
        "Platform Readiness":      "Database backend, migration count, abuse anomalies, and connector posture: the operational checklist before promoting to corp/prod.",
        "YARA Source Analytics":   "Per-source hit / suppression counters with avg score. Use to identify which rule pack is contributing the most signal.",
        "Local YARA Policy":       "Allow-list, boost, and suppression rule patterns. Saving rewrites the live detection policy. A diff preview is shown before commit.",
        "Security Ops Detail":     "Raw response payloads, errors, and exported report paths. Secrets are auto-redacted before display.",
        "Graph Summary":           "Headline counts and overall risk score for the live attack-surface entity graph.",
        "Priority Findings":       "High-risk operator findings extracted from the graph build (exposed services, suspicious parent chains, anomalous exposures).",
        "Hot Processes":           "Highest-scoring processes by composite risk (parent chain, signature, network exposure). Double-click a row to focus the graph on that PID.",
        "Entity Nodes":            "Every node in the latest graph build with its group, cluster, and individual risk score.",
        "Entity Edges":            "Every relationship between nodes (process to connection, host to domain, etc.) with its label and width.",
        "Graph Detail":            "Raw graph JSON, useful for downstream replay or scripted analysis. Secrets auto-redacted.",
        # ---- Timeline tab ----
        "Swimlane":         "Per-lane chronological view of telemetry, response, incident, alert and remediation events. Ctrl+Wheel to zoom, Shift+Drag to brush a time window, Right-click for bookmark / annotate. Dot size scales with cluster count.",
        "Event Detail":     "Raw payload of the selected event. Sensitive fields are auto-redacted before display. Pivot buttons above jump into the Graph or Processes tab focused on the event's PID / host.",
        "Event Log (sortable)": "Filtered event table mirroring the swimlane. Sort by any column; double-click a row to select the corresponding dot.",
        # ---- Persistence tab ----
        "Persistence Findings": "Live persistence enumeration: autoruns, scheduled tasks, services, WMI subscriptions, startup folders, drivers. Columns include MITRE technique, Signer trust, SHA-256, and Path Zone (protected / user-writable). Tone-coded for at-a-glance triage.",
        "Persistence Detail":   "Raw payload of the selected entry. Use Backup Selected before any destructive remediation - the JSON snapshot under shadowlab_out/persistence_backups/ is the only rollback path the UI exposes.",
        "Persistence Actions":  "Refresh, backup, pivot to Processes / Graph / Case, and remediate. Remediation requires a fresh refresh (sudo window), structured reason, and pre-delete JSON backup.",
    }

    def panel_card(self, title: str, content: QWidget, expand_fn=None, *, export_fn=None, help_text: str | None = None) -> QWidget:
        card = QFrame()
        card.setProperty("card", True)
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        card_layout = QVBoxLayout(card)
        compact_content = bool(content.property("panel_compact"))
        card_layout.setContentsMargins(10, 8, 10, 10 if compact_content else 12)
        card_layout.setSpacing(6 if compact_content else 8)
        header = QWidget()
        header.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        header_row = QHBoxLayout(header)
        header_row.setContentsMargins(0, 0, 0, 0)
        header_row.setSpacing(6)
        label = QLabel(title)
        label.setStyleSheet("font-size:13px;font-weight:700;color:#f4f7fb;letter-spacing:0.2px;")
        header_row.addWidget(label)
        # Inline help icon - every named panel gets one as long as the
        # PANEL_HELP registry has an entry (or the caller passed an
        # override). Cheap visual that immediately tells a new operator
        # what they're looking at.
        tooltip = help_text or self.PANEL_HELP.get(title, "")
        if tooltip:
            help_btn = QPushButton("?")
            help_btn.setToolTip(tooltip)
            help_btn.setFixedSize(20, 20)
            help_btn.setStyleSheet(
                "QPushButton { color:#9aa5b1; background:#1f2933; border:1px solid #364152;"
                " border-radius:10px; font-weight:600; font-size:11px; }"
                "QPushButton:hover { color:#f4f7fb; border-color:#9aa5b1; }"
            )
            help_btn.setCursor(Qt.PointingHandCursor)
            # Show the same tooltip in a modeless info box on click so
            # touchscreen / dense-UI operators can read it.
            def _show_help_dialog():
                from PySide6.QtWidgets import QMessageBox as _MB
                _MB.information(self.app, title, tooltip)
            help_btn.clicked.connect(_show_help_dialog)
            header_row.addWidget(help_btn)
        header_row.addStretch(1)
        # Per-panel export - accepts an `export_fn(filepath, kind)`
        # callable; when None we expose a default CSV/JSON dumper for
        # QTableWidget / QTextEdit content.
        if export_fn is not None or isinstance(content, (QTableWidget, QTextEdit, QTextBrowser)):
            export_btn = QPushButton("⤓")
            export_btn.setToolTip("Export this panel's content (CSV for tables, JSON/HTML for text)")
            export_btn.setFixedSize(28, 22)
            export_btn.setStyleSheet(
                "QPushButton { color:#cbd5e0; background:#1f2933; border:1px solid #364152;"
                " border-radius:6px; font-weight:600; }"
                "QPushButton:hover { color:#f4f7fb; border-color:#9aa5b1; }"
            )
            export_btn.clicked.connect(
                lambda _=False, t=title, c=content, ex=export_fn: self._export_panel_content(t, c, ex)
            )
            header_row.addWidget(export_btn)
        if expand_fn is not None:
            expand_btn = QPushButton("Open Panel")
            expand_btn.setMaximumWidth(104)
            expand_btn.clicked.connect(expand_fn)
            header_row.addWidget(expand_btn)
        expanding_content = isinstance(content, (QTextEdit, QTextBrowser, QTableWidget, QListWidget, QTreeWidget)) or bool(
            content.property("panel_expand")
        )
        if compact_content:
            content.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        elif expanding_content:
            content.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        else:
            content.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        card_layout.addWidget(header)
        if compact_content:
            card_layout.addWidget(content, 0, Qt.AlignTop)
        elif expanding_content:
            card_layout.addWidget(content, 1)
        else:
            card_layout.addWidget(content, 0, Qt.AlignTop)
        return card

    def _export_panel_content(self, title: str, content: QWidget, custom_export=None) -> None:
        """Save the panel's current content to disk.

        Tables → CSV. Text browsers → JSON if the body is JSON-parseable,
        otherwise raw text (.txt). Custom callables override the default.
        """
        from PySide6.QtWidgets import QFileDialog
        slug = "".join(ch for ch in title.lower() if ch.isalnum() or ch == "_").replace(" ", "_") or "panel"
        if custom_export is not None:
            try:
                custom_export()
            except Exception as exc:
                self.show_error(None, "Export failed", exc)
            return
        if isinstance(content, QTableWidget):
            path, _ = QFileDialog.getSaveFileName(
                self.app, f"Export {title}", f"shadowlab_out/{slug}.csv", "CSV (*.csv)"
            )
            if not path:
                return
            try:
                import csv
                with open(path, "w", encoding="utf-8", newline="") as handle:
                    writer = csv.writer(handle)
                    headers = [content.horizontalHeaderItem(c).text() if content.horizontalHeaderItem(c) else f"col{c}"
                               for c in range(content.columnCount())]
                    writer.writerow(headers)
                    for r in range(content.rowCount()):
                        row = []
                        for c in range(content.columnCount()):
                            item = content.item(r, c)
                            row.append(item.text() if item else "")
                        writer.writerow(row)
                self.app.statusBar().showMessage(f"Exported {content.rowCount()} rows to {path}", 5000)
            except Exception as exc:
                self.show_error(None, "Export failed", exc)
            return
        if isinstance(content, (QTextEdit, QTextBrowser)):
            text = content.toPlainText() if hasattr(content, "toPlainText") else content.toHtml()
            # Try JSON first so structured payloads land as proper .json.
            try:
                parsed = json.loads(text)
                default_ext = ".json"
                rendered = json.dumps(parsed, indent=2, ensure_ascii=False)
                filter_str = "JSON (*.json);;Text (*.txt)"
            except Exception:
                default_ext = ".txt"
                rendered = text
                filter_str = "Text (*.txt);;HTML (*.html)"
            path, _ = QFileDialog.getSaveFileName(
                self.app, f"Export {title}", f"shadowlab_out/{slug}{default_ext}", filter_str
            )
            if not path:
                return
            try:
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(rendered)
                self.app.statusBar().showMessage(f"Exported to {path}", 5000)
            except Exception as exc:
                self.show_error(None, "Export failed", exc)

    def open_panel_window(self, title: str, body: QWidget) -> None:
        dlg = QDialog(self.app)
        dlg.setWindowTitle(title)
        dlg.resize(1180, 760)
        dlg.setModal(False)
        dlg.setWindowModality(Qt.NonModal)
        dlg.setAttribute(Qt.WA_DeleteOnClose, True)
        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.addWidget(body)

        def _cleanup_panel_window(*_args) -> None:
            self.app.panel_windows = [window for window in self.app.panel_windows if window is not dlg]

        dlg.destroyed.connect(_cleanup_panel_window)
        dlg.show()
        dlg.raise_()
        dlg.activateWindow()
        self.app.panel_windows.append(dlg)

    def clone_table(self, source: QTableWidget) -> QTableWidget:
        clone = QTableWidget(source.rowCount(), source.columnCount())
        headers = []
        for col in range(source.columnCount()):
            item = source.horizontalHeaderItem(col)
            headers.append(item.text() if item else f"Column {col + 1}")
        clone.setHorizontalHeaderLabels(headers)
        for row in range(source.rowCount()):
            for col in range(source.columnCount()):
                cell = source.item(row, col)
                clone.setItem(row, col, QTableWidgetItem(cell.text() if cell else ""))
        self.app._style_table(clone)
        return clone

    def clone_text_view(self, source: QWidget) -> QTextBrowser:
        clone = QTextBrowser()
        clone.setOpenExternalLinks(True)
        if isinstance(source, QTextBrowser):
            clone.setHtml(source.toHtml())
        elif isinstance(source, QTextEdit):
            clone.setPlainText(source.toPlainText())
        elif isinstance(source, QLabel):
            clone.setText(source.text())
        return clone

    def enterprise_action_button(self, label: str, callback, capability: str | None = None) -> QPushButton:
        button = QPushButton(label)
        button.setMinimumHeight(32)
        button.clicked.connect(callback)
        if capability:
            self.app._bind_capability(button, capability)
        return button

    def enterprise_menu_button(self, label: str, actions: list[tuple[str, object, str | None]]) -> QToolButton:
        button = QToolButton()
        button.setText(label)
        button.setPopupMode(QToolButton.InstantPopup)
        button.setToolButtonStyle(Qt.ToolButtonTextOnly)
        button.setMinimumHeight(32)
        menu = QMenu(button)
        capability_bound = False
        for action_label, callback, capability in actions:
            action = QAction(action_label, button)
            action.triggered.connect(callback)
            menu.addAction(action)
            if capability and not capability_bound:
                self.app._bind_capability(button, capability)
                capability_bound = True
        button.setMenu(menu)
        return button

    def style_enterprise_compact_control(self, widget: QWidget) -> QWidget:
        widget.setMinimumHeight(28)
        existing = widget.styleSheet().strip()
        compact = "font-size:11px;padding:4px 8px;"
        widget.setStyleSheet(f"{existing};{compact}" if existing else compact)
        return widget

    def open_process_table_panel(self) -> None:
        self.open_panel_window("Processes: Table", self.clone_table(self.app.proc_table))

    def open_process_detail_panel(self) -> None:
        detail = QTextEdit()
        detail.setReadOnly(True)
        detail.setPlainText(self.app.proc_detail.toPlainText())
        self.open_panel_window("Processes: Detail", detail)

    def refresh_timeline(self) -> None:
        self.app.timeline_controller.refresh_timeline()

    def show_selected_timeline(self) -> None:
        self.app.timeline_controller.show_selected_timeline()

    def refresh_antivirus_workspace(self) -> None:
        self.app.antivirus_controller.refresh_workspace()

    def refresh_antivirus_status(self) -> None:
        self.app.antivirus_controller.refresh_status()

    def scan_antivirus_validation_sample(self) -> None:
        self.app.antivirus_controller.scan_validation_sample()

    def scan_antivirus_target(self) -> None:
        self.app.antivirus_controller.scan_target_file()

    def scan_antivirus_selected_process(self) -> None:
        self.app.antivirus_controller.scan_selected_process()

    def show_selected_antivirus_result(self) -> None:
        self.app.antivirus_controller.show_selected_result()

    def quarantine_selected_antivirus_result(self) -> None:
        self.app.antivirus_controller.quarantine_selected_result()

    def show_selected_antivirus_quarantine(self) -> None:
        self.app.antivirus_controller.show_selected_quarantine()

    def open_selected_antivirus_quarantine(self) -> None:
        self.app.antivirus_controller.open_selected_quarantine()



    def field_block(self, label: str, widget: QWidget) -> QWidget:
        block = QWidget()
        layout = QVBoxLayout(block)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        title = QLabel(label)
        title.setStyleSheet("color:#96a5b8;font-size:10px;font-weight:600;")
        layout.addWidget(title)
        layout.addWidget(widget)
        return block

    def tab_header(self, layout: QVBoxLayout, title: str, subtitle: str = "") -> None:
        title_label = QLabel(title)
        title_label.setStyleSheet("font-size:16px;font-weight:700;color:#f4f7fb;")
        layout.addWidget(title_label)
        if subtitle:
            subtitle_label = QLabel(subtitle)
            subtitle_label.setWordWrap(True)
            subtitle_label.setStyleSheet("color:#96a5b8;font-size:12px;")
            layout.addWidget(subtitle_label)

    def metric_card(self, title: str, accent: str) -> tuple[QWidget, QLabel]:
        card = QFrame()
        card.setProperty("card", True)
        card.setMinimumHeight(88)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)
        label = QLabel(title)
        label.setStyleSheet("color:#96a5b8;font-size:11px;font-weight:600;")
        value = QLabel("--")
        value.setStyleSheet(f"color:{accent};font-size:22px;font-weight:700;")
        layout.addWidget(label)
        layout.addWidget(value)
        layout.addStretch(1)
        return card, value

    def set_metric_label(self, label: QLabel, value: str) -> None:
        label.setText(str(value))

    def switch_to_tab(self, label: str) -> None:
        for index in range(self.app.tabs.count()):
            if self.app.tabs.tabText(index).strip().lower() == label.strip().lower():
                self.app.tabs.setCurrentIndex(index)
                return

    def json_response(self, response):
        return response.json()

    def put(self, path: str, **kwargs):
        if not self._request_allowed(path):
            raise RuntimeError(self._auth_block_message())
        return self.app.api_client.put(path, **kwargs)

    def patch(self, path: str, **kwargs):
        if not self._request_allowed(path):
            raise RuntimeError(self._auth_block_message())
        return self.app.api_client.patch(path, **kwargs)

    def delete(self, path: str, **kwargs):
        if not self._request_allowed(path):
            raise RuntimeError(self._auth_block_message())
        return self.app.api_client.delete(path, **kwargs)

    def safe_int(self, value, default: int = 0) -> int:
        try:
            return int(value)
        except Exception:
            return default

    def render_monitor_brief(self, result: dict, incident: dict | None = None) -> str:
        summary = result.get("summary", {}) if isinstance(result, dict) else {}
        incident = incident or {}
        final_score = result.get("final_score", {}) if isinstance(result.get("final_score", {}), dict) else {}
        event_summaries = result.get("event_summaries", {}) if isinstance(result.get("event_summaries", {}), dict) else {}
        telemetry_rows = result.get("telemetry_rows", []) if isinstance(result.get("telemetry_rows", []), list) else []
        timeline_scores = result.get("timeline_scores", []) if isinstance(result.get("timeline_scores", []), list) else []
        raw_artifacts = result.get("artifacts", [])
        artifacts = raw_artifacts if isinstance(raw_artifacts, (list, dict)) else []
        collector_export = result.get("collector_export", {}) if isinstance(result.get("collector_export", {}), dict) else {}

        severity = str(incident.get("severity", summary.get("severity", "unknown")) or "unknown")
        incident_id = str(incident.get("incident_id", "-") or "-")
        title = str(incident.get("title", "Host telemetry monitor session") or "Host telemetry monitor session")
        narrative = str(
            incident.get("summary")
            or incident.get("correlation_story")
            or "Telemetry is ready for investigation. Review signal coverage, findings, and recommended response before taking action."
        )
        process_count = summary.get("process_count", "-")
        connection_count = summary.get("connection_count", "-")
        telemetry_count = result.get("telemetry_count", len(telemetry_rows))
        try:
            likelihood = final_score.get("likelihood", max([float(x or 0) for x in timeline_scores], default=0.0))
            likelihood_text = f"{float(likelihood):.0%}" if float(likelihood) <= 1 else f"{float(likelihood):.0f}%"
        except Exception:
            likelihood_text = "--"

        defender = event_summaries.get("defender", {}) if isinstance(event_summaries.get("defender", {}), dict) else {}
        sysmon = event_summaries.get("sysmon", {}) if isinstance(event_summaries.get("sysmon", {}), dict) else {}
        findings = incident.get("findings", []) if isinstance(incident.get("findings", []), list) else []
        recommended_actions = incident.get("recommended_actions", []) if isinstance(incident.get("recommended_actions", []), list) else []
        attack_chain = incident.get("attack_chain", []) if isinstance(incident.get("attack_chain", []), list) else []
        mitre = incident.get("mitre_techniques", []) if isinstance(incident.get("mitre_techniques", []), list) else []
        notes = incident.get("notes", []) if isinstance(incident.get("notes", []), list) else []

        def _li(value) -> str:
            if isinstance(value, dict):
                label = value.get("title") or value.get("name") or value.get("type") or value.get("technique_id") or "item"
                detail = value.get("detail") or value.get("description") or value.get("summary") or value.get("reason") or ""
                if detail:
                    return f"<li><b>{html.escape(str(label))}</b>: {html.escape(str(detail))}</li>"
                return f"<li>{html.escape(str(label))}</li>"
            return f"<li>{html.escape(str(value))}</li>"

        finding_rows = "".join(_li(item) for item in findings[:6]) or "<li>No correlated findings recorded.</li>"
        action_rows = "".join(_li(item) for item in recommended_actions[:6]) or "<li>Keep monitoring and enrich the incident before containment.</li>"
        chain_rows = "".join(_li(item) for item in attack_chain[:6]) or "<li>No attack-chain stage mapped yet.</li>"
        mitre_rows = "".join(_li(item) for item in mitre[:6]) or "<li>No ATT&amp;CK technique mapped yet.</li>"
        note_rows = "".join(_li(item) for item in notes[:4]) or "<li>No analyst notes recorded.</li>"
        artifact_count = len(artifacts)
        collector_state = "enabled" if collector_export.get("enabled") else "not enabled"

        severity_color = {
            "critical": "#ff6b8a",
            "high": "#ff8f70",
            "medium": "#f4c26b",
            "warning": "#f4c26b",
            "low": "#7fe39d",
            "info": "#7fd7ff",
        }.get(severity.lower(), "#c8d8ea")

        return (
            "<div style='font-family:Segoe UI,Arial,sans-serif;color:#eef4fb;'>"
            f"<h2 style='margin:0 0 4px;color:#f4f7fb;'>{html.escape(title)}</h2>"
            f"<div style='color:#96a5b8;margin-bottom:12px;'>Incident <b>{html.escape(incident_id)}</b> | "
            f"Severity <b style='color:{severity_color};'>{html.escape(severity.upper())}</b> | "
            f"Likelihood <b>{html.escape(likelihood_text)}</b></div>"
            f"<p style='margin:0 0 12px;line-height:1.35;'>{html.escape(narrative)}</p>"
            "<table width='100%' cellspacing='0' cellpadding='8' style='border-collapse:separate;border-spacing:6px;'>"
            "<tr>"
            f"<td style='border:1px solid #243446;border-radius:8px;'><b>Processes</b><br><span style='font-size:20px;color:#7fd7ff;'>{html.escape(str(process_count))}</span></td>"
            f"<td style='border:1px solid #243446;border-radius:8px;'><b>Connections</b><br><span style='font-size:20px;color:#7fd7ff;'>{html.escape(str(connection_count))}</span></td>"
            f"<td style='border:1px solid #243446;border-radius:8px;'><b>Telemetry</b><br><span style='font-size:20px;color:#7fe39d;'>{html.escape(str(telemetry_count))}</span></td>"
            f"<td style='border:1px solid #243446;border-radius:8px;'><b>Artifacts</b><br><span style='font-size:20px;color:#f4c26b;'>{artifact_count}</span></td>"
            "</tr></table>"
            "<table width='100%' cellspacing='0' cellpadding='10' style='border-collapse:separate;border-spacing:6px;'>"
            "<tr>"
            f"<td valign='top' width='50%' style='border:1px solid #243446;border-radius:8px;'><h3 style='margin:0 0 6px;color:#f4f7fb;'>Correlated Findings</h3><ul>{finding_rows}</ul></td>"
            f"<td valign='top' width='50%' style='border:1px solid #243446;border-radius:8px;'><h3 style='margin:0 0 6px;color:#f4f7fb;'>Recommended Response</h3><ul>{action_rows}</ul></td>"
            "</tr><tr>"
            f"<td valign='top' style='border:1px solid #243446;border-radius:8px;'><h3 style='margin:0 0 6px;color:#f4f7fb;'>ATT&amp;CK / Kill Chain</h3><b>Chain</b><ul>{chain_rows}</ul><b>Techniques</b><ul>{mitre_rows}</ul></td>"
            f"<td valign='top' style='border:1px solid #243446;border-radius:8px;'><h3 style='margin:0 0 6px;color:#f4f7fb;'>Evidence &amp; Signal Health</h3>"
            f"<p>Defender events: <b>{html.escape(str(defender.get('total', 0)))}</b><br>"
            f"Sysmon events: <b>{html.escape(str(sysmon.get('total', 0)))}</b><br>"
            f"Collector export: <b>{html.escape(collector_state)}</b></p><b>Notes</b><ul>{note_rows}</ul></td>"
            "</tr></table></div>"
        )

    def format_yara_summary(self, result: dict) -> str:
        hits = result.get("hits", []) if isinstance(result, dict) else []
        summary = result.get("summary", {}) if isinstance(result, dict) else {}
        return json.dumps({"summary": summary, "hit_count": len(hits), "hits": hits}, indent=2, ensure_ascii=False)

    def format_triage_summary(self, result: dict) -> str:
        return json.dumps(result, indent=2, ensure_ascii=False)

    def format_response_execution(self, result: dict) -> str:
        return json.dumps(result, indent=2, ensure_ascii=False)

    def malware_analyst_runtime_status(self, result: dict) -> tuple[str, str]:
        runtime = result.get("runtime", {}) if isinstance(result, dict) else {}
        badge = str(runtime.get("status", "unknown"))
        location = str(runtime.get("path", ""))
        return badge, location

    def integration_rows(self, payload) -> list[dict]:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            for key in ("items", "rows", "results", "artifacts", "alerts"):
                value = payload.get(key)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)]
        return []

    def incident_rows_for_prefix(self, prefix: str) -> list[dict]:
        rows = getattr(self.app, "incident_rows", [])
        return [row for row in rows if str(row.get("id", "")).startswith(prefix)]

    def persist_enterprise_ui_state(self) -> None:
        settings = self.app.settings
        for key, value in {
            "enterprise_case_filter": getattr(self.app, "enterprise_case_filter", None),
            "enterprise_task_filter": getattr(self.app, "enterprise_task_filter", None),
            "enterprise_activity_filter": getattr(self.app, "enterprise_activity_filter", None),
        }.items():
            if value is not None:
                settings.setValue(key, value.text().strip())

    def scrollable_tab(self, child: QWidget, allow_horizontal: bool = False) -> QWidget:
        if child.property("no_vertical_scroll"):
            child.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            return child
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QFrame.NoFrame)
        area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded if allow_horizontal else Qt.ScrollBarAlwaysOff)
        area.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff if child.property("no_vertical_scroll") else Qt.ScrollBarAsNeeded)
        area.setWidget(child)
        return area

    def build_timeline_tab(self) -> QWidget:
        return self.app.timeline_controller.build_timeline_tab()

    def build_antivirus_tab(self) -> QWidget:
        return self.app.antivirus_controller.build_tab()


    def build_about_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)
        split = QHBoxLayout()
        split.setContentsMargins(0, 0, 0, 0)
        split.setSpacing(8)

        about_body = QWidget()
        about_body.setProperty("panel_expand", True)
        about_body_layout = QVBoxLayout(about_body)
        about_body_layout.setContentsMargins(2, 0, 2, 0)
        about_body_layout.setSpacing(8)

        about_text = QTextBrowser()
        about_text.setOpenExternalLinks(True)
        about_text.setProperty("role", "brief")
        about_text.setFrameShape(QFrame.NoFrame)
        about_text.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        about_text.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        about_text.setStyleSheet(
            "QTextBrowser{border:none;background:transparent;padding:0;color:#eef4fb;font-size:11px;line-height:1.25;}"
        )
        about_text.setHtml(
            "<p><b>ShadowLab</b> is a Windows first defensive operations workspace. It pairs a "
            "local FastAPI backend with a PySide6 desktop client and gives an operator a single "
            "place to run triage, investigation, evidence handling, enterprise casework, and "
            "security operations controls without bouncing between half a dozen vendor tools.</p>"

            "<p>This release is a meaningful step beyond the original detection lab. The platform "
            "now ties host telemetry, process intelligence, persistence review, threat intel "
            "enrichment, quarantine and artifact custody, attack surface graph, an investigation "
            "timeline workbench, ATT&amp;CK coverage, enterprise case workflow, approval aware "
            "destructive actions, workspace scoped tenancy, and a security ops readiness surface "
            "into one coherent product.</p>"

            "<p><b>Core Capabilities</b><br>"
            "Dashboards and overview surfaces tuned for daily triage rather than a generic "
            "metrics dump.<br>"
            "Processes console with provenance, signature trust, network exposure, and a Risk "
            "Policy view so analysts can prioritise hot PIDs at a glance.<br>"
            "Persistence and Autoruns workspace covering registry, scheduled tasks, services, "
            "WMI subscriptions, startup folders, and drivers, with MITRE technique mapping, "
            "signer trust, path zone classification, a documented risk score, and pre delete "
            "backups for every destructive action.<br>"
            "Static file analysis console for intake, structural evidence, YARA and DIE signals, "
            "imports, strings, and analyst decisioning.<br>"
            "Antivirus workspace with multi provider scanning, quarantine custody, MITRE heat "
            "map, and live verdict polling.<br>"
            "Entity Graph with five lane KPI strip, swimlane zoom and brush selection, group "
            "and cluster filters, MITRE overlay, snapshot save and diff, AD context strip, "
            "interactive embedded graph view, and pivot to Processes and Timeline.<br>"
            "Investigation Timeline workbench rendering telemetry, response, incident, alert, "
            "and remediation events on a five lane chronological chart with right click bookmark "
            "and annotation, replay scrubber, anomaly highlight, colour blind safe palette, and "
            "a Server Sent Events live feed for active SOC shifts.<br>"
            "Artifacts and Evidence Store with SHA 256, signature verification, manifest hash "
            "chain comparison, forensic export, and chain of custody handoff into Enterprise "
            "case work.<br>"
            "History tab consolidating incidents, response actions, telemetry, alerts, remediations, "
            "auth log, and an integrity hash chain verify endpoint.<br>"
            "WHIDS and HIDS integration with grouped action surfaces (Ingest, Scheduler, IoC, "
            "Rules, Policy), inline TLS warning, test connection probe, and JSON validation "
            "before any policy is rewritten.<br>"
            "Enterprise casework with assignments, tasks, notes, stories, notifications, exports, "
            "and a Workbench HTML export for investigation reporting.<br>"
            "Security Ops console for integrity manifest, observability counters, scheduled "
            "secret rotation, retention housekeeping, YARA policy with side by side diff before "
            "save, compliance posture strip, and a sudo grace window for destructive actions.</p>"

            "<p><b>Runtime Shape</b><br>"
            "<b>Backend and API:</b> Python, FastAPI, Uvicorn, SQLite or PostgreSQL, optional "
            "Redis for distributed rate limit.<br>"
            "<b>Desktop Client:</b> PySide6, QtWebEngine for the embedded interactive graph, "
            "pywin32, psutil, watchdog.<br>"
            "<b>Analysis Layer:</b> YARA Python, Scapy, pandas, NumPy, scikit learn, die python, "
            "Sigma rule compatible event shape.<br>"
            "<b>Visualization and Reporting:</b> Plotly, Matplotlib, PyVis, ReportLab, and a "
            "custom QGraphicsView swimlane for the Timeline tab.<br>"
            "<b>Security Controls:</b> HKDF derived request signing keys, RFC 6238 TOTP MFA "
            "with per token replay protection, Origin allow list for browser callers, a tamper "
            "evident SHA 256 audit chain over every mutating request, pluggable rate limit "
            "(memory, database, or Redis), scheduled secret rotation worker, optional mutual "
            "TLS between desktop and API, central redaction layer that scrubs secrets out of "
            "every Detail pane, signed mutations with structured reasons, approvals on "
            "destructive paths, role aware access, workspace scoped tenancy, tenant aware "
            "exports.</p>"

            "<p><b>Continuous Assurance</b><br>"
            "402 unit and integration tests, Bandit, Semgrep, pip audit, and Schemathesis fuzz "
            "harness gate every change. A CycloneDX SBOM is built per release and attested "
            "with sigstore.</p>"

            "<p><b>FAQ</b><br>"
            "<b>What is ShadowLab?</b> A local operator platform for Windows investigation, "
            "detection engineering, incident response, and enterprise case operations. It runs "
            "entirely on the operator workstation by default and never reaches outside the lab "
            "unless an integration is explicitly configured.<br>"
            "<b>Who is it for?</b> Detection engineers, threat hunters, SOC analysts, incident "
            "responders, malware analysts, and defensive researchers who want vendor agnostic "
            "tooling that surfaces telemetry, scoring, and chain of custody in one workspace.<br>"
            "<b>What changed in this release?</b> The Timeline tab is now a proper investigation "
            "workbench rather than a flat event table. Persistence enumerates and risk scores "
            "every common autorun vector. Artifacts surface signature trust and SHA 256 inline. "
            "Security Ops carries a compliance posture strip and a sudo grace window. WHIDS "
            "destructive actions are gated behind confirmation, structured reasons, and a TLS "
            "footgun warning. Cross cutting hardening landed on the backend: HKDF signing, MFA, "
            "audit hash chain, Origin allow list, redis ready rate limit, scheduled rotation, "
            "and a mTLS option for desktop traffic.<br>"
            "<b>Can it be packaged?</b> Yes. The PySide6 desktop remains the primary operator "
            "client and the packaging base for an EXE delivery. The FastAPI backend ships as "
            "a sidecar or as a managed service depending on the deployment profile (lab, corp, "
            "or prod).</p>"
        )
        about_body_layout.addWidget(about_text)

        profile_body = QWidget()
        profile_body.setProperty("panel_expand", True)
        profile_body_layout = QVBoxLayout(profile_body)
        profile_body_layout.setContentsMargins(0, 0, 0, 0)
        profile_body_layout.setSpacing(8)

        profile_name = QLabel("Ulfat Ibadov")
        profile_name.setStyleSheet("font-size:20px;font-weight:800;color:#f4f7fb;")
        profile_role = QLabel("Offensive Security Expert")
        profile_role.setStyleSheet("color:#9aa5b8;font-size:14px;font-weight:600;")
        profile_body_layout.addWidget(profile_name)
        profile_body_layout.addWidget(profile_role)

        profile_image = QLabel()
        profile_image.setAlignment(Qt.AlignCenter)
        profile_image.setMinimumHeight(260)
        image_path = Path(self.app.logo_path).resolve().parent / "ulfat-profile.png"
        if image_path.exists():
            profile_image.setPixmap(QPixmap(str(image_path)).scaled(260, 260, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            profile_image.setText("Profile image unavailable")
            profile_image.setStyleSheet("color:#96a5b8;")
        profile_body_layout.addWidget(profile_image, 0, Qt.AlignCenter)

        profile_copy = QTextBrowser()
        profile_copy.setOpenExternalLinks(True)
        profile_copy.setFrameShape(QFrame.NoFrame)
        profile_copy.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        profile_copy.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        profile_copy.setStyleSheet(
            "QTextBrowser{color:#eef4fb;font-size:14px;line-height:1.55;"
            "border:1px solid #2b425b;border-radius:10px;padding:14px;background:#0e1720;}"
        )
        profile_copy.setHtml(
            "<p><b>Profile:</b> Offensive security practitioner and detection engineer with hands-on experience in penetration testing, red team operations, and behavioral threat detection.<br>"
            "<b>Certifications:</b> EC-Council certified (CEH Master, WAHS Professional), currently pursuing CPENT and Hack The Box CPTS.<br>"
            "<b>Ranking:</b> Global Top 1% on both Hack The Box and TryHackMe.<br>"
            "<b>Focus:</b> Builds systems that detect what is discovered on the offensive side, most notably ShadowLab, a security operations platform correlating host telemetry with ML-assisted behavioral scoring for detection engineering and incident response.</p>"
        )
        profile_body_layout.addWidget(profile_copy, 1)

        buttons = QWidget()
        buttons_row = QHBoxLayout(buttons)
        buttons_row.setContentsMargins(0, 0, 0, 0)
        buttons_row.setSpacing(8)
        project_btn = QPushButton("Project")
        project_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://shadowlab.about.surf/")))
        github_btn = QPushButton("GitHub")
        github_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://github.com/ibadovulfat/")))
        buttons_row.addWidget(project_btn)
        buttons_row.addWidget(github_btn)
        buttons_row.addStretch(1)
        about_body_layout.addWidget(buttons)

        profile_buttons = QWidget()
        profile_buttons_row = QHBoxLayout(profile_buttons)
        profile_buttons_row.setContentsMargins(0, 0, 0, 0)
        profile_buttons_row.setSpacing(8)
        portfolio_btn = QPushButton("Portfolio")
        portfolio_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://about.surf/")))
        linkedin_btn = QPushButton("LinkedIn")
        linkedin_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://www.linkedin.com/in/ibadovulfat/")))
        profile_buttons_row.addWidget(portfolio_btn)
        profile_buttons_row.addWidget(linkedin_btn)
        profile_buttons_row.addStretch(1)
        profile_body_layout.addWidget(profile_buttons)

        split.addWidget(self.panel_card("About ShadowLab", about_body), 3)
        split.addWidget(self.panel_card("Creator Profile", profile_body), 2)
        layout.addLayout(split, 1)
        return w

    def bind_capability(self, widget: QWidget, capability: str) -> None:
        self.app.capability_widgets.append((widget, capability))
        capabilities = self.app.auth_context.get("capabilities", {}) if isinstance(self.app.auth_context, dict) else {}
        widget.setEnabled(bool(capabilities.get(capability, False)) or not self.app.auth_active)

    def apply_auth_context(self, context: dict) -> None:
        self.app.auth_context = context or {}
        self.app.auth_active = bool(self.app.auth_context.get("auth_required", False))
        role = str(self.app.auth_context.get("role", "locked") or "locked")
        self.app.auth_session_ready = role.lower() in {"viewer", "analyst", "admin"}
        self.app.auth_role.setText(f"Role: {role}")
        self.app.auth_mode_badge.setText(f"Mode: {role}")
        self.app.auth_mode_hint.setVisible(not self.app.auth_session_ready)
        if self.app.auth_session_ready:
            self.app.auth_mode_hint.setText("")
        else:
            self.app.auth_mode_hint.setText(self._auth_block_message())
        capabilities = self.app.auth_context.get("capabilities", {}) if isinstance(self.app.auth_context.get("capabilities"), dict) else {}
        for widget, capability in self.app.capability_widgets:
            widget.setEnabled(bool(capabilities.get(capability, False)))
        # Per-tab controllers cache role-derived button enabled-state
        # locally (so that drawer-only widgets don't have to subscribe to
        # an event bus). When the global role flips (e.g. analyst pastes
        # an admin key), poke each controller's apply_role_access so its
        # Scan / Quarantine / Vault buttons un-grey immediately instead
        # of waiting for the next manual Refresh.
        controller = getattr(self.app, "antivirus_controller", None)
        if controller is not None and hasattr(controller, "apply_role_access"):
            try:
                controller.apply_role_access()
            except Exception:
                pass
        # P3-21 - re-evaluate Dashboards panel visibility when the role
        # flips (e.g. analyst pastes an admin key, viewer downgrades).
        # Also fire an initial Dashboards refresh so the operator sees
        # data immediately after applying the key (no manual Refresh
        # button is exposed - it lives in autorefresh / external paths).
        dashboard_ctrl = getattr(self.app, "dashboard_controller", None)
        if dashboard_ctrl is not None and hasattr(dashboard_ctrl, "_apply_current_view"):
            try:
                dashboard_ctrl._apply_current_view()
            except Exception:
                pass
            if self.app.auth_session_ready and hasattr(dashboard_ctrl, "refresh_dashboard_panels"):
                try:
                    dashboard_ctrl.refresh_dashboard_panels()
                except Exception:
                    pass
        # Once auth is alive, push any locally-stored cloud credentials to
        # the backend so cloud_intel / cloud_sandbox providers go ready
        # without requiring a manual focus-out on each input.
        sync = getattr(self.app, "_sync_av_credentials_to_backend", None)
        if callable(sync):
            try:
                sync()
            except Exception:
                pass

    def activate_role_mode(self) -> None:
        if not self.app.api_key.text().strip():
            self.app.auth_session_ready = False
            self.apply_auth_context({"role": "locked", "auth_required": True, "capabilities": {}})
            return
        try:
            context = self.get("/auth/context").json()
        except Exception as exc:
            self.app.auth_session_ready = False
            self.apply_auth_context({"role": "locked", "auth_required": True, "capabilities": {}})
            self.show_error(None, "Auth failed", exc)
            return
        self.apply_auth_context(context)
        self.save_settings()
        self.check_api_health()
        # If "Remember API key" is ticked, refresh the stored credential
        # so the latest accepted key is kept on disk.
        persist = getattr(self.app, "_persist_api_key_after_activate", None)
        if callable(persist):
            try:
                persist()
            except Exception:
                pass

    def check_api_health(self) -> None:
        try:
            payload = self.get("/health", timeout=10).json()
            status = str(payload.get("status", "ok") or "ok").lower()
            self.app.health.setText(f"API status: {status}")
            self.app.health.setStyleSheet(
                "background:#1b3b2b;color:#7fe39d;border:1px solid #2e6b4a;"
                "border-radius:10px;padding:6px 14px;font-weight:700;font-size:12px;"
            )
        except Exception:
            self.app.health.setText("API status: offline")
            self.app.health.setStyleSheet(
                "background:#3f2430;color:#ff9ab0;border:1px solid #6b3a4d;"
                "border-radius:10px;padding:6px 14px;font-weight:700;font-size:12px;"
            )

    def toggle_advanced_settings(self) -> None:
        visible = self.app.advanced_card.isVisible()
        self.app.advanced_card.setVisible(not visible)
        self.app.toggle_advanced_btn.setText("Show Advanced Settings" if visible else "Hide Advanced Settings")
        self.update_controls_layout()

    def update_controls_layout(self) -> None:
        self.app.controls.adjustSize()
        # Honour the dashboard-only visibility rule on startup too - the
        # user's last-selected tab may not be Dashboards.
        if hasattr(self.app, "tabs"):
            self.apply_controls_visibility_for_tab(self.app.tabs.currentIndex())

    def update_tab_bar_layout(self) -> None:
        if hasattr(self.app, "tabs"):
            self.app.tabs.tabBar().updateGeometry()

    def _is_dashboard_tab(self, index: int) -> bool:
        try:
            return self.app.tabs.tabText(index).strip().lower().startswith("dashboard")
        except Exception:
            return False

    def apply_controls_visibility_for_tab(self, index: int) -> None:
        """Hide the giant Primary/Advanced control cards on every tab
        except Dashboards.

        Those two cards are operator-wide settings (API key, workspace,
        VirusTotal/MalwareBazaar/YARAify creds, lab inputs). They were
        visible on every tab, eating ~40% of the viewport and forcing
        every operational view (Antivirus, Network, Enterprise, etc.)
        into a cramped strip below them. Real product consoles surface
        global settings behind a gear icon or restrict them to a single
        landing/dashboard view - that's what this does.

        Window-state preservation: previously this method called
        `layout().activate()` + `updateGeometry()` to force the freed
        vertical space to collapse. That worked, but on Windows the
        forced re-layout flipped the top-level window out of
        Maximized / FullScreen state every time the analyst switched
        tabs. We now snapshot the window state, toggle visibility (Qt
        excludes hidden widgets from the layout automatically - no
        manual activate is required), and then restore the original
        state if Qt nudged it during the toggle."""
        if not hasattr(self.app, "controls"):
            return
        show = self._is_dashboard_tab(index)
        # Snapshot the top-level window state before touching visibility.
        try:
            from PySide6.QtCore import Qt
            window = self.app.window() if hasattr(self.app, "window") else None
            prev_state = window.windowState() if window is not None else None
        except Exception:
            window, prev_state = None, None
        try:
            # The two giant settings cards.
            self.app.controls.setVisible(show)
            # The "Hide Advanced Settings" toggle is itself a setting only
            # meaningful while the cards are visible.
            if hasattr(self.app, "toggle_advanced_btn"):
                self.app.toggle_advanced_btn.setVisible(show)
            # The 4 global hub metric chips (Processes/Telemetry/Last
            # Incident/Artifacts) - irrelevant on Antivirus/Network/etc.
            if hasattr(self.app, "hero_status"):
                self.app.hero_status.setVisible(show)
            # The 5 Dashboards-only quick-action buttons (Run Monitor,
            # Load Processes, Lookup Hash, Lookup IP, Filter Persistence)
            # - same reasoning. Health badge + auth_role badge stay
            # always-visible because they are runtime status indicators.
            for btn in getattr(self.app, "dashboard_only_action_buttons", []):
                btn.setVisible(show)
            # Restore Maximized / FullScreen if the visibility flip
            # accidentally dropped them. Qt sometimes clears these flags
            # on a layout change because the central widget's size hint
            # shrinks; snap them back so the analyst doesn't see the
            # window pop out of fullscreen on every tab switch.
            if window is not None and prev_state is not None:
                wanted = prev_state & (Qt.WindowMaximized | Qt.WindowFullScreen)
                current = window.windowState()
                missing = wanted & ~current
                if int(missing) != 0:
                    window.setWindowState(current | wanted)
        except Exception:
            return

    def on_tab_changed(self, _index: int) -> None:
        # Tab visibility / settings save are cheap - keep them inline.
        self.apply_controls_visibility_for_tab(_index)
        self.save_settings()
        # Auto-refresh on tab switch was removed per UX request - the
        # operator drives every refresh manually from per-tab buttons
        # (Refresh / Run Monitor / Refresh Overview / etc.).

    def auto_refresh_active_tab(self) -> None:
        # Kept as a no-op shim so any external caller (or future
        # scripted workflow) doesn't crash; manual buttons are the
        # only refresh path now.
        return

    def load_settings(self) -> None:
        settings = self.app.settings
        # ── Plain text fields ────────────────────────────────────────
        text_fields = {
            "base_url": self.app.base,
            "workspace_id": self.app.workspace_id,
            "approval_id": self.app.approval_id,
            "actor_name": self.app.actor_name,
            "hash_input": self.app.hash_input,
            "ip_input": self.app.ip_input,
            "persist_filter": self.app.persist_filter,
            "webhook_url": self.app.webhook_url,
            # P1 - operator workflow fields that previously reset every
            # restart. We do NOT persist secret AV credentials here;
            # those round-trip through the backend credential store.
            "evidence_alert_name": self.app.evidence_alert_name,
            "net_range":           self.app.net_range,
            "block_target":        self.app.block_target,
            "block_gateway":       self.app.block_gateway,
            "strings_patterns":    self.app.strings_patterns,
        }
        for key, widget in text_fields.items():
            value = settings.value(key, "", type=str)
            if value:
                widget.setText(value)
        # ── Numeric fields (QSpinBox / QDoubleSpinBox) ──────────────
        numeric_fields = {
            "duration":           (self.app.duration,           int,   5,   600),
            "interval":           (self.app.interval,           float, 0.1, 10.0),
            "strings_min_length": (self.app.strings_min_length, int,   3,   20),
            "trace_duration":     (self.app.trace_duration,     int,   2,   60),
            "trace_interval":     (self.app.trace_interval,     float, 0.1, 5.0),
        }
        for key, (widget, caster, lo, hi) in numeric_fields.items():
            raw = settings.value(key, None)
            if raw is None or raw == "":
                continue
            try:
                value = caster(raw)
            except (TypeError, ValueError):
                continue
            if value < lo or value > hi:
                continue
            try:
                widget.setValue(value)
            except Exception:
                continue
        raw_buttons = settings.value("custom_toolbar_buttons", "[]", type=str) or "[]"
        try:
            parsed = json.loads(raw_buttons)
        except Exception:
            parsed = []
        if isinstance(parsed, list):
            self.app.custom_toolbar_buttons = [
                {"label": str(item.get("label", "")).strip(), "target": str(item.get("target", "")).strip()}
                for item in parsed
                if isinstance(item, dict) and str(item.get("label", "")).strip() and str(item.get("target", "")).strip()
            ]
        else:
            self.app.custom_toolbar_buttons = []
        self.rebuild_toolbar()

    def save_settings(self) -> None:
        settings = self.app.settings
        # Plain text
        settings.setValue("base_url", self.app.base.text().strip())
        settings.setValue("workspace_id", self.app.workspace_id.text().strip())
        settings.setValue("approval_id", self.app.approval_id.text().strip())
        settings.setValue("actor_name", self.app.actor_name.text().strip())
        settings.setValue("hash_input", self.app.hash_input.text().strip())
        settings.setValue("ip_input", self.app.ip_input.text().strip())
        settings.setValue("persist_filter", self.app.persist_filter.text().strip())
        settings.setValue("webhook_url", self.app.webhook_url.text().strip())
        # Operator workflow fields (P1) - keep last-used values across restarts
        settings.setValue("evidence_alert_name", self.app.evidence_alert_name.text().strip())
        settings.setValue("net_range",           self.app.net_range.text().strip())
        settings.setValue("block_target",        self.app.block_target.text().strip())
        settings.setValue("block_gateway",       self.app.block_gateway.text().strip())
        settings.setValue("strings_patterns",    self.app.strings_patterns.text().strip())
        # Numeric fields
        settings.setValue("duration",           int(self.app.duration.value()))
        settings.setValue("interval",           float(self.app.interval.value()))
        settings.setValue("strings_min_length", int(self.app.strings_min_length.value()))
        settings.setValue("trace_duration",     int(self.app.trace_duration.value()))
        settings.setValue("trace_interval",     float(self.app.trace_interval.value()))
        settings.setValue("custom_toolbar_buttons", json.dumps(self.app.custom_toolbar_buttons, ensure_ascii=True))
