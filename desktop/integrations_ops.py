from __future__ import annotations

import html
import json
import re
import time
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices

try:
    from _safe_paths import UnsafeArtifactPath, ensure_under_artifact_root
except ImportError:  # pragma: no cover
    from desktop._safe_paths import UnsafeArtifactPath, ensure_under_artifact_root
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QInputDialog,
)

try:
    from _audit_log import AuditLogStore, actor_workspace_pair
except ImportError:  # pragma: no cover
    from desktop._audit_log import AuditLogStore, actor_workspace_pair

try:
    from _audit_mirror import install_backend_mirror as _install_audit_mirror
except ImportError:  # pragma: no cover
    from desktop._audit_mirror import install_backend_mirror as _install_audit_mirror

try:
    from _action_common import ActionGate, ReasonCapture
except ImportError:  # pragma: no cover
    from desktop._action_common import ActionGate, ReasonCapture

try:
    from _response_dialog import prompt_response_reason as _prompt_response_reason
except ImportError:  # pragma: no cover
    from desktop._response_dialog import prompt_response_reason as _prompt_response_reason


# Server-accepted integration actions. Mirrored client-side so a typo
# in a future button can't reach an undocumented endpoint.
INTEGRATIONS_ACTION_ALLOWLIST: frozenset[str] = frozenset({
    "ioc-add", "ioc-delete", "ioc-query",
    "rule-add", "rule-delete", "rule-query",
    "policy-save", "policy-load",
    "scheduler-start", "scheduler-stop",
    "hids-orchestrate", "hids-orchestrate-dry",
    "hids-live-start", "hids-live-stop",
    "import-file", "import-manager", "import-reports", "import-artifacts",
})

# Actions that touch detection state or external connectors and need a
# structured reason for the audit chain.
INTEGRATIONS_REASON_REQUIRED: frozenset[str] = frozenset({
    "ioc-delete", "rule-delete", "policy-save", "hids-orchestrate",
})

INTEGRATIONS_DEBOUNCE_SECONDS = 1.5

INTEGRATIONS_AUDIT_RETENTION = 500


class IntegrationsWorkspaceController:
    def __init__(self, app) -> None:
        self.app = app
        self._audit_store = AuditLogStore(
            self.audit_log_path,
            retention=INTEGRATIONS_AUDIT_RETENTION,
        )
        _install_audit_mirror(self._audit_store, app, source_slug="integrations")
        self._gate = ActionGate(
            allowlist=INTEGRATIONS_ACTION_ALLOWLIST,
            debounce_seconds=INTEGRATIONS_DEBOUNCE_SECONDS,
            status_bar=lambda msg: app.statusBar().showMessage(msg),
        )
        self._reason = ReasonCapture(
            reason_required=INTEGRATIONS_REASON_REQUIRED,
            parent=app,
            on_cancel=lambda action: app.statusBar().showMessage(
                f"`{action}` cancelled — structured reason required."
            ),
        )
        self._last_action_click: dict[str, float] = {}

    # ------------------------------------------------------------------ #
    # Audit + reason helpers (paylaşılan model)
    # ------------------------------------------------------------------ #

    def audit_log_path(self) -> Path:
        return Path.cwd() / "shadowlab_out" / "integrations-audit-log.json"

    def load_audit_log(self) -> list[dict]:
        return self._audit_store.load()

    def _check_action_gate(self, action: str) -> bool:
        # Delegate to the shared `ActionGate`. Legacy mirror dict
        # updated for tests that touch it directly.
        ok = self._gate.check(action)
        if ok:
            self._last_action_click[action] = time.time()
        return ok

    def _capture_reason(self, action: str) -> dict | None:
        return self._reason.capture(action)

    def _record_audit(
        self,
        *,
        action: str,
        target: str,
        severity: str,
        status: str,
        payload,
        reason: dict | None = None,
    ) -> dict:
        actor, workspace = actor_workspace_pair(self.app)
        return self._audit_store.append(
            category="integrations",
            action=action,
            target=target,
            severity=severity,
            status=status,
            payload=payload,
            actor=actor,
            workspace=workspace,
            reason=reason if reason else None,
        )

    # ------------------------------------------------------------------ #
    # WHIDS hardening helpers (P0: validation, sudo, confirmation)
    # ------------------------------------------------------------------ #

    SUDO_WINDOW_SECONDS = 5 * 60
    _ENDPOINT_UUID_RE = None

    def _mark_whids_sudo_verified(self) -> None:
        import time as _time
        self._whids_sudo_expires_at = _time.time() + self.SUDO_WINDOW_SECONDS

    def _whids_sudo_required(self) -> bool:
        import time as _time
        return _time.time() >= getattr(self, "_whids_sudo_expires_at", 0.0)

    def _ensure_whids_sudo_or_warn(self, action_label: str) -> bool:
        """Block destructive WHIDS actions on a stale session.

        Mirrors the Security Ops sudo-mode pattern: the operator must
        either have refreshed within the 5-minute window OR explicitly
        click through a warning. Test Connection success counts as a
        fresh verification, so the typical workflow (configure → test →
        change) doesn't trip the gate.
        """
        if not self._whids_sudo_required():
            return True
        confirm = QMessageBox(self.app)
        confirm.setWindowTitle("Re-verify recommended")
        confirm.setIcon(QMessageBox.Warning)
        confirm.setText(f"Sudo window expired - proceed with {action_label}?")
        confirm.setInformativeText(
            "It has been more than 5 minutes since the last verified WHIDS "
            "action on this session. Run Test Connection to refresh the window, "
            "or click OK to continue at your own risk."
        )
        confirm.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
        return confirm.exec() == QMessageBox.Ok

    @classmethod
    def _validate_uuid(cls, value: str) -> tuple[bool, str]:
        """Return `(ok, normalized)` for a UUID string. Empty is accepted."""
        import re as _re
        candidate = (value or "").strip()
        if not candidate:
            return True, ""
        if cls._ENDPOINT_UUID_RE is None:
            cls._ENDPOINT_UUID_RE = _re.compile(
                r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
            )
        if not cls._ENDPOINT_UUID_RE.match(candidate):
            return False, candidate
        return True, candidate.lower()

    def _validated_endpoint_uuid(self) -> tuple[bool, str]:
        ok, value = self._validate_uuid(self.app.whids_endpoint_uuid.text())
        if not ok:
            self.app._show_error(
                self.app.whids_detail,
                "Invalid Endpoint UUID",
                ValueError(
                    f"`{value}` is not a valid UUID. Expected 8-4-4-4-12 hex format "
                    "(e.g. 0fbe89ab-2c45-4d2e-9c91-7bb1c5d8a1ff), or leave the field empty."
                ),
            )
            return False, ""
        return True, value

    @staticmethod
    def _validate_json_payload(raw: str, *, allow_empty: bool = False) -> tuple[bool, object, str]:
        """Parse a JSON-bearing form field. Returns `(ok, parsed, error)`."""
        text = (raw or "").strip()
        if not text:
            if allow_empty:
                return True, None, ""
            return False, None, "Payload is empty - paste a JSON object or array first."
        try:
            parsed = json.loads(text)
            return True, parsed, ""
        except json.JSONDecodeError as exc:
            return False, None, f"Malformed JSON: {exc.msg} at line {exc.lineno}, column {exc.colno}."

    def _confirm_destructive(self, *, title: str, message: str, informative: str) -> bool:
        confirm = QMessageBox(self.app)
        confirm.setWindowTitle(title)
        confirm.setIcon(QMessageBox.Critical)
        confirm.setText(message)
        confirm.setInformativeText(informative)
        confirm.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
        return confirm.exec() == QMessageBox.Ok

    def _refresh_tls_warning(self) -> None:
        """Surface an inline TLS-off warning when the configured manager
        URL is non-loopback AND `Verify TLS` is unchecked.

        Catches the most common operator footgun: pasting a corp WHIDS
        URL while keeping the dev-default `Verify TLS = False`. The
        warning sits inside the WHIDS Controls card so it can never be
        scrolled away from.
        """
        if not hasattr(self, "_whids_tls_warning_label"):
            return
        url = (self.app.whids_manager_url.text() or "").strip().lower()
        verify_on = bool(getattr(self.app.whids_verify_tls, "isChecked", lambda: True)())
        is_loopback = any(host in url for host in ("localhost", "127.0.0.1", "::1"))
        if not verify_on and url and not is_loopback:
            self._whids_tls_warning_label.setText(
                "⚠ Verify TLS is OFF for a non-loopback manager. A network "
                "intermediary can MitM the credentials below. Re-enable Verify "
                "TLS for any non-localhost destination."
            )
            self._whids_tls_warning_label.setStyleSheet(
                "color:#feb2b2; background:#2c1820; padding:6px 10px;"
                " border:1px solid #5f1d1d; border-radius:6px; font-size:11px; font-weight:600;"
            )
            self._whids_tls_warning_label.setVisible(True)
        else:
            self._whids_tls_warning_label.setVisible(False)

    # ------------------------------------------------------------------ #
    # Guarded wrappers around the upstream `app.*_whids_*` methods. Each
    # one adds: UUID preflight + JSON validation where applicable +
    # confirmation modal + sudo gate. The existing app helpers retain
    # their own structured-reason capture so the audit chain stays
    # consistent across consoles.
    # ------------------------------------------------------------------ #

    def _guarded_add_whids_iocs(self) -> None:
        ok_uuid, _ = self._validated_endpoint_uuid()
        if not ok_uuid:
            return
        ok_json, _, error = self._validate_json_payload(
            self.app.whids_ioc_payload.toPlainText() if hasattr(self.app.whids_ioc_payload, "toPlainText")
            else self.app.whids_ioc_payload.text()
        )
        if not ok_json:
            self.app._show_error(self.app.whids_detail, "Add IoC blocked", ValueError(error))
            return
        if hasattr(self, "_whids_busy"):
            self._whids_busy.set_busy(True, "Submitting IoC…")
        try:
            self.app.add_whids_iocs()
        finally:
            if hasattr(self, "_whids_busy"):
                self._whids_busy.set_busy(False)

    def _guarded_add_whids_rules(self) -> None:
        ok_uuid, _ = self._validated_endpoint_uuid()
        if not ok_uuid:
            return
        raw = self.app.whids_rule_payload.toPlainText() if hasattr(self.app.whids_rule_payload, "toPlainText") \
            else self.app.whids_rule_payload.text()
        text = (raw or "").strip()
        if not text:
            self.app._show_error(self.app.whids_detail, "Add Rule blocked",
                                 ValueError("Rule body is empty - paste a YARA rule or JSON envelope first."))
            return
        # Best-effort JSON validation; accept non-JSON payloads (raw YARA)
        # without blocking the request.
        if text.lstrip().startswith(("{", "[")):
            ok_json, _, error = self._validate_json_payload(text)
            if not ok_json:
                self.app._show_error(self.app.whids_detail, "Add Rule blocked", ValueError(error))
                return
        if hasattr(self, "_whids_busy"):
            self._whids_busy.set_busy(True, "Submitting rule…")
        try:
            self.app.add_whids_rules()
        finally:
            if hasattr(self, "_whids_busy"):
                self._whids_busy.set_busy(False)

    def _guarded_delete_whids_iocs(self) -> None:
        if not self._ensure_whids_sudo_or_warn("Delete IoCs"):
            return
        if not self._confirm_destructive(
            title="Confirm IoC deletion",
            message="Delete IoC(s) from the WHIDS manager?",
            informative=(
                "This removes the matching IoC entries from the live manager. "
                "Active detections referencing the IoC will stop firing. "
                "A structured reason will be required next."
            ),
        ):
            return
        if hasattr(self, "_whids_busy"):
            self._whids_busy.set_busy(True, "Deleting IoCs…")
        try:
            self.app.delete_whids_iocs()
        finally:
            if hasattr(self, "_whids_busy"):
                self._whids_busy.set_busy(False)

    def _guarded_delete_whids_rules(self) -> None:
        if not self._ensure_whids_sudo_or_warn("Delete Rule"):
            return
        rule_name = (self.app.whids_rule_name.text() or "").strip() if hasattr(self.app, "whids_rule_name") else ""
        if not rule_name:
            if not self._confirm_destructive(
                title="Confirm bulk rule deletion",
                message="Delete WITHOUT a rule name filter?",
                informative=(
                    "No Rule Name / Filter is set - the deletion will be applied to "
                    "every matching rule on the manager. Type a filter substring above "
                    "to narrow scope, or click OK to continue with the bulk action."
                ),
            ):
                return
        else:
            if not self._confirm_destructive(
                title="Confirm rule deletion",
                message=f"Delete rule(s) matching `{rule_name}`?",
                informative=(
                    "Detections backed by the named rule will stop firing immediately. "
                    "A structured reason will be required next."
                ),
            ):
                return
        if hasattr(self, "_whids_busy"):
            self._whids_busy.set_busy(True, "Deleting rule(s)…")
        try:
            self.app.delete_whids_rules()
        finally:
            if hasattr(self, "_whids_busy"):
                self._whids_busy.set_busy(False)

    def _guarded_save_integration_policy(self) -> None:
        if not self._ensure_whids_sudo_or_warn("Save Response Policy"):
            return
        raw = self.app.integration_policy_payload.toPlainText() if hasattr(self.app.integration_policy_payload, "toPlainText") \
            else self.app.integration_policy_payload.text()
        ok_json, _, error = self._validate_json_payload(raw)
        if not ok_json:
            self.app._show_error(self.app.whids_detail, "Save Policy blocked", ValueError(error))
            return
        if not self._confirm_destructive(
            title="Confirm Response Policy save",
            message="Rewrite the live Response Policy?",
            informative=(
                "Save Policy replaces the active enforcement document. "
                "Hosts running this policy will pick up the new configuration "
                "on their next poll. Review the JSON above before confirming."
            ),
        ):
            return
        if hasattr(self, "_whids_busy"):
            self._whids_busy.set_busy(True, "Saving response policy…")
        try:
            self.app.save_integration_policy()
        finally:
            if hasattr(self, "_whids_busy"):
                self._whids_busy.set_busy(False)

    def test_whids_connection(self) -> None:
        """Probe the configured WHIDS manager URL and update the health badge.

        Reads the live form fields - no extra round-trip through the
        ShadowLab backend, which means the analyst gets immediate
        feedback even when the central API is unreachable.
        """
        app = self.app
        url = (app.whids_manager_url.text() or "").strip().rstrip("/")
        api_key = (app.whids_manager_api_key.text() or "").strip()
        verify_on = bool(getattr(app.whids_verify_tls, "isChecked", lambda: True)())
        if not url:
            app.statusBar().showMessage("Set the WHIDS Manager URL first.", 5000)
            return
        # Pre-flight: reject obvious malformed shapes so we never tee up a
        # round-trip that the urllib stack will reject anyway.
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.scheme not in {"https", "http"}:
                raise ValueError(f"Unsupported scheme: {parsed.scheme!r}")
        except Exception as exc:
            self._set_whids_health_badge("malformed URL", "crit")
            app._show_error(app.whids_detail, "Connection test failed", exc)
            return

        # Lock the action surface so a second click can't fire while the
        # first probe is in flight.
        if hasattr(self, "_whids_busy"):
            self._whids_busy.set_busy(True, "Testing WHIDS manager connection…")
        try:
            import requests as _requests
            headers = {"X-Api-Key": api_key} if api_key else {}
            response = _requests.get(
                f"{url}/api/v1/manager/info",
                headers=headers,
                timeout=8,
                verify=verify_on,
            )
            if response.ok:
                self._set_whids_health_badge(f"healthy · HTTP {response.status_code}", "ok")
                app.statusBar().showMessage(
                    f"Connection OK: HTTP {response.status_code} from {url}", 5000,
                )
                self._mark_whids_sudo_verified()
            elif response.status_code in {401, 403}:
                self._set_whids_health_badge(f"auth rejected · {response.status_code}", "crit")
            else:
                self._set_whids_health_badge(f"reachable · HTTP {response.status_code}", "warn")
            from _panel_kit import redact_payload as _redact
            try:
                body = response.json()
            except Exception:
                body = {"raw": response.text[:600]}
            app._show_json(app.whids_detail, _redact({
                "test_connection": {
                    "url": url,
                    "verify_tls": verify_on,
                    "status_code": response.status_code,
                    "body": body,
                }
            }))
        except Exception as exc:
            self._set_whids_health_badge("unreachable", "crit")
            app._show_error(app.whids_detail, "WHIDS connection test failed", exc)
        finally:
            if hasattr(self, "_whids_busy"):
                self._whids_busy.set_busy(False)

    def _set_whids_health_badge(self, label: str, tone: str = "neutral") -> None:
        palette = {
            "ok":      ("#1b4332", "#9ae6b4"),
            "warn":    ("#5c4400", "#f6e05e"),
            "crit":    ("#5f1d1d", "#feb2b2"),
            "neutral": ("#4a5568", "white"),
        }
        bg, fg = palette.get(tone, palette["neutral"])
        if hasattr(self.app, "whids_health_badge"):
            self.app.whids_health_badge.setText(f"WHIDS: {label}")
            self.app.whids_health_badge.setStyleSheet(
                f"background:{bg};color:{fg};padding:6px 10px;border-radius:8px;"
                "font-weight:700;font-size:11px;"
            )

    def build_whids_tab(self) -> QWidget:
        app = self.app
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(8, 8, 8, 8)
        l.setSpacing(8)
        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(8)
        header_left = QWidget()
        header_left_layout = QVBoxLayout(header_left)
        header_left_layout.setContentsMargins(0, 0, 0, 0)
        header_left_layout.setSpacing(3)
        header_title = QLabel("WHIDS Integration")
        header_title.setStyleSheet("font-size:16px;font-weight:700;color:#f4f7fb;letter-spacing:0.2px;")
        header_left_layout.addWidget(header_title)
        open_whids_target_btn = QPushButton("Open Selected Target")
        open_whids_target_btn.clicked.connect(app.open_selected_whids_target)
        app._bind_capability(open_whids_target_btn, "can_manage_integrations")
        open_whids_case_btn = QPushButton("Open Enterprise Case")
        open_whids_case_btn.clicked.connect(lambda: app.open_enterprise_case_for_incident(prefix="WHIDS-"))
        app._bind_capability(open_whids_case_btn, "can_manage_incidents")
        header_actions = QWidget()
        header_actions_layout = QHBoxLayout(header_actions)
        header_actions_layout.setContentsMargins(0, 0, 0, 0)
        header_actions_layout.setSpacing(8)
        header_actions_layout.addWidget(open_whids_target_btn)
        header_actions_layout.addWidget(open_whids_case_btn)
        app.whids_health_badge = QLabel("WHIDS: unknown")
        app.whids_health_badge.setStyleSheet("background:#4a5568;color:white;padding:6px 10px;border-radius:8px;font-weight:700;")
        header_layout.addWidget(header_left, 1)
        header_layout.addWidget(header_actions, 0, Qt.AlignTop)
        header_layout.addWidget(app.whids_health_badge, 0, Qt.AlignTop | Qt.AlignRight)
        l.addWidget(header)
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("background:#1e3050;max-height:1px;border:none;")
        l.addWidget(sep)

        # ---- KPI strip + TLS warning. Five chips give one-glance posture
        # for the WHIDS workspace; the TLS banner only renders when the
        # Verify-TLS-off footgun is detected.
        try:
            from _panel_kit import build_kpi_strip
        except ImportError:
            from desktop._panel_kit import build_kpi_strip
        kpi_strip, self._whids_kpis = build_kpi_strip(
            w, ("Endpoints", "Last Sync", "Pending Alerts", "Scheduler", "Manager"),
        )
        l.addWidget(kpi_strip)

        self._whids_tls_warning_label = QLabel("")
        self._whids_tls_warning_label.setWordWrap(True)
        self._whids_tls_warning_label.setVisible(False)
        l.addWidget(self._whids_tls_warning_label)
        # Wire field changes to the warning + start in the right state.
        app.whids_manager_url.textChanged.connect(lambda _: self._refresh_tls_warning())
        if hasattr(app.whids_verify_tls, "toggled"):
            app.whids_verify_tls.toggled.connect(lambda _: self._refresh_tls_warning())
        self._refresh_tls_warning()

        top = QWidget()
        top_layout = QVBoxLayout(top)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(4)
        # Inline tooltips so the operator doesn't need to consult the
        # WHIDS docs to understand which button does what. Mirrors the
        # post-review feedback that the dense action-row read as a
        # wall of identical chips.
        manager_import_btn = QPushButton("Pull WHIDS Manager")
        manager_import_btn.setToolTip("Pull manager state (endpoint inventory, fleet config) from the WHIDS Manager URL.")
        manager_import_btn.clicked.connect(app.import_whids_manager)
        app._bind_capability(manager_import_btn, "can_manage_integrations")
        report_import_btn = QPushButton("Pull WHIDS Reports")
        report_import_btn.setToolTip("Fetch newly-generated detection reports from the manager and normalise them into history.")
        report_import_btn.clicked.connect(app.import_whids_reports)
        app._bind_capability(report_import_btn, "can_manage_integrations")
        artifact_import_btn = QPushButton("Pull WHIDS Artifacts")
        artifact_import_btn.setToolTip(
            "Pull binary / log artifacts since the configured timestamp, bounded by Artifact Limit."
        )
        artifact_import_btn.clicked.connect(app.import_whids_artifacts)
        app._bind_capability(artifact_import_btn, "can_manage_integrations")
        manager_refresh_btn = QPushButton("Refresh WHIDS")
        manager_refresh_btn.setToolTip("Reload the local WHIDS workspace tables from cached history (no manager round-trip).")
        manager_refresh_btn.clicked.connect(app.refresh_whids_workspace)
        app._bind_capability(manager_refresh_btn, "can_manage_integrations")
        query_iocs_btn = QPushButton("Query IoCs")
        query_iocs_btn.setToolTip("List IoCs currently configured on the WHIDS manager.")
        query_iocs_btn.clicked.connect(app.query_whids_iocs)
        app._bind_capability(query_iocs_btn, "can_manage_integrations")
        add_iocs_btn = QPushButton("Add IoCs")
        add_iocs_btn.setToolTip("Submit the JSON payload above as a new IoC entry to the manager.")
        add_iocs_btn.clicked.connect(self._guarded_add_whids_iocs)
        app._bind_capability(add_iocs_btn, "can_manage_integrations")
        delete_iocs_btn = QPushButton("Delete IoCs")
        delete_iocs_btn.clicked.connect(self._guarded_delete_whids_iocs)
        app._bind_capability(delete_iocs_btn, "can_manage_integrations")
        query_rules_btn = QPushButton("Query Rules")
        query_rules_btn.setToolTip("List detection rules currently published to the manager.")
        query_rules_btn.clicked.connect(app.query_whids_rules)
        app._bind_capability(query_rules_btn, "can_manage_integrations")
        add_rules_btn = QPushButton("Add Rules")
        add_rules_btn.setToolTip("Push the YARA / JSON rule body above to the manager.")
        add_rules_btn.clicked.connect(self._guarded_add_whids_rules)
        app._bind_capability(add_rules_btn, "can_manage_integrations")
        delete_rules_btn = QPushButton("Delete Rule")
        delete_rules_btn.clicked.connect(self._guarded_delete_whids_rules)
        app._bind_capability(delete_rules_btn, "can_manage_integrations")
        scheduler_start_btn = QPushButton("Start Scheduler")
        scheduler_start_btn.setToolTip("Begin polling the manager at the Scheduler Poll interval set below.")
        scheduler_start_btn.clicked.connect(app.start_whids_scheduler)
        app._bind_capability(scheduler_start_btn, "can_manage_integrations")
        scheduler_stop_btn = QPushButton("Stop Scheduler")
        scheduler_stop_btn.setToolTip("Halt the scheduled poll. Any in-flight pull continues to completion.")
        scheduler_stop_btn.clicked.connect(app.stop_whids_scheduler)
        app._bind_capability(scheduler_stop_btn, "can_manage_integrations")
        scheduler_status_btn = QPushButton("Scheduler Status")
        scheduler_status_btn.setToolTip("Show the live scheduler state: running / stopped, last run, next run.")
        scheduler_status_btn.clicked.connect(app.refresh_whids_scheduler_status)
        app._bind_capability(scheduler_status_btn, "can_manage_integrations")
        load_policy_btn = QPushButton("Load Policy")
        load_policy_btn.setToolTip("Pull the active Response Policy JSON from the server into the editor below.")
        load_policy_btn.clicked.connect(app.load_integration_policy)
        app._bind_capability(load_policy_btn, "can_manage_integrations")
        save_policy_btn = QPushButton("Save Policy")
        save_policy_btn.clicked.connect(self._guarded_save_integration_policy)
        app._bind_capability(save_policy_btn, "can_manage_integrations")
        app.whids_ioc_payload.setMinimumHeight(24)
        app.whids_ioc_payload.setMaximumHeight(24)
        app.whids_rule_payload.setMinimumHeight(24)
        app.whids_rule_payload.setMaximumHeight(24)
        app.integration_policy_payload.setMinimumHeight(24)
        app.integration_policy_payload.setMaximumHeight(24)
        import_btn = QPushButton("Import WHIDS File")
        import_btn.clicked.connect(app.import_whids_file)
        app._bind_capability(import_btn, "can_manage_integrations")

        verify_block = QWidget()
        verify_block_layout = QVBoxLayout(verify_block)
        verify_block_layout.setContentsMargins(0, 0, 0, 0)
        verify_block_layout.setSpacing(2)
        verify_label = QLabel("")
        verify_label.setMinimumHeight(14)
        verify_label.setMaximumHeight(14)
        verify_block_layout.addWidget(verify_label)
        verify_block_layout.addWidget(app.whids_verify_tls)

        transport_block = app._field_block("Transport", verify_block)
        row1 = QWidget()
        row1_layout = QHBoxLayout(row1)
        row1_layout.setContentsMargins(0, 0, 0, 0)
        row1_layout.setSpacing(8)
        row1_layout.addWidget(app._field_block("WHIDS Manager URL", app.whids_manager_url), 1)
        row1_layout.addWidget(app._field_block("X-Api-Key", app.whids_manager_api_key), 1)
        row1_layout.addWidget(app._field_block("Endpoint UUID (optional)", app.whids_endpoint_uuid), 1)
        row1_layout.addWidget(transport_block, 1)

        row2 = QWidget()
        row2_layout = QHBoxLayout(row2)
        row2_layout.setContentsMargins(0, 0, 0, 0)
        row2_layout.setSpacing(8)
        row2_layout.addWidget(app._field_block("WHIDS Export File", app.whids_file_path), 1)
        row2_layout.addWidget(app._field_block("Artifacts Since (RFC3339)", app.whids_artifact_since), 1)
        row2_layout.addWidget(app._field_block("Artifact Limit", app.whids_artifact_limit), 1)
        row2_layout.addWidget(app._field_block("Scheduler Poll (s)", app.whids_scheduler_interval), 1)

        ioc_block = app._field_block("WHIDS IoC JSON", app.whids_ioc_payload)
        rule_json_block = app._field_block("WHIDS Rule JSON", app.whids_rule_payload)
        rule_name_block = app._field_block("Rule Name / Filter", app.whids_rule_name)
        policy_block = app._field_block("Response Policy JSON", app.integration_policy_payload)

        row3 = QWidget()
        row3_layout = QHBoxLayout(row3)
        row3_layout.setContentsMargins(0, 0, 0, 0)
        row3_layout.setSpacing(8)
        row3_layout.addWidget(ioc_block, 1)
        row3_layout.addWidget(rule_json_block, 1)
        row3_layout.addWidget(rule_name_block, 1)
        row3_layout.addWidget(policy_block, 1)

        top_layout.addWidget(row1)
        top_layout.addWidget(row2)
        top_layout.addWidget(row3)

        # Placeholder hints — the form fields previously offered no
        # guidance on what to type, so a first-time operator had to
        # cross-reference the WHIDS docs from memory. Concrete examples
        # let them paste-and-edit instead of read-and-guess.
        app.whids_manager_url.setPlaceholderText("https://whids.corp.example/api  (no trailing slash)")
        app.whids_manager_api_key.setPlaceholderText("X-Api-Key header value (treated as a credential)")
        app.whids_endpoint_uuid.setPlaceholderText("UUID for a single endpoint (leave blank to span the fleet)")
        app.whids_artifact_since.setPlaceholderText("2026-05-01T00:00:00Z  (RFC 3339)")
        app.whids_ioc_payload.setPlaceholderText('{"value":"203.0.113.5","type":"ip","source":"shadowlab"}')
        app.whids_rule_payload.setPlaceholderText('YARA rule body or JSON rule envelope expected by your WHIDS build.')
        app.whids_rule_name.setPlaceholderText("Rule name or filter substring (used for Query / Delete)")
        app.integration_policy_payload.setPlaceholderText('{"default_action":"alert","containment":{"isolate":false}}')

        app.whids_summary = QTextBrowser()
        app.whids_summary.setProperty("role", "brief")
        app.whids_summary.setMinimumHeight(180)
        app.whids_summary.setHtml(
            "<div style='padding:6px'>"
            "<h3 style='margin:0 0 6px 0;color:#cbd5e0'>WHIDS Integration</h3>"
            "<p style='color:#9aa5b1;line-height:1.45;margin:0'>"
            "First-time setup:<br>"
            "<b>1.</b> Paste the manager URL above (use HTTPS) and the X-Api-Key.<br>"
            "<b>2.</b> Press <b>Test Connection</b> to validate credentials.<br>"
            "<b>3.</b> Use the <b>Ingest</b> group to pull manager state / reports / artifacts.<br>"
            "<b>4.</b> Use <b>Scheduler</b> to poll automatically on the interval set below."
            "</p></div>"
        )
        app.whids_table = QTableWidget(0, 5)
        app.whids_table.setHorizontalHeaderLabels(["Created", "Type", "Target", "Status", "Detail"])
        app.whids_table.itemSelectionChanged.connect(app.show_selected_whids_export)
        app._style_table(app.whids_table)
        app.whids_table.setMinimumHeight(180)
        app.whids_table.setSortingEnabled(True)
        try:
            from _panel_kit import install_empty_table_placeholder as _install_empty
        except ImportError:
            from desktop._panel_kit import install_empty_table_placeholder as _install_empty
        _install_empty(
            app.whids_table,
            "No exports recorded yet - press Pull WHIDS Manager / Reports / Artifacts to populate.",
        )
        app.whids_detail = QTextEdit()
        app.whids_detail.setReadOnly(True)
        app.whids_detail.setProperty("role", "brief")
        app.whids_detail.setMinimumHeight(180)
        app.whids_detail.setPlainText(
            "Response payloads, errors, query results, and selected export contents land here.\n"
            "Sensitive fields (X-Api-Key, tokens, signing material) are auto-redacted before display."
        )

        controls_card = QFrame()
        controls_card.setProperty("card", True)
        controls_layout = QVBoxLayout(controls_card)
        controls_layout.setContentsMargins(12, 10, 12, 12)
        controls_layout.setSpacing(8)
        controls_title = QLabel("WHIDS Controls")
        controls_title.setStyleSheet("font-size:13px;font-weight:700;color:#f4f7fb;letter-spacing:0.2px;")
        controls_layout.addWidget(controls_title)
        controls_layout.addWidget(top)
        l.addWidget(controls_card)

        # Test connection — non-destructive probe that pings the WHIDS
        # manager with the operator's current credentials and updates
        # the health badge. Sits next to the Pull buttons because it
        # answers the same operator question ("is my manager reachable?")
        # before they kick off a real ingest.
        test_connection_btn = QPushButton("Test Connection")
        test_connection_btn.setToolTip(
            "Issue a GET against the configured WHIDS manager URL with the "
            "current credentials. Updates the WHIDS badge in the top-right "
            "without ingesting any reports."
        )
        test_connection_btn.clicked.connect(self.test_whids_connection)
        app._bind_capability(test_connection_btn, "can_manage_integrations")

        # ---- Action buttons grouped by intent so the previous 14-in-a-row
        # wall of identical chips becomes a visual hierarchy.
        # Group palette mirrors the network tab's "category card" pattern.
        controls_actions = QWidget()
        controls_actions_layout = QVBoxLayout(controls_actions)
        controls_actions_layout.setContentsMargins(0, 0, 0, 0)
        controls_actions_layout.setSpacing(6)

        # Common style helpers.
        def _style_button(btn, *, destructive: bool = False) -> None:
            btn.setMinimumHeight(28)
            btn.setMinimumWidth(max(92, btn.sizeHint().width() + 18))
            btn.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            if destructive:
                # Destructive actions get the muted red tone shared with
                # Security Ops + Network Warfare. Hover brightens and the
                # pressed state visibly sinks so accidental clicks register.
                btn.setStyleSheet(
                    "QPushButton{background:#2c1820;color:#feb2b2;border:1px solid #5f1d1d;"
                    "border-radius:8px;padding:4px 8px;font-weight:600;font-size:10px;}"
                    "QPushButton:hover{background:#3d2129;border-color:#8a2a2a;color:#ffd0d0;}"
                    "QPushButton:pressed{background:#511c1c;border-color:#a83232;padding-top:5px;padding-bottom:3px;}"
                    "QPushButton:disabled{background:#1f1418;color:#7a5a5a;border-color:#3a2024;}"
                )
            else:
                btn.setStyleSheet(
                    "QPushButton{background:#1a2a3d;color:#c8d8ea;border:1px solid #2c4260;"
                    "border-radius:8px;padding:4px 8px;font-weight:600;font-size:10px;}"
                    "QPushButton:hover{background:#23394f;border-color:#4a6c95;color:#eaf2fb;}"
                    "QPushButton:pressed{background:#2f4f70;border-color:#5d8aa8;padding-top:5px;padding-bottom:3px;}"
                    "QPushButton:disabled{background:#141d28;color:#5e6f80;border-color:#23303f;}"
                )

        # Pre-mark the destructive buttons so the operator can see the
        # consequence in the label and the help-text confirmation flow
        # can demand structured reasons (handled in app.delete_*).
        for dbtn, label, shortcut in (
            (delete_iocs_btn,   "⚠ Delete IoCs",   None),
            (delete_rules_btn,  "⚠ Delete Rule",   None),
            (save_policy_btn,   "⚠ Save Policy",   None),
        ):
            dbtn.setText(label)
            dbtn.setToolTip(
                "Destructive — confirmation required. Wraps a structured-reason "
                "capture so the audit chain records WHY the change was made."
            )

        def _make_group(title: str, accent: str, buttons: list[QPushButton]) -> QWidget:
            group = QFrame()
            group.setProperty("card", True)
            group.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
            group.setStyleSheet(
                "QFrame[card='true']{"
                f"background:#0e1720;border:1px solid {accent};border-radius:7px;padding:2px 4px;"
                "}"
            )
            gl = QHBoxLayout(group)
            gl.setContentsMargins(6, 2, 6, 2)
            gl.setSpacing(3)
            cap = QLabel(title)
            cap.setStyleSheet(f"color:{accent};font-size:9px;font-weight:800;letter-spacing:0.5px;")
            gl.addWidget(cap)
            for btn in buttons:
                _style_button(btn, destructive=btn in (delete_iocs_btn, delete_rules_btn, save_policy_btn))
                gl.addWidget(btn)
            return group

        action_groups = [
            ("Ingest",     "#3a6ea8", [manager_import_btn, report_import_btn, artifact_import_btn, manager_refresh_btn, test_connection_btn]),
            ("Scheduler",  "#5d8aa8", [scheduler_start_btn, scheduler_stop_btn, scheduler_status_btn]),
            ("IoC",        "#7d6ca8", [query_iocs_btn, add_iocs_btn, delete_iocs_btn]),
            ("Rules",      "#9b6ca8", [query_rules_btn, add_rules_btn, delete_rules_btn]),
            ("Policy",     "#a87d6c", [load_policy_btn, save_policy_btn, import_btn]),
        ]
        # Two content-sized rows. The IoC group rides up onto the top
        # row so the wide empty space to the right of Scheduler is used
        # instead of wasted, leaving a balanced Rules/Policy bottom row.
        # Each group hugs its own buttons and a trailing stretch keeps
        # them left-packed — the previous QGridLayout forced shared
        # column widths, so the IoC card was stretched to the 5-button
        # Ingest width and rendered a wide empty gap before its buttons.
        for row_groups in ([0, 1, 2], [3, 4]):
            row_widget = QWidget()
            row_layout = QHBoxLayout(row_widget)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(6)
            for idx in row_groups:
                title, accent, buttons = action_groups[idx]
                row_layout.addWidget(_make_group(title, accent, buttons))
            row_layout.addStretch(1)
            controls_actions_layout.addWidget(row_widget)
        l.addWidget(controls_actions)

        # Track every action button so the BusyController + capability
        # gate can flip them in unison during long ingests.
        self._whids_action_buttons = (
            [test_connection_btn]
            + [b for _, _, group_btns in action_groups for b in group_btns]
        )
        # Centralised busy controller — disables every action button + flips
        # the parent-window cursor + pushes a status-bar message while a
        # long-running ingest is in flight. The previous wiring let an
        # operator click "Pull Reports" five times in a row and watch the
        # last one win silently.
        try:
            from _panel_kit import BusyController
        except ImportError:
            from desktop._panel_kit import BusyController
        self._whids_busy = BusyController(app, list(self._whids_action_buttons))

        bottom_row_cards = QWidget()
        bottom_row_layout = QHBoxLayout(bottom_row_cards)
        bottom_row_layout.setContentsMargins(0, 0, 0, 0)
        bottom_row_layout.setSpacing(8)
        bottom_row_layout.addWidget(app._panel_card("WHIDS Summary", app.whids_summary, lambda: app._open_panel_window("WHIDS Summary", app._clone_text_view(app.whids_summary))), 2)
        bottom_row_layout.addWidget(app._panel_card("WHIDS Export History", app.whids_table, lambda: app._open_panel_window("WHIDS Export History", app._clone_table(app.whids_table))), 3)
        bottom_row_layout.addWidget(app._panel_card("WHIDS Detail", app.whids_detail, lambda: app._open_panel_window("WHIDS Detail", app._clone_text_view(app.whids_detail))), 2)
        l.addWidget(bottom_row_cards, 1)
        return w

    def build_hids_tab(self) -> QWidget:
        app = self.app
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(8, 8, 8, 8)
        l.setSpacing(8)

        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(10)
        header_copy = QWidget()
        header_copy_layout = QVBoxLayout(header_copy)
        header_copy_layout.setContentsMargins(0, 0, 0, 0)
        header_copy_layout.setSpacing(2)
        header_title = QLabel("HIDS Operations Console")
        header_title.setStyleSheet("font-size:18px;font-weight:800;color:#f4f7fb;")
        header_subtitle = QLabel("OSSEC/HIDS alert intake, live ingest health, response orchestration, and normalized export review.")
        header_subtitle.setStyleSheet("color:#96a5b8;font-size:12px;")
        header_copy_layout.addWidget(header_title)
        header_copy_layout.addWidget(header_subtitle)
        header_layout.addWidget(header_copy, 1)
        app.hids_health_badge = QLabel("HIDS: unknown")
        app.hids_health_badge.setStyleSheet(
            "background:#4a5568;color:white;padding:7px 12px;border-radius:8px;font-weight:800;"
        )
        header_layout.addWidget(app.hids_health_badge, 0, Qt.AlignTop | Qt.AlignRight)
        l.addWidget(header)

        import_btn = QPushButton("Import HIDS File")
        import_btn.clicked.connect(app.import_hids_file)
        app._bind_capability(import_btn, "can_manage_integrations")
        plan_response_btn = QPushButton("Plan Response")
        plan_response_btn.clicked.connect(lambda: app.orchestrate_hids_response(False))
        app._bind_capability(plan_response_btn, "can_manage_integrations")
        apply_response_btn = QPushButton("Apply Response")
        apply_response_btn.clicked.connect(lambda: app.orchestrate_hids_response(True))
        app._bind_capability(apply_response_btn, "can_manage_integrations")
        live_start_btn = QPushButton("Start Live Ingest")
        live_start_btn.clicked.connect(app.start_hids_live_ingest)
        app._bind_capability(live_start_btn, "can_manage_integrations")
        live_stop_btn = QPushButton("Stop Live Ingest")
        live_stop_btn.clicked.connect(app.stop_hids_live_ingest)
        app._bind_capability(live_stop_btn, "can_manage_integrations")
        live_status_btn = QPushButton("Live Status")
        live_status_btn.clicked.connect(app.refresh_hids_live_status)
        app._bind_capability(live_status_btn, "can_manage_integrations")
        refresh_btn = QPushButton("Refresh HIDS")
        refresh_btn.clicked.connect(app.refresh_hids_workspace)
        app._bind_capability(refresh_btn, "can_manage_integrations")

        app.hids_kpi_exports = QLabel("--")
        app.hids_kpi_incidents = QLabel("--")
        app.hids_kpi_live = QLabel("--")
        app.hids_kpi_dedupe = QLabel("--")
        app.hids_kpi_exports_sub = QLabel("normalized rows")
        app.hids_kpi_incidents_sub = QLabel("OSSEC-linked cases")
        app.hids_kpi_live_sub = QLabel("live ingest")
        app.hids_kpi_dedupe_sub = QLabel("dedupe skips")
        kpis = QWidget()
        kpi_layout = QHBoxLayout(kpis)
        kpi_layout.setContentsMargins(0, 0, 0, 0)
        kpi_layout.setSpacing(8)
        kpi_layout.addWidget(self._integration_kpi_tile("EXPORTS", app.hids_kpi_exports, app.hids_kpi_exports_sub, "#7fd7ff"), 1)
        kpi_layout.addWidget(self._integration_kpi_tile("INCIDENTS", app.hids_kpi_incidents, app.hids_kpi_incidents_sub, "#ff6b8a"), 1)
        kpi_layout.addWidget(self._integration_kpi_tile("LIVE INGEST", app.hids_kpi_live, app.hids_kpi_live_sub, "#7fe39d"), 1)
        kpi_layout.addWidget(self._integration_kpi_tile("DEDUPED", app.hids_kpi_dedupe, app.hids_kpi_dedupe_sub, "#f4c26b"), 1)
        l.addWidget(kpis)

        top = QWidget()
        top_layout = QVBoxLayout(top)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(6)
        fields_row = QWidget()
        fields_row_layout = QHBoxLayout(fields_row)
        fields_row_layout.setContentsMargins(0, 0, 0, 0)
        fields_row_layout.setSpacing(8)
        fields_row_layout.addWidget(app._field_block("OSSEC / HIDS Alert File", app.hids_file_path), 2)
        fields_row_layout.addWidget(app._field_block("Incident ID", app.hids_incident_id), 1)
        fields_row_layout.addWidget(app._field_block("Live Poll (s)", app.hids_live_interval))
        fields_row_layout.addWidget(app.hids_live_start_at_end)

        actions_row = QWidget()
        actions_row_layout = QHBoxLayout(actions_row)
        actions_row_layout.setContentsMargins(0, 0, 0, 0)
        actions_row_layout.setSpacing(4)
        for btn in [
            import_btn,
            plan_response_btn,
            apply_response_btn,
            live_start_btn,
            live_stop_btn,
            live_status_btn,
            refresh_btn,
            open_hids_target_btn := QPushButton("Open Target"),
            open_hids_case_btn := QPushButton("Open Case"),
        ]:
            btn.setMinimumHeight(28)
            btn.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
            btn.setStyleSheet(
                "QPushButton{background:#1a2a3d;color:#c8d8ea;border:1px solid #2c4260;"
                "border-radius:8px;padding:4px 8px;font-weight:600;font-size:10px;}"
                "QPushButton:hover{background:#23394f;border-color:#4a6c95;color:#eaf2fb;}"
                "QPushButton:pressed{background:#2f4f70;border-color:#5d8aa8;padding-top:5px;padding-bottom:3px;}"
                "QPushButton:disabled{background:#141d28;color:#5e6f80;border-color:#23303f;}"
            )
            actions_row_layout.addWidget(btn)
        open_hids_target_btn.clicked.connect(app.open_selected_hids_target)
        app._bind_capability(open_hids_target_btn, "can_manage_integrations")
        open_hids_case_btn.clicked.connect(lambda: app.open_enterprise_case_for_incident(prefix="OSSEC-"))
        app._bind_capability(open_hids_case_btn, "can_manage_incidents")
        actions_row_layout.addStretch(1)
        top_layout.addWidget(fields_row)
        top_layout.addWidget(actions_row)

        controls_card = QFrame()
        controls_card.setProperty("card", True)
        controls_layout = QVBoxLayout(controls_card)
        controls_layout.setContentsMargins(12, 9, 12, 10)
        controls_layout.setSpacing(7)
        controls_title = QLabel("Ingest & Response Controls")
        controls_title.setStyleSheet("font-size:13px;font-weight:800;color:#f4f7fb;")
        controls_layout.addWidget(controls_title)
        controls_layout.addWidget(top)
        l.addWidget(controls_card)

        app.hids_summary = QTextBrowser()
        app.hids_summary.setProperty("role", "brief")
        app.hids_summary.setMinimumHeight(360)
        app.hids_summary.setHtml(
            "<h3 style='margin:0 0 8px;color:#f4f7fb;'>HIDS Intake Readiness</h3>"
            "<p style='color:#96a5b8;'>Import OSSEC/HIDS exports or start live ingest to populate normalized alerts, "
            "incident correlation, and response plans.</p>"
        )
        app.hids_table = QTableWidget(0, 5)
        app.hids_table.setHorizontalHeaderLabels(["Created", "Type", "Target", "Status", "Detail"])
        app.hids_table.itemSelectionChanged.connect(app.show_selected_hids_export)
        app._style_table(app.hids_table)
        app.hids_table.setMinimumHeight(300)
        app.hids_detail = QTextEdit()
        app.hids_detail.setReadOnly(True)
        app.hids_detail.setProperty("role", "brief")
        app.hids_detail.setMinimumHeight(360)
        app.hids_detail.setPlainText(
            "Select an export row or run an ingest/response action to inspect normalized HIDS detail."
        )

        bottom_row_cards = QWidget()
        bottom_row_layout = QHBoxLayout(bottom_row_cards)
        bottom_row_layout.setContentsMargins(0, 0, 0, 0)
        bottom_row_layout.setSpacing(8)
        bottom_row_layout.addWidget(app._panel_card("HIDS Triage & Coverage", app.hids_summary, lambda: app._open_panel_window("HIDS Triage & Coverage", app._clone_text_view(app.hids_summary))), 2)
        bottom_row_layout.addWidget(app._panel_card("Normalized Export History", app.hids_table, lambda: app._open_panel_window("HIDS Export History", app._clone_table(app.hids_table))), 4)
        bottom_row_layout.addWidget(app._panel_card("Selected Alert & Response", app.hids_detail, lambda: app._open_panel_window("HIDS Detail", app._clone_text_view(app.hids_detail))), 2)
        l.addWidget(bottom_row_cards, 1)
        return w

    def _integration_kpi_tile(self, title: str, value: QLabel, sub: QLabel, accent: str) -> QWidget:
        tile = QFrame()
        tile.setProperty("card", True)
        tile.setMinimumHeight(76)
        tile.setMaximumHeight(86)
        layout = QVBoxLayout(tile)
        layout.setContentsMargins(12, 7, 12, 7)
        layout.setSpacing(1)
        label = QLabel(title)
        label.setStyleSheet("color:#96a5b8;font-size:10px;font-weight:800;")
        value.setStyleSheet(f"color:{accent};font-size:20px;font-weight:800;")
        sub.setStyleSheet("color:#c8d8ea;font-size:10px;")
        sub.setWordWrap(True)
        layout.addWidget(label)
        layout.addWidget(value)
        layout.addWidget(sub)
        return tile

    def refresh_whids_workspace(self) -> None:
        if not self.app.auth_context.get("capabilities", {}).get("can_manage_integrations", False):
            self.app.whids_table.setRowCount(0)
            self.app.whids_summary.setHtml(
                "<h3>WHIDS Integration</h3>"
                "<p>Admin access is required for manager sync, reports, artifacts, rules, IoCs, and scheduler controls.</p>"
            )
            self.app.whids_health_badge.setText("WHIDS: locked")
            self.app.whids_health_badge.setStyleSheet("background:#4a5568;color:white;padding:6px 10px;border-radius:8px;font-weight:700;")
            self.app.whids_detail.setPlainText(
                "WHIDS integration workspace is locked for the current role.\n\n"
                "To use manager sync, rules, IoCs, scheduler, or artifact pull actions, apply an admin API key."
            )
            return
        try:
            exports = self.app._integration_rows("whids")
            incidents = self.app._incident_rows_for_prefix("WHIDS-")
            scheduler = self.app._get("/integrations/whids/scheduler/status", timeout=15).json()
        except Exception as exc:
            self.app._show_error(self.app.whids_detail, "WHIDS refresh failed", exc)
            return
        # A misbehaving/hostile manager can return a non-object JSON
        # (list/str/null); the .get() calls below would then raise an
        # uncaught AttributeError and break the whole refresh.
        if not isinstance(scheduler, dict):
            scheduler = {}
        dedupe_skips = len([item for item in exports if str(item.get("export_type", "")) == "dedupe_skip"])
        self.app.whids_table.setRowCount(len(exports))
        for r, item in enumerate(exports):
            values = [item.get("created_at", ""), item.get("export_type", ""), item.get("target", ""), item.get("status", ""), item.get("detail", "")]
            for c, value in enumerate(values):
                self.app.whids_table.setItem(r, c, QTableWidgetItem(str(value)))
            self.app._paint_row(self.app.whids_table, r, self.app._severity_color("high" if str(item.get("status", "")).lower() not in {"success", "ok"} else "low"))
        self.app.whids_summary.setHtml(
            "<h3>WHIDS Import Status</h3>"
            f"<p><b>Imports logged:</b> {len(exports)}<br>"
            f"<b>WHIDS incidents:</b> {len(incidents)}<br>"
            f"<b>Manager:</b> {html.escape(self.app.whids_manager_url.text().strip())}<br>"
            f"<b>Current file:</b> {html.escape(self.app.whids_file_path.text().strip())}<br>"
            f"<b>Endpoint UUID:</b> {html.escape(self.app.whids_endpoint_uuid.text().strip() or 'all endpoints')}<br>"
            f"<b>Artifacts since:</b> {html.escape(self.app.whids_artifact_since.text().strip() or 'not set')}<br>"
            f"<b>Scheduler:</b> {html.escape('running' if scheduler.get('running') else 'stopped')}<br>"
            f"<b>Dedupe skips:</b> {dedupe_skips}</p>"
        )
        latest_status = str(exports[0].get("status", "")) if exports else "idle"
        scheduler_running = bool(scheduler.get("running"))
        latest_color = "#2f9e67" if latest_status.lower() in {"success", "ok"} and not scheduler.get("last_error") else "#d64550" if exports and latest_status.lower() not in {"success", "ok"} or scheduler.get("last_error") else "#4a5568"
        self.app.whids_health_badge.setText(f"WHIDS: {latest_status or 'idle'} | scheduler={'on' if scheduler_running else 'off'}")
        self.app.whids_health_badge.setStyleSheet(f"background:{latest_color};color:white;padding:6px 10px;border-radius:8px;font-weight:700;")
        if exports:
            self.app.whids_detail.setPlainText(json.dumps(exports[0], indent=2, ensure_ascii=False))
        else:
            self.app.whids_detail.setPlainText(
                "No WHIDS integration exports yet.\n\n"
                "Start with a manager import, report sync, artifact pull, or local export file import."
            )

    def refresh_hids_workspace(self) -> None:
        if not self.app.auth_context.get("capabilities", {}).get("can_manage_integrations", False):
            self.app.hids_table.setRowCount(0)
            self.app.hids_summary.setHtml(
                "<h3 style='margin:0 0 8px;color:#f4f7fb;'>HIDS Locked</h3>"
                "<p style='color:#96a5b8;'>Admin access is required for OSSEC live ingest, orchestration, "
                "and provider-native response controls.</p>"
            )
            self.app.hids_health_badge.setText("HIDS: locked")
            self.app.hids_health_badge.setStyleSheet("background:#4a5568;color:white;padding:7px 12px;border-radius:8px;font-weight:800;")
            if hasattr(self.app, "hids_kpi_exports"):
                self.app.hids_kpi_exports.setText("--")
                self.app.hids_kpi_incidents.setText("--")
                self.app.hids_kpi_live.setText("LOCKED")
                self.app.hids_kpi_dedupe.setText("--")
            self.app.hids_detail.setPlainText(
                "HIDS integration workspace is locked for the current role.\n\n"
                "Apply an admin API key to run live ingest, orchestrate response, or import provider files."
            )
            return
        try:
            exports = self.app._integration_rows("ossec")
            incidents = self.app._incident_rows_for_prefix("OSSEC-")
            live_status = self.app._get("/integrations/ossec/live/status", timeout=15).json()
        except Exception as exc:
            self.app._show_error(self.app.hids_detail, "HIDS refresh failed", exc)
            return
        if not isinstance(live_status, dict):
            live_status = {}
        dedupe_skips = len([item for item in exports if str(item.get("export_type", "")) == "dedupe_skip"])
        successes = len([item for item in exports if str(item.get("status", "")).lower() in {"success", "ok"}])
        failures = len(exports) - successes
        self.app.hids_table.setRowCount(len(exports))
        for r, item in enumerate(exports):
            values = [item.get("created_at", ""), item.get("export_type", ""), item.get("target", ""), item.get("status", ""), item.get("detail", "")]
            for c, value in enumerate(values):
                self.app.hids_table.setItem(r, c, QTableWidgetItem(str(value)))
            self.app._paint_row(self.app.hids_table, r, self.app._severity_color("high" if str(item.get("status", "")).lower() not in {"success", "ok"} else "low"))
        live_label = "running" if live_status.get("running") else "stopped"
        live_error = str(live_status.get("last_error", "") or "")
        imported_live = str(live_status.get("total_imported", 0))
        current_file = self.app.hids_file_path.text().strip()
        source_path = Path(current_file) if current_file else None
        source_exists = bool(source_path and source_path.exists())
        source_size = source_path.stat().st_size if source_exists and source_path is not None else 0
        source_mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(source_path.stat().st_mtime)) if source_exists and source_path is not None else "unavailable"
        incident_ready = bool(self.app.hids_incident_id.text().strip() or incidents)
        latest_export = exports[0] if exports else {}
        latest_status = str(latest_export.get("status", "idle") or "idle")
        export_types: dict[str, int] = {}
        for item in exports:
            key = str(item.get("export_type", "unknown") or "unknown")
            export_types[key] = export_types.get(key, 0) + 1
        top_types = ", ".join(f"{html.escape(k)}={v}" for k, v in list(export_types.items())[:4]) or "none"
        weaknesses: list[str] = []
        if not source_exists:
            weaknesses.append("source file is not reachable from this workstation")
        if not live_status.get("running"):
            weaknesses.append("live ingest is stopped")
        if failures:
            weaknesses.append(f"{failures} export row(s) need review")
        if not incident_ready:
            weaknesses.append("no correlated incident is selected")
        if live_error:
            weaknesses.append("live ingest reported an error")
        weakness_rows = "".join(f"<li>{html.escape(item)}</li>" for item in weaknesses[:5]) or "<li>No immediate integration weakness detected.</li>"
        if hasattr(self.app, "hids_kpi_exports"):
            self.app.hids_kpi_exports.setText(str(len(exports)))
            self.app.hids_kpi_exports_sub.setText(f"{successes} ok / {failures} attention")
            self.app.hids_kpi_incidents.setText(str(len(incidents)))
            self.app.hids_kpi_incidents_sub.setText("OSSEC incident links")
            self.app.hids_kpi_live.setText(live_label.upper())
            self.app.hids_kpi_live_sub.setText(f"{imported_live} imported live")
            self.app.hids_kpi_dedupe.setText(str(dedupe_skips))
            self.app.hids_kpi_dedupe_sub.setText("duplicate alert skips")
        self.app.hids_summary.setHtml(
            "<h3 style='margin:0 0 7px;color:#f4f7fb;'>HIDS Triage & Coverage</h3>"
            "<table width='100%' cellspacing='0' cellpadding='6' style='border-collapse:separate;border-spacing:5px;font-size:12px;'>"
            f"<tr><td style='border:1px solid #243446;border-radius:8px;'><b>Source health</b><br>{'reachable' if source_exists else 'missing'}</td>"
            f"<td style='border:1px solid #243446;border-radius:8px;'><b>Latest export</b><br>{html.escape(latest_status)}</td></tr>"
            f"<tr><td style='border:1px solid #243446;border-radius:8px;'><b>Response ready</b><br>{'yes' if incident_ready else 'no incident'}</td>"
            f"<td style='border:1px solid #243446;border-radius:8px;'><b>Live ingest</b><br>{html.escape(live_label)} / {html.escape(imported_live)} imported</td></tr>"
            "</table>"
            f"<p style='color:#96a5b8;margin:7px 0 0;'><b>Current file:</b> {html.escape(current_file or 'not set')}<br>"
            f"<b>File size:</b> {source_size} bytes | <b>Modified:</b> {html.escape(source_mtime)}<br>"
            f"<b>Coverage:</b> {len(exports)} exports, {len(incidents)} OSSEC incidents, types: {top_types}<br>"
            f"<b>Last error:</b> {html.escape(live_error or 'none')}</p>"
            f"<h4 style='margin:8px 0 3px;color:#ffcf7a;'>Operational Gaps</h4><ul>{weakness_rows}</ul>"
        )
        live_color = "#2f9e67" if live_status.get("running") and not live_error else "#d64550" if live_error else "#4a5568"
        self.app.hids_health_badge.setText(f"HIDS: {live_label}")
        self.app.hids_health_badge.setStyleSheet(f"background:{live_color};color:white;padding:7px 12px;border-radius:8px;font-weight:800;")
        if exports:
            self.app.hids_detail.setPlainText(json.dumps(exports[0], indent=2, ensure_ascii=False))
        else:
            self.app.hids_detail.setPlainText(
                "No HIDS integration exports yet.\n\n"
                "Import an OSSEC alert file or start live ingest to populate normalized HIDS history."
            )

    def import_whids_file(self) -> None:
        path = self.app.whids_file_path.text().strip()
        if not path:
            self.app.statusBar().showMessage("Provide a WHIDS alert file path first")
            return
        try:
            result = self.app._post("/integrations/whids/import/file", json={"file_path": path, "limit": 500}, timeout=90).json()
        except Exception as exc:
            self.app._show_error(self.app.whids_detail, "WHIDS import failed", exc)
            return
        self.app._show_json(self.app.whids_detail, result)
        self.refresh_whids_workspace()
        self.app.refresh_hosts()
        self.app.refresh_history()
        self.app._switch_to_tab("WHIDS")

    def import_whids_manager(self) -> None:
        manager_url = self.app.whids_manager_url.text().strip()
        api_key = self.app.whids_manager_api_key.text().strip()
        endpoint_uuid = self.app.whids_endpoint_uuid.text().strip()
        if not manager_url or not api_key:
            self._show_whids_missing_input("Provide WHIDS manager URL and X-Api-Key first")
            return
        payload = {
            "manager_url": manager_url,
            "api_key": api_key,
            "limit": 500,
            "endpoint_uuid": endpoint_uuid,
            "verify_tls": self.app.whids_verify_tls.isChecked(),
        }
        try:
            result = self.app._post("/integrations/whids/import/manager", json=payload, timeout=120).json()
        except Exception as exc:
            self.app._show_error(self.app.whids_detail, "WHIDS manager import failed", exc)
            return
        self.app._show_json(self.app.whids_detail, result)
        self.refresh_whids_workspace()
        self.app.refresh_hosts()
        self.app.refresh_history()
        self.app._switch_to_tab("WHIDS")

    def import_whids_reports(self) -> None:
        manager_url = self.app.whids_manager_url.text().strip()
        api_key = self.app.whids_manager_api_key.text().strip()
        if not manager_url or not api_key:
            self._show_whids_missing_input("Provide WHIDS manager URL and X-Api-Key first")
            return
        payload = {
            "manager_url": manager_url,
            "api_key": api_key,
            "limit": 500,
            "endpoint_uuid": self.app.whids_endpoint_uuid.text().strip(),
            "verify_tls": self.app.whids_verify_tls.isChecked(),
        }
        try:
            result = self.app._post("/integrations/whids/reports", json=payload, timeout=120).json()
        except Exception as exc:
            self.app._show_error(self.app.whids_detail, "WHIDS report sync failed", exc)
            return
        self.app._show_json(self.app.whids_detail, result)
        self.refresh_whids_workspace()
        self.app.refresh_history()
        self.app.refresh_artifacts()
        self.app._switch_to_tab("WHIDS")

    def import_whids_artifacts(self) -> None:
        manager_url = self.app.whids_manager_url.text().strip()
        api_key = self.app.whids_manager_api_key.text().strip()
        endpoint_uuid = self.app.whids_endpoint_uuid.text().strip()
        if not manager_url or not api_key or not endpoint_uuid:
            self._show_whids_missing_input("Provide WHIDS manager URL, X-Api-Key and Endpoint UUID first")
            return
        payload = {
            "manager_url": manager_url,
            "api_key": api_key,
            "endpoint_uuid": endpoint_uuid,
            "since": self.app.whids_artifact_since.text().strip(),
            "max_files": self.app.whids_artifact_limit.value(),
            "verify_tls": self.app.whids_verify_tls.isChecked(),
        }
        try:
            result = self.app._post("/integrations/whids/artifacts", json=payload, timeout=180).json()
        except Exception as exc:
            self.app._show_error(self.app.whids_detail, "WHIDS artifact sync failed", exc)
            return
        self.app._show_json(self.app.whids_detail, result)
        self.refresh_whids_workspace()
        self.app.refresh_history()
        self.app.refresh_artifacts()
        self.app._switch_to_tab("WHIDS")

    def import_hids_file(self) -> None:
        path = self.app.hids_file_path.text().strip()
        if not path:
            self.app.statusBar().showMessage("Provide an OSSEC/HIDS alert file path first")
            return
        try:
            result = self.app._post("/integrations/ossec/import/file", json={"file_path": path, "limit": 500}, timeout=90).json()
        except Exception as exc:
            self.app._show_error(self.app.hids_detail, "HIDS import failed", exc)
            return
        self.app._show_json(self.app.hids_detail, result)
        self.refresh_hids_workspace()
        self.app.refresh_hosts()
        self.app.refresh_history()
        self.app._switch_to_tab("HIDS")

    def orchestrate_hids_response(self, apply_actions: bool) -> None:
        gate_key = "hids-orchestrate" if apply_actions else "hids-orchestrate-dry"
        if not self._check_action_gate(gate_key):
            return
        incident_id = self.app.hids_incident_id.text().strip()
        if not incident_id:
            # Do NOT infer the incident id from the detail panel. It is
            # not bound to the selected row — `show_selected_hids_export`
            # never writes an `incident_id`, so the panel only ever holds
            # an unrelated source (a prior refresh's exports[0] or an
            # earlier response result). Inferring it here would aim a
            # kill/quarantine at the wrong incident while the dialog
            # looks legitimate. Require an explicit target instead.
            incident_id, ok = QInputDialog.getText(self.app, "Incident Response", "Incident ID:")
            if not ok or not incident_id.strip():
                self.app.statusBar().showMessage("Provide an incident ID first")
                return
            incident_id = incident_id.strip()
        # Real response (apply_actions=True) triggers quarantine + kill
        # on the host — capture a structured reason so the audit chain
        # explains *why* automation was authorised. Dry-run is audited
        # too but doesn't need a ticket.
        reason: dict | None = None
        if apply_actions:
            confirm = QMessageBox(self.app)
            confirm.setWindowTitle("Confirm HIDS response orchestration")
            confirm.setText(f"Apply policy-driven response to incident `{incident_id}`?")
            confirm.setInformativeText(
                "This propagates kill/quarantine actions to the affected hosts. "
                "Use only when triage has confirmed the incident is real. "
                "Structured reason required."
            )
            confirm.setIcon(QMessageBox.Critical)
            confirm.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
            if confirm.exec() != QMessageBox.Ok:
                return
            reason = self._capture_reason("hids-orchestrate")
            if reason is None:
                return
        try:
            result = self.app._post(
                f"/integrations/incidents/{incident_id}/response",
                json={"apply_actions": apply_actions},
                timeout=120,
            ).json()
            ok_flag = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok_flag = False
            error = str(exc)
        self._record_audit(
            action=gate_key,
            target=f"incident={incident_id}",
            severity="critical" if apply_actions else "low",
            status="ok" if ok_flag else "failed",
            payload={"apply_actions": apply_actions, "response": result},
            reason=reason,
        )
        if not ok_flag:
            self.app._show_error(self.app.hids_detail, "HIDS response orchestration failed", Exception(error))
            return
        self.app.hids_incident_id.setText(incident_id)
        self.app._show_json(self.app.hids_detail, result)
        self.app.refresh_history()
        self.refresh_hids_workspace()
        self.app._switch_to_tab("HIDS")

    def whids_manager_payload_base(self) -> dict:
        return {
            "manager_url": self.app.whids_manager_url.text().strip(),
            "api_key": self.app.whids_manager_api_key.text().strip(),
            "verify_tls": self.app.whids_verify_tls.isChecked(),
        }

    def _show_whids_missing_input(self, message: str) -> None:
        self.app.statusBar().showMessage(message)
        if hasattr(self.app, "whids_detail"):
            self.app.whids_detail.setPlainText(
                f"{message}\n\n"
                "Required fields for manager-backed WHIDS actions:\n"
                "- WHIDS Manager URL\n"
                "- X-Api-Key\n"
                "- Endpoint UUID for artifact/config/archive actions\n\n"
                "Refresh WHIDS only reloads local cached history; it does not contact the manager."
            )

    def load_integration_policy(self) -> None:
        try:
            result = self.app._get("/integrations/response-policy", timeout=45).json()
        except Exception as exc:
            self.app._show_error(self.app.whids_detail, "Integration policy load failed", exc)
            return
        self.app.integration_policy_payload.setPlainText(json.dumps(result, indent=2, ensure_ascii=False))
        self.app._show_json(self.app.whids_detail, result)

    def save_integration_policy(self) -> None:
        if not self._check_action_gate("policy-save"):
            return
        # Integration response policy decides which alerts get
        # auto-quarantined / auto-killed across WHIDS+HIDS. Touching
        # this is a forensic event — the audit chain must capture
        # who shifted the policy and why.
        reason = self._capture_reason("policy-save")
        if reason is None:
            return
        try:
            policy = self.parse_json_text(self.app.integration_policy_payload, {})
            payload = {"policy": policy}
            result = self.app._post("/integrations/response-policy", json=payload, timeout=60).json()
            ok = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok = False
            error = str(exc)
            policy = {}
        provider_count = len((policy.get("providers") or {}).keys()) if isinstance(policy, dict) else 0
        action_count = len((policy.get("default_actions") or [])) if isinstance(policy, dict) else 0
        self._record_audit(
            action="policy-save",
            target=f"providers={provider_count} default_actions={action_count}",
            severity="medium",
            status="ok" if ok else "failed",
            payload={"summary": {"providers": provider_count, "default_actions": action_count}, "response": result},
            reason=reason,
        )
        if not ok:
            self.app._show_error(self.app.whids_detail, "Integration policy save failed", Exception(error))
            return
        self.app.integration_policy_payload.setPlainText(json.dumps(result, indent=2, ensure_ascii=False))
        self.app._show_json(self.app.whids_detail, result)

    def start_whids_scheduler(self) -> None:
        payload = self.whids_manager_payload_base()
        if not payload["manager_url"] or not payload["api_key"]:
            self._show_whids_missing_input("Provide WHIDS manager URL and X-Api-Key first")
            return
        payload["endpoint_uuid"] = self.app.whids_endpoint_uuid.text().strip()
        payload["poll_interval"] = self.app.whids_scheduler_interval.value()
        try:
            result = self.app._post("/integrations/whids/scheduler/start", json=payload, timeout=60).json()
        except Exception as exc:
            self.app._show_error(self.app.whids_detail, "WHIDS scheduler start failed", exc)
            return
        self.app._show_json(self.app.whids_detail, result)
        self.refresh_whids_workspace()

    def stop_whids_scheduler(self) -> None:
        try:
            result = self.app._post("/integrations/whids/scheduler/stop", timeout=45).json()
        except Exception as exc:
            self.app._show_error(self.app.whids_detail, "WHIDS scheduler stop failed", exc)
            return
        self.app._show_json(self.app.whids_detail, result)
        self.refresh_whids_workspace()

    def refresh_whids_scheduler_status(self) -> None:
        try:
            result = self.app._get("/integrations/whids/scheduler/status", timeout=45).json()
        except Exception as exc:
            self.app._show_error(self.app.whids_detail, "WHIDS scheduler status failed", exc)
            return
        self.app._show_json(self.app.whids_detail, result)
        self.refresh_whids_workspace()

    def parse_json_text(self, widget: QTextEdit, default):
        text = widget.toPlainText().strip()
        if not text:
            return default
        return json.loads(text)

    def query_whids_iocs(self) -> None:
        payload = self.whids_manager_payload_base()
        if not payload["manager_url"] or not payload["api_key"]:
            self._show_whids_missing_input("Provide WHIDS manager URL and X-Api-Key first")
            return
        filters = {}
        if self.app.whids_rule_name.text().strip():
            filters["value"] = self.app.whids_rule_name.text().strip()
        payload["filters"] = filters
        try:
            result = self.app._post("/integrations/whids/iocs/query", json=payload, timeout=90).json()
        except Exception as exc:
            self.app._show_error(self.app.whids_detail, "WHIDS IoC query failed", exc)
            return
        self.app._show_json(self.app.whids_detail, result)

    def add_whids_iocs(self) -> None:
        payload = self.whids_manager_payload_base()
        if not payload["manager_url"] or not payload["api_key"]:
            self._show_whids_missing_input("Provide WHIDS manager URL and X-Api-Key first")
            return
        try:
            payload["items"] = self.parse_json_text(self.app.whids_ioc_payload, [])
            result = self.app._post("/integrations/whids/iocs/add", json=payload, timeout=90).json()
        except Exception as exc:
            self.app._show_error(self.app.whids_detail, "WHIDS IoC add failed", exc)
            return
        self.app._show_json(self.app.whids_detail, result)
        self.refresh_whids_workspace()

    def delete_whids_iocs(self) -> None:
        payload = self.whids_manager_payload_base()
        if not payload["manager_url"] or not payload["api_key"]:
            self._show_whids_missing_input("Provide WHIDS manager URL and X-Api-Key first")
            return
        if not self._check_action_gate("ioc-delete"):
            return
        filters = {}
        if self.app.whids_rule_name.text().strip():
            filters["value"] = self.app.whids_rule_name.text().strip()
        payload["filters"] = filters
        # IOC deletion erases threat intel evidence. Without a filter
        # this would wipe the entire IOC store on the WHIDS manager —
        # demand confirmation + reason.
        scope = filters.get("value") or "ALL IoCs (no filter)"
        confirm = QMessageBox(self.app)
        confirm.setWindowTitle("Confirm WHIDS IoC delete")
        confirm.setText(f"Delete WHIDS IoCs matching: {scope}?")
        confirm.setInformativeText(
            "IOC deletion is propagated to the WHIDS manager and is not reversible. "
            "A structured reason is required for the audit chain."
        )
        confirm.setIcon(QMessageBox.Critical if not filters.get("value") else QMessageBox.Warning)
        confirm.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
        if confirm.exec() != QMessageBox.Ok:
            return
        reason = self._capture_reason("ioc-delete")
        if reason is None:
            return
        try:
            result = self.app._post("/integrations/whids/iocs/delete", json=payload, timeout=90).json()
            ok = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok = False
            error = str(exc)
        self._record_audit(
            action="ioc-delete",
            target=f"filter={scope}",
            severity="high",
            status="ok" if ok else "failed",
            payload={"filters": filters, "response": result},
            reason=reason,
        )
        if not ok:
            self.app._show_error(self.app.whids_detail, "WHIDS IoC delete failed", Exception(error))
            return
        self.app._show_json(self.app.whids_detail, result)
        self.refresh_whids_workspace()

    def query_whids_rules(self) -> None:
        payload = self.whids_manager_payload_base()
        if not payload["manager_url"] or not payload["api_key"]:
            self._show_whids_missing_input("Provide WHIDS manager URL and X-Api-Key first")
            return
        payload["name_filter"] = self.app.whids_rule_name.text().strip()
        try:
            result = self.app._post("/integrations/whids/rules/query", json=payload, timeout=90).json()
        except Exception as exc:
            self.app._show_error(self.app.whids_detail, "WHIDS rule query failed", exc)
            return
        self.app._show_json(self.app.whids_detail, result)

    def add_whids_rules(self) -> None:
        payload = self.whids_manager_payload_base()
        if not payload["manager_url"] or not payload["api_key"]:
            self._show_whids_missing_input("Provide WHIDS manager URL and X-Api-Key first")
            return
        try:
            payload["rules"] = self.parse_json_text(self.app.whids_rule_payload, [])
            result = self.app._post("/integrations/whids/rules/add", json=payload, timeout=90).json()
        except Exception as exc:
            self.app._show_error(self.app.whids_detail, "WHIDS rule add failed", exc)
            return
        self.app._show_json(self.app.whids_detail, result)
        self.refresh_whids_workspace()

    def delete_whids_rules(self) -> None:
        payload = self.whids_manager_payload_base()
        if not payload["manager_url"] or not payload["api_key"] or not self.app.whids_rule_name.text().strip():
            self._show_whids_missing_input("Provide WHIDS manager URL, X-Api-Key and rule name first")
            return
        if not self._check_action_gate("rule-delete"):
            return
        rule_name = self.app.whids_rule_name.text().strip()
        # Detection rule deletion immediately reduces coverage — the
        # operator must explain *why* a rule is being removed (false
        # positive? deprecated? attacker insider?).
        confirm = QMessageBox(self.app)
        confirm.setWindowTitle("Confirm WHIDS rule delete")
        # This field is a name / filter substring (see the input
        # placeholder), so the manager may match and remove MORE than one
        # rule. The confirmation must not imply a single exact rule.
        confirm.setText(f"Delete WHIDS rule(s) matching `{html.escape(rule_name)}`?")
        confirm.setInformativeText(
            "This is a name / filter substring — every rule on the WHIDS "
            "manager whose name matches it will be removed, not just one. "
            "Coverage drops until a replacement is deployed. Structured "
            "reason required."
        )
        confirm.setIcon(QMessageBox.Warning)
        confirm.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
        if confirm.exec() != QMessageBox.Ok:
            return
        reason = self._capture_reason("rule-delete")
        if reason is None:
            return
        payload["rule_name"] = rule_name
        try:
            result = self.app._post("/integrations/whids/rules/delete", json=payload, timeout=90).json()
            ok = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok = False
            error = str(exc)
        self._record_audit(
            action="rule-delete",
            target=f"rule={rule_name}",
            severity="high",
            status="ok" if ok else "failed",
            payload={"rule_name": rule_name, "response": result},
            reason=reason,
        )
        if not ok:
            self.app._show_error(self.app.whids_detail, "WHIDS rule delete failed", Exception(error))
            return
        self.app._show_json(self.app.whids_detail, result)
        self.refresh_whids_workspace()

    def start_hids_live_ingest(self) -> None:
        path = self.app.hids_file_path.text().strip()
        if not path:
            self.app.statusBar().showMessage("Provide an OSSEC/HIDS alert file path first")
            return
        payload = {
            "file_path": path,
            "poll_interval": self.app.hids_live_interval.value(),
            "limit": 500,
            "start_at_end": self.app.hids_live_start_at_end.isChecked(),
        }
        try:
            result = self.app._post("/integrations/ossec/live/start", json=payload, timeout=45).json()
        except Exception as exc:
            self.app._show_error(self.app.hids_detail, "HIDS live ingest start failed", exc)
            return
        self.app._show_json(self.app.hids_detail, result)
        self.refresh_hids_workspace()
        self.app.statusBar().showMessage("OSSEC live ingest started")
        self.app._switch_to_tab("HIDS")

    def stop_hids_live_ingest(self) -> None:
        try:
            result = self.app._post("/integrations/ossec/live/stop", timeout=45).json()
        except Exception as exc:
            self.app._show_error(self.app.hids_detail, "HIDS live ingest stop failed", exc)
            return
        self.app._show_json(self.app.hids_detail, result)
        self.refresh_hids_workspace()
        self.app.statusBar().showMessage("OSSEC live ingest stopped")
        self.app._switch_to_tab("HIDS")

    def refresh_hids_live_status(self) -> None:
        try:
            result = self.app._get("/integrations/ossec/live/status", timeout=20).json()
        except Exception as exc:
            self.app._show_error(self.app.hids_detail, "HIDS live status failed", exc)
            return
        self.app._show_json(self.app.hids_detail, result)
        self.refresh_hids_workspace()
        self.app._switch_to_tab("HIDS")

    def show_selected_whids_export(self) -> None:
        row = self.app.whids_table.currentRow()
        if row < 0:
            return
        values = {
            "created_at": self.app.whids_table.item(row, 0).text() if self.app.whids_table.item(row, 0) else "",
            "export_type": self.app.whids_table.item(row, 1).text() if self.app.whids_table.item(row, 1) else "",
            "target": self.app.whids_table.item(row, 2).text() if self.app.whids_table.item(row, 2) else "",
            "status": self.app.whids_table.item(row, 3).text() if self.app.whids_table.item(row, 3) else "",
            "detail": self.app.whids_table.item(row, 4).text() if self.app.whids_table.item(row, 4) else "",
        }
        self.app.whids_detail.setPlainText(json.dumps(values, indent=2, ensure_ascii=False))

    def show_selected_hids_export(self) -> None:
        row = self.app.hids_table.currentRow()
        if row < 0:
            return
        values = {
            "created_at": self.app.hids_table.item(row, 0).text() if self.app.hids_table.item(row, 0) else "",
            "export_type": self.app.hids_table.item(row, 1).text() if self.app.hids_table.item(row, 1) else "",
            "target": self.app.hids_table.item(row, 2).text() if self.app.hids_table.item(row, 2) else "",
            "status": self.app.hids_table.item(row, 3).text() if self.app.hids_table.item(row, 3) else "",
            "detail": self.app.hids_table.item(row, 4).text() if self.app.hids_table.item(row, 4) else "",
        }
        self.app.hids_detail.setPlainText(json.dumps(values, indent=2, ensure_ascii=False))

    def open_selected_whids_target(self) -> None:
        row = self.app.whids_table.currentRow()
        if row < 0:
            self.app.statusBar().showMessage("Select a WHIDS export first")
            return
        target = self.app.whids_table.item(row, 2).text() if self.app.whids_table.item(row, 2) else ""
        self.open_local_target(target)

    def open_selected_hids_target(self) -> None:
        row = self.app.hids_table.currentRow()
        if row < 0:
            self.app.statusBar().showMessage("Select a HIDS export first")
            return
        target = self.app.hids_table.item(row, 2).text() if self.app.hids_table.item(row, 2) else ""
        self.open_local_target(target)

    def open_local_target(self, target: str) -> None:
        candidate = str(target or "").strip()
        if not candidate:
            self.app.statusBar().showMessage("No local target is attached to this export")
            return
        # The target column is populated from WHIDS/HIDS server JSON; a
        # malicious manager (or MitM) could otherwise hand the operator
        # `\\evil-share\payload.lnk` or a path inside System32 and we'd
        # shell-launch it via the default file association.
        try:
            path = ensure_under_artifact_root(candidate, allow_shell_open=True)
        except UnsafeArtifactPath as exc:
            self.app.statusBar().showMessage(f"Open blocked: {exc}", 8000)
            return
        if path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
            return
        self.app.statusBar().showMessage(f"Target not found locally: {path}")

    def open_enterprise_case_for_incident(self, *, prefix: str = "") -> None:
        incident_id = self.app.hids_incident_id.text().strip()
        if prefix.upper().startswith("WHIDS"):
            current_detail = self.app.whids_detail.toPlainText().strip()
            incident_id = incident_id or self.find_incident_id_in_text(current_detail, "WHIDS-")
        else:
            current_detail = self.app.hids_detail.toPlainText().strip()
            incident_id = incident_id or self.find_incident_id_in_text(current_detail, "OSSEC-")
        if not incident_id:
            self.app.statusBar().showMessage("No correlated incident ID found for enterprise case jump")
            return
        try:
            cases = self.app._get("/enterprise/cases", timeout=20).json()
        except Exception as exc:
            self.app.statusBar().showMessage(f"Enterprise case lookup failed: {exc}")
            return
        if not isinstance(cases, list):
            # Backend may return an error envelope ({"error": ...}); the
            # loop below would otherwise enumerate dict keys and crash.
            self.app.statusBar().showMessage("Enterprise case lookup returned an unexpected response")
            return
        for idx, item in enumerate(cases):
            if isinstance(item, dict) and str(item.get("incident_id", "")).strip() == incident_id:
                self.app._switch_to_tab("Enterprise")
                self.app.refresh_enterprise_workspace()
                self.app.enterprise_cases_table.selectRow(idx)
                self.app.load_selected_case_board()
                return
        self.app.statusBar().showMessage(f"No enterprise case linked to {incident_id}")

    def find_incident_id_in_text(self, text: str, prefix: str) -> str:
        match = re.search(rf"{re.escape(prefix)}[A-Z0-9-]+", text.upper())
        return match.group(0) if match else ""
