"""Shared modal for capturing a structured response-action reason.

Used by Process Hunt and Antivirus consoles before executing destructive
actions (kill, kill-tree, suspend, quarantine, network isolate, VSS
restore). Replaces ad-hoc `QInputDialog.getText` flows that accepted
"asdfasdf" as a justification — every response action now writes a
ticket ID, a category from a fixed taxonomy, and a 12+ char narrative
to the audit log.
"""
from __future__ import annotations

import html

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


REASON_CATEGORIES: tuple[str, ...] = (
    "incident-confirmed",
    "ioc-match",
    "policy-violation",
    "manual-investigation",
    "training-exercise",
    "no-ticket",
)

NARRATIVE_MIN_LEN = 12
TICKET_MIN_LEN = 3


def prompt_response_reason(parent: QWidget, action: str) -> tuple[str, str, str] | None:
    """Show the modal; return (ticket_id, category, narrative) or None.

    `action` is shown in the title and narrative prompt so the operator
    has an unambiguous reminder of which action they're authorising.
    Validation rules:
      * Ticket ID >= TICKET_MIN_LEN, except when category is `no-ticket`
        in which case the field is forced to literal `NO-TICKET`
      * Category must come from REASON_CATEGORIES
      * Narrative >= NARRATIVE_MIN_LEN so the audit row is actionable
    """
    dialog = QDialog(parent)
    dialog.setWindowTitle(f"Response reason — {action}")
    dialog.setModal(True)
    layout = QVBoxLayout(dialog)
    layout.setContentsMargins(14, 14, 14, 12)
    layout.setSpacing(10)

    prompt = QLabel(
        f"<b>{html.escape(action)}</b> is a response action and is written to the immutable "
        "audit log. Provide a ticket reference, classify the reason, and add a short narrative "
        "for the SOC handover."
    )
    prompt.setWordWrap(True)
    prompt.setStyleSheet("color:#c8d8ea;font-size:12px;")
    layout.addWidget(prompt)

    form = QFormLayout()
    form.setSpacing(8)
    ticket_field = QLineEdit()
    ticket_field.setPlaceholderText("e.g. SOC-1234, INC-0042, or NO-TICKET")
    category_combo = QComboBox()
    category_combo.addItems(list(REASON_CATEGORIES))
    narrative_field = QTextEdit()
    narrative_field.setPlaceholderText(f"Why is this {action} appropriate now? ({NARRATIVE_MIN_LEN}+ chars)")
    narrative_field.setFixedHeight(96)
    form.addRow("Ticket ID", ticket_field)
    form.addRow("Reason category", category_combo)
    form.addRow("Narrative", narrative_field)
    layout.addLayout(form)

    error_label = QLabel("")
    error_label.setStyleSheet("color:#ff6b8a;font-size:11px;font-weight:700;")
    error_label.setWordWrap(True)
    layout.addWidget(error_label)

    buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
    layout.addWidget(buttons)

    result_holder: dict = {}

    def on_accept() -> None:
        ticket = ticket_field.text().strip()
        category = category_combo.currentText().strip().lower()
        narrative = narrative_field.toPlainText().strip()
        if category == "no-ticket":
            if ticket and ticket.upper() != "NO-TICKET":
                error_label.setText("Category 'no-ticket' requires the ticket field to be empty or 'NO-TICKET'.")
                return
            ticket = "NO-TICKET"
        else:
            if len(ticket) < TICKET_MIN_LEN:
                error_label.setText(f"Ticket ID must be at least {TICKET_MIN_LEN} characters (e.g. SOC-1234).")
                return
        if category not in REASON_CATEGORIES:
            error_label.setText("Pick a reason category from the dropdown.")
            return
        if len(narrative) < NARRATIVE_MIN_LEN:
            error_label.setText(f"Narrative must be at least {NARRATIVE_MIN_LEN} characters so the audit entry is actionable.")
            return
        result_holder["ticket"] = ticket
        result_holder["category"] = category
        result_holder["text"] = narrative
        dialog.accept()

    buttons.accepted.connect(on_accept)
    buttons.rejected.connect(dialog.reject)
    ticket_field.setFocus()

    if dialog.exec() != QDialog.Accepted:
        return None
    return result_holder["ticket"], result_holder["category"], result_holder["text"]
