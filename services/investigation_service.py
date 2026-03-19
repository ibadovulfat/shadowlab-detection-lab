from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import database as db

from services.timeline_service import TimelineService


class InvestigationService:
    def __init__(self, timeline_service: TimelineService):
        self.timeline_service = timeline_service

    def workspace(
        self,
        *,
        query_text: str = "",
        event_types: list[str] | None = None,
        severities: list[str] | None = None,
        start_time: float | None = None,
        end_time: float | None = None,
        limit: int = 150,
        case_id: int | None = None,
    ) -> dict[str, Any]:
        conn = db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            items = self.timeline_service.build(
                telemetry_rows=db.get_historical_data(conn).to_dict(orient="records")[-300:],
                response_rows=db.get_response_logs(conn).to_dict(orient="records")[:300],
                incident_rows=db.get_incidents(conn).to_dict(orient="records")[:300],
                alert_rows=db.get_alerts(conn).to_dict(orient="records")[:300],
                remediation_rows=db.get_remediations(conn).to_dict(orient="records")[:300],
            )
            notes = db.get_investigation_notes(conn, case_id=case_id).fillna("").to_dict(orient="records")
            stories = db.get_investigation_stories(conn, case_id=case_id).fillna("").to_dict(orient="records")
            saved_views = db.get_investigation_views(conn, case_id=case_id).fillna("").to_dict(orient="records")
            pins = db.get_investigation_pins(conn, case_id=case_id).fillna("").to_dict(orient="records")
            cases = db.get_case_records(conn).fillna("").to_dict(orient="records")
            activity = db.get_case_activity(conn, case_id).fillna("").to_dict(orient="records") if case_id is not None else []
        finally:
            conn.close()

        filtered = self.timeline_service.filter_items(
            items,
            query_text=query_text,
            event_types=event_types or [],
            severities=severities or [],
            start_time=start_time,
            end_time=end_time,
            limit=limit,
        )
        return {
            "items": filtered,
            "summary": self._workspace_summary(filtered, notes, stories, pins),
            "filters": {
                "query_text": query_text,
                "event_types": event_types or [],
                "severities": severities or [],
                "start_time": start_time,
                "end_time": end_time,
                "limit": limit,
                "case_id": case_id,
            },
            "saved_views": [self._serialize_view(item) for item in saved_views[:10]],
            "recent_notes": [self._serialize_note(item) for item in notes[:10]],
            "active_stories": [self._serialize_story(item) for item in stories[:10]],
            "pinned_items": [self._serialize_pin(item) for item in pins[:10]],
            "case_board": self._build_case_board(case_id, filtered, notes, stories, pins, cases),
            "activity_feed": [self._serialize_activity(item) for item in activity[:20]],
        }

    def create_saved_view(
        self,
        *,
        name: str,
        description: str = "",
        query_text: str = "",
        event_types: list[str] | None = None,
        severities: list[str] | None = None,
        start_time: float | None = None,
        end_time: float | None = None,
        case_id: int | None = None,
        created_by: str = "",
    ) -> dict[str, Any]:
        filters = {
            "event_types": event_types or [],
            "severities": severities or [],
            "start_time": start_time,
            "end_time": end_time,
        }
        conn = db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            view_id = db.create_investigation_view(
                conn,
                name=name,
                description=description,
                query_text=query_text,
                filters_json=json.dumps(filters),
                case_id=case_id,
                created_by=created_by,
            )
            rows = db.get_investigation_views(conn, case_id=case_id).fillna("").to_dict(orient="records")
        finally:
            conn.close()
        return next((self._serialize_view(item) for item in rows if int(item.get("id", 0) or 0) == view_id), {"id": view_id})

    def list_saved_views(self, *, case_id: int | None = None) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if conn is None:
            return []
        try:
            rows = db.get_investigation_views(conn, case_id=case_id).fillna("").to_dict(orient="records")
        finally:
            conn.close()
        return [self._serialize_view(item) for item in rows]

    def create_note(
        self,
        *,
        note_text: str,
        case_id: int | None = None,
        view_id: int | None = None,
        item_time: float = 0,
        item_type: str = "",
        item_title: str = "",
        tags: list[str] | None = None,
        author: str = "",
    ) -> dict[str, Any]:
        conn = db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            note_id = db.create_investigation_note(
                conn,
                note_text=note_text,
                case_id=case_id,
                view_id=view_id,
                item_time=item_time,
                item_type=item_type,
                item_title=item_title,
                tags_json=json.dumps(tags or []),
                author=author,
            )
            rows = db.get_investigation_notes(conn, case_id=case_id, view_id=view_id).fillna("").to_dict(orient="records")
            if case_id is not None:
                db.log_case_activity(
                    conn,
                    case_id=case_id,
                    event_type="note_added",
                    actor=author,
                    summary=f"Investigation note added: {item_title or item_type or 'note'}",
                    detail_json=json.dumps({"tags": tags or [], "view_id": view_id}),
                )
        finally:
            conn.close()
        return next((self._serialize_note(item) for item in rows if int(item.get("id", 0) or 0) == note_id), {"id": note_id})

    def list_notes(self, *, case_id: int | None = None, view_id: int | None = None) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if conn is None:
            return []
        try:
            rows = db.get_investigation_notes(conn, case_id=case_id, view_id=view_id).fillna("").to_dict(orient="records")
        finally:
            conn.close()
        return [self._serialize_note(item) for item in rows]

    def create_story(
        self,
        *,
        title: str,
        hypothesis: str = "",
        summary: str = "",
        confidence: str = "medium",
        tags: list[str] | None = None,
        case_id: int | None = None,
        created_by: str = "",
    ) -> dict[str, Any]:
        conn = db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            story_id = db.create_investigation_story(
                conn,
                title=title,
                hypothesis=hypothesis,
                summary=summary,
                confidence=confidence,
                tags_json=json.dumps(tags or []),
                case_id=case_id,
                created_by=created_by,
            )
            rows = db.get_investigation_stories(conn, case_id=case_id).fillna("").to_dict(orient="records")
            if case_id is not None:
                db.log_case_activity(
                    conn,
                    case_id=case_id,
                    event_type="story_added",
                    actor=created_by,
                    summary=f"Investigation story added: {title}",
                    detail_json=json.dumps({"confidence": confidence, "tags": tags or []}),
                )
        finally:
            conn.close()
        return next((self._serialize_story(item) for item in rows if int(item.get("id", 0) or 0) == story_id), {"id": story_id})

    def list_stories(self, *, case_id: int | None = None) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if conn is None:
            return []
        try:
            rows = db.get_investigation_stories(conn, case_id=case_id).fillna("").to_dict(orient="records")
        finally:
            conn.close()
        return [self._serialize_story(item) for item in rows]

    def create_pin(
        self,
        *,
        case_id: int | None = None,
        view_id: int | None = None,
        item_time: float = 0,
        item_type: str = "",
        item_title: str = "",
        item_severity: str = "",
        item_payload: dict[str, Any] | None = None,
        rationale: str = "",
        pinned_by: str = "",
    ) -> dict[str, Any]:
        conn = db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            pin_id = db.create_investigation_pin(
                conn,
                case_id=case_id,
                view_id=view_id,
                item_time=item_time,
                item_type=item_type,
                item_title=item_title,
                item_severity=item_severity,
                item_payload_json=json.dumps(item_payload or {}),
                rationale=rationale,
                pinned_by=pinned_by,
            )
            rows = db.get_investigation_pins(conn, case_id=case_id, view_id=view_id).fillna("").to_dict(orient="records")
            if case_id is not None:
                db.log_case_activity(
                    conn,
                    case_id=case_id,
                    event_type="pin_added",
                    actor=pinned_by,
                    summary=f"Pinned {item_type}: {item_title}",
                    detail_json=json.dumps({"severity": item_severity, "view_id": view_id}),
                )
        finally:
            conn.close()
        return next((self._serialize_pin(item) for item in rows if int(item.get("id", 0) or 0) == pin_id), {"id": pin_id})

    def list_pins(self, *, case_id: int | None = None, view_id: int | None = None) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if conn is None:
            return []
        try:
            rows = db.get_investigation_pins(conn, case_id=case_id, view_id=view_id).fillna("").to_dict(orient="records")
        finally:
            conn.close()
        return [self._serialize_pin(item) for item in rows]

    def case_board(self, *, case_id: int) -> dict[str, Any]:
        workspace = self.workspace(case_id=case_id, limit=200)
        return workspace["case_board"]

    def assign_analyst(
        self,
        *,
        case_id: int,
        analyst: str,
        role: str = "owner",
        status: str = "active",
        assigned_by: str = "",
    ) -> dict[str, Any]:
        conn = db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            assignment_id = db.create_case_assignment(
                conn, case_id=case_id, analyst=analyst, role=role, status=status, assigned_by=assigned_by
            )
            db.log_case_activity(
                conn,
                case_id=case_id,
                event_type="analyst_assigned",
                actor=assigned_by,
                summary=f"Assigned {analyst} as {role}",
                detail_json=json.dumps({"status": status}),
            )
            rows = db.get_case_assignments(conn, case_id).fillna("").to_dict(orient="records")
        finally:
            conn.close()
        return next((item for item in rows if int(item.get("id", 0) or 0) == assignment_id), {"id": assignment_id})

    def list_assignments(self, *, case_id: int) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if conn is None:
            return []
        try:
            return db.get_case_assignments(conn, case_id).fillna("").to_dict(orient="records")
        finally:
            conn.close()

    def create_task(
        self,
        *,
        case_id: int,
        title: str,
        description: str = "",
        status: str = "todo",
        priority: str = "medium",
        assigned_to: str = "",
        due_at: float = 0,
        created_by: str = "",
    ) -> dict[str, Any]:
        conn = db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            task_id = db.create_case_task(
                conn,
                case_id=case_id,
                title=title,
                description=description,
                status=status,
                priority=priority,
                assigned_to=assigned_to,
                due_at=due_at,
                created_by=created_by,
            )
            db.log_case_activity(
                conn,
                case_id=case_id,
                event_type="task_created",
                actor=created_by,
                summary=f"Task created: {title}",
                detail_json=json.dumps({"assigned_to": assigned_to, "priority": priority, "due_at": due_at}),
            )
            rows = db.get_case_tasks(conn, case_id).fillna("").to_dict(orient="records")
        finally:
            conn.close()
        return next((item for item in rows if int(item.get("id", 0) or 0) == task_id), {"id": task_id})

    def list_tasks(self, *, case_id: int) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if conn is None:
            return []
        try:
            return db.get_case_tasks(conn, case_id).fillna("").to_dict(orient="records")
        finally:
            conn.close()

    def update_task(
        self,
        *,
        task_id: int,
        case_id: int,
        status: str | None = None,
        priority: str | None = None,
        assigned_to: str | None = None,
        due_at: float | None = None,
    ) -> dict[str, Any]:
        conn = db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            db.update_case_task(
                conn,
                task_id,
                status=status,
                priority=priority,
                assigned_to=assigned_to,
                due_at=due_at,
            )
            db.log_case_activity(
                conn,
                case_id=case_id,
                event_type="task_updated",
                actor=assigned_to or "",
                summary=f"Task {task_id} updated",
                detail_json=json.dumps({"status": status, "priority": priority, "assigned_to": assigned_to, "due_at": due_at}),
            )
            rows = db.get_case_tasks(conn, case_id).fillna("").to_dict(orient="records")
        finally:
            conn.close()
        return next((item for item in rows if int(item.get("id", 0) or 0) == task_id), {"id": task_id})

    def list_activity(self, *, case_id: int) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if conn is None:
            return []
        try:
            rows = db.get_case_activity(conn, case_id).fillna("").to_dict(orient="records")
        finally:
            conn.close()
        return [self._serialize_activity(item) for item in rows]

    def export_case_report(self, *, case_id: int, out_dir: str) -> dict[str, Any]:
        workspace = self.workspace(case_id=case_id, limit=200)
        board = workspace["case_board"]
        target_dir = Path(out_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        safe_case_id = f"case_{case_id}"
        json_path = target_dir / f"{safe_case_id}_investigation_report.json"
        html_path = target_dir / f"{safe_case_id}_investigation_report.html"
        pdf_path = target_dir / f"{safe_case_id}_executive_report.pdf"
        assignments = self.list_assignments(case_id=case_id)
        tasks = self.list_tasks(case_id=case_id)
        payload = {
            "case_board": board,
            "summary": workspace["summary"],
            "saved_views": workspace["saved_views"],
            "pinned_items": workspace["pinned_items"],
            "recent_notes": workspace["recent_notes"],
            "active_stories": workspace["active_stories"],
            "assignments": assignments,
            "tasks": tasks,
            "activity_feed": workspace.get("activity_feed", []),
        }
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        html_path.write_text(self._render_case_report_html(payload), encoding="utf-8")
        pdf_result = self._render_case_report_pdf(payload, pdf_path)
        return {
            "status": "exported",
            "json_path": str(json_path),
            "html_path": str(html_path),
            "pdf_path": str(pdf_result),
            "case_id": case_id,
        }

    def _serialize_view(self, item: dict[str, Any]) -> dict[str, Any]:
        filters = item.get("filters_json", "{}")
        if isinstance(filters, str):
            try:
                filters = json.loads(filters) if filters else {}
            except json.JSONDecodeError:
                filters = {}
        return {
            "id": item.get("id"),
            "name": item.get("name", ""),
            "description": item.get("description", ""),
            "query_text": item.get("query_text", ""),
            "filters": filters if isinstance(filters, dict) else {},
            "case_id": item.get("case_id") or None,
            "created_by": item.get("created_by", ""),
            "created_at": item.get("created_at", 0),
            "updated_at": item.get("updated_at", 0),
        }

    def _serialize_note(self, item: dict[str, Any]) -> dict[str, Any]:
        tags = item.get("tags_json", "[]")
        if isinstance(tags, str):
            try:
                tags = json.loads(tags) if tags else []
            except json.JSONDecodeError:
                tags = []
        return {
            "id": item.get("id"),
            "case_id": item.get("case_id") or None,
            "view_id": item.get("view_id") or None,
            "item_time": item.get("item_time", 0),
            "item_type": item.get("item_type", ""),
            "item_title": item.get("item_title", ""),
            "note_text": item.get("note_text", ""),
            "tags": tags if isinstance(tags, list) else [],
            "author": item.get("author", ""),
            "created_at": item.get("created_at", 0),
        }

    def _serialize_story(self, item: dict[str, Any]) -> dict[str, Any]:
        tags = item.get("tags_json", "[]")
        if isinstance(tags, str):
            try:
                tags = json.loads(tags) if tags else []
            except json.JSONDecodeError:
                tags = []
        return {
            "id": item.get("id"),
            "case_id": item.get("case_id") or None,
            "title": item.get("title", ""),
            "hypothesis": item.get("hypothesis", ""),
            "summary": item.get("summary", ""),
            "confidence": item.get("confidence", "medium"),
            "tags": tags if isinstance(tags, list) else [],
            "created_by": item.get("created_by", ""),
            "created_at": item.get("created_at", 0),
            "updated_at": item.get("updated_at", 0),
        }

    def _serialize_pin(self, item: dict[str, Any]) -> dict[str, Any]:
        payload = item.get("item_payload_json", "{}")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload) if payload else {}
            except json.JSONDecodeError:
                payload = {}
        return {
            "id": item.get("id"),
            "case_id": item.get("case_id") or None,
            "view_id": item.get("view_id") or None,
            "item_time": item.get("item_time", 0),
            "item_type": item.get("item_type", ""),
            "item_title": item.get("item_title", ""),
            "item_severity": item.get("item_severity", ""),
            "item_payload": payload if isinstance(payload, dict) else {},
            "rationale": item.get("rationale", ""),
            "pinned_by": item.get("pinned_by", ""),
            "created_at": item.get("created_at", 0),
        }

    def _serialize_activity(self, item: dict[str, Any]) -> dict[str, Any]:
        detail = item.get("detail_json", "{}")
        if isinstance(detail, str):
            try:
                detail = json.loads(detail) if detail else {}
            except json.JSONDecodeError:
                detail = {}
        return {
            "id": item.get("id"),
            "case_id": item.get("case_id") or None,
            "event_type": item.get("event_type", ""),
            "actor": item.get("actor", ""),
            "summary": item.get("summary", ""),
            "detail": detail if isinstance(detail, dict) else {},
            "created_at": item.get("created_at", 0),
        }

    def _workspace_summary(
        self,
        items: list[dict[str, Any]],
        notes: list[dict[str, Any]],
        stories: list[dict[str, Any]],
        pins: list[dict[str, Any]],
    ) -> dict[str, Any]:
        summary = self.timeline_service.build_summary(items)
        summary["note_count"] = len(notes)
        summary["story_count"] = len(stories)
        summary["pin_count"] = len(pins)
        summary["analyst_authors"] = sorted({str(note.get("author", "")).strip() for note in notes if str(note.get("author", "")).strip()})
        summary["confidence_levels"] = self._count_values(stories, "confidence")
        return summary

    def _count_values(self, rows: list[dict[str, Any]], key: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        for row in rows:
            value = str(row.get(key, "") or "").strip().lower()
            if not value:
                continue
            counts[value] = counts.get(value, 0) + 1
        return counts

    def _build_case_board(
        self,
        case_id: int | None,
        items: list[dict[str, Any]],
        notes: list[dict[str, Any]],
        stories: list[dict[str, Any]],
        pins: list[dict[str, Any]],
        cases: list[dict[str, Any]],
    ) -> dict[str, Any]:
        case_record = next((item for item in cases if case_id is not None and int(item.get("id", 0) or 0) == case_id), None)
        high_priority_items = [item for item in items if str(item.get("severity", "")).lower() in {"high", "critical"}][:8]
        assignments = self.list_assignments(case_id=case_id) if case_id is not None else []
        tasks = self.list_tasks(case_id=case_id) if case_id is not None else []
        activity = self.list_activity(case_id=case_id) if case_id is not None else []
        overdue_tasks = self._overdue_tasks(tasks)
        task_statuses = self._count_values(tasks, "status")
        task_priorities = self._count_values(tasks, "priority")
        timeline = self._case_timeline(items, notes, stories, pins, tasks, activity)
        entity_links = self._case_entity_links(case_record or {}, items, notes, stories, pins, tasks, activity)
        return {
            "case": case_record or {},
            "queue": {
                "pinned": len(pins),
                "stories": len(stories),
                "notes": len(notes),
                "high_priority_items": len(high_priority_items),
                "assignments": len(assignments),
                "open_tasks": len([task for task in tasks if str(task.get("status", "")).lower() not in {"done", "closed"}]),
                "overdue_tasks": len(overdue_tasks),
            },
            "kpis": {
                "event_total": len(items),
                "high_or_critical_events": len(high_priority_items),
                "note_coverage": len(notes),
                "story_coverage": len(stories),
                "pin_coverage": len(pins),
                "task_statuses": task_statuses,
                "task_priorities": task_priorities,
            },
            "assignments": assignments[:10],
            "tasks": tasks[:20],
            "activity": activity[:20],
            "overdue_tasks": overdue_tasks[:10],
            "focus_items": [
                {
                    "title": item.get("title", ""),
                    "type": item.get("type", ""),
                    "severity": item.get("severity", ""),
                    "time": item.get("time", 0),
                }
                for item in high_priority_items
            ],
            "timeline": timeline[:30],
            "entity_links": entity_links,
            "recommended_next_steps": self._recommended_next_steps(items, notes, stories, pins, overdue_tasks),
        }

    def _recommended_next_steps(
        self,
        items: list[dict[str, Any]],
        notes: list[dict[str, Any]],
        stories: list[dict[str, Any]],
        pins: list[dict[str, Any]],
        overdue_tasks: list[dict[str, Any]],
    ) -> list[str]:
        steps: list[str] = []
        if overdue_tasks:
            steps.append("Resolve overdue case tasks first so investigation momentum is not lost.")
        if not pins:
            steps.append("Pin the most decision-relevant telemetry, incident, or response artifacts.")
        if not stories:
            steps.append("Create an investigation story to capture the current hypothesis and analyst confidence.")
        if len(notes) < 2:
            steps.append("Add analyst notes that explain why the current evidence matters.")
        if any(str(item.get("severity", "")).lower() == "high" for item in items):
            steps.append("Review high severity events first and link them to a case narrative.")
        return steps[:5]

    def _overdue_tasks(self, tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
        now = self._now()
        overdue: list[dict[str, Any]] = []
        for task in tasks:
            status = str(task.get("status", "") or "").lower()
            due_at = float(task.get("due_at", 0) or 0)
            if due_at > 0 and due_at < now and status not in {"done", "closed"}:
                overdue.append(task)
        return overdue

    def _now(self) -> float:
        import time

        return time.time()

    def _render_case_report_html(self, payload: dict[str, Any]) -> str:
        board = payload.get("case_board", {}) if isinstance(payload, dict) else {}
        summary = payload.get("summary", {}) if isinstance(payload, dict) else {}
        pins = payload.get("pinned_items", []) if isinstance(payload, dict) else []
        notes = payload.get("recent_notes", []) if isinstance(payload, dict) else []
        stories = payload.get("active_stories", []) if isinstance(payload, dict) else []
        assignments = payload.get("assignments", []) if isinstance(payload, dict) else []
        tasks = payload.get("tasks", []) if isinstance(payload, dict) else []
        focus_items = board.get("focus_items", []) if isinstance(board, dict) else []
        next_steps = board.get("recommended_next_steps", []) if isinstance(board, dict) else []
        timeline = board.get("timeline", []) if isinstance(board, dict) else []
        entity_links = board.get("entity_links", {}) if isinstance(board, dict) else {}
        case_meta = board.get("case", {}) if isinstance(board, dict) else {}
        queue = board.get("queue", {}) if isinstance(board, dict) else {}
        executive_summary = self._executive_summary(board, summary, entity_links)
        timeline_html = "".join(
            f"<tr><td>{self._html_escape(str(item.get('time', '')))}</td><td>{self._html_escape(str(item.get('kind', '')))}</td><td>{self._html_escape(str(item.get('severity', '')))}</td><td>{self._html_escape(str(item.get('title', '')))}</td></tr>"
            for item in timeline[:12]
        ) or "<tr><td colspan='4'>No timeline events.</td></tr>"
        link_rows = "".join(
            f"<tr><td>{self._html_escape(str(item.get('entity', '')))}</td><td>{self._html_escape(str(item.get('kind', '')))}</td><td>{self._html_escape(str(item.get('evidence_count', 0)))}</td><td>{self._html_escape(str(item.get('examples', [])))}</td></tr>"
            for item in entity_links.get("items", [])[:10]
        ) or "<tr><td colspan='4'>No linked entities.</td></tr>"
        return (
            "<html><body style='font-family:Segoe UI,Arial,sans-serif;background:#0f1722;color:#eef4ff;padding:24px;'>"
            "<h1>ShadowLab Executive Investigation Report</h1>"
            f"<div style='background:#16202c;border:1px solid #2b425b;border-radius:12px;padding:16px;margin-bottom:16px;'><h2 style='margin:0 0 8px 0;'>Executive Summary</h2><p>{self._html_escape(executive_summary)}</p>"
            f"<p><b>Case:</b> {self._html_escape(str(case_meta.get('title', 'Unknown')))} | <b>Owner:</b> {self._html_escape(str(case_meta.get('owner', '')))} | <b>Priority:</b> {self._html_escape(str(case_meta.get('priority', '')))}</p>"
            f"<p><b>Total events:</b> {summary.get('total_events', 0)} | <b>Pins:</b> {summary.get('pin_count', 0)} | <b>Notes:</b> {summary.get('note_count', 0)} | <b>Stories:</b> {summary.get('story_count', 0)} | <b>Open tasks:</b> {queue.get('open_tasks', 0)}</p></div>"
            "<h2>Focus Items</h2><pre style='white-space:pre-wrap;background:#121b27;padding:12px;border-radius:10px;'>"
            + json.dumps(focus_items, indent=2)
            + "</pre><h2>Case Timeline</h2><table style='width:100%;border-collapse:collapse;background:#121b27;border-radius:10px;overflow:hidden;'><tr><th align='left'>Time</th><th align='left'>Kind</th><th align='left'>Severity</th><th align='left'>Title</th></tr>"
            + timeline_html
            + "</table><h2>Linked Entities</h2><table style='width:100%;border-collapse:collapse;background:#121b27;border-radius:10px;overflow:hidden;'><tr><th align='left'>Entity</th><th align='left'>Kind</th><th align='left'>Evidence</th><th align='left'>Examples</th></tr>"
            + link_rows
            + "</table><h2>Pinned Evidence</h2><pre style='white-space:pre-wrap;background:#121b27;padding:12px;border-radius:10px;'>"
            + json.dumps(pins, indent=2)
            + "</pre><h2>Analyst Notes</h2><pre style='white-space:pre-wrap;background:#121b27;padding:12px;border-radius:10px;'>"
            + json.dumps(notes, indent=2)
            + "</pre><h2>Stories</h2><pre style='white-space:pre-wrap;background:#121b27;padding:12px;border-radius:10px;'>"
            + json.dumps(stories, indent=2)
            + "</pre><h2>Assignments</h2><pre style='white-space:pre-wrap;background:#121b27;padding:12px;border-radius:10px;'>"
            + json.dumps(assignments, indent=2)
            + "</pre><h2>Tasks</h2><pre style='white-space:pre-wrap;background:#121b27;padding:12px;border-radius:10px;'>"
            + json.dumps(tasks, indent=2)
            + "</pre><h2>Next Steps</h2><pre style='white-space:pre-wrap;background:#121b27;padding:12px;border-radius:10px;'>"
            + json.dumps(next_steps, indent=2)
            + "</pre></body></html>"
        )

    def _render_case_report_pdf(self, payload: dict[str, Any], pdf_path: Path) -> Path:
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.units import mm
            from reportlab.pdfgen import canvas
        except Exception:
            pdf_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            return pdf_path

        board = payload.get("case_board", {}) if isinstance(payload, dict) else {}
        summary = payload.get("summary", {}) if isinstance(payload, dict) else {}
        assignments = payload.get("assignments", []) if isinstance(payload, dict) else []
        tasks = payload.get("tasks", []) if isinstance(payload, dict) else []
        stories = payload.get("active_stories", []) if isinstance(payload, dict) else []
        entity_links = board.get("entity_links", {}) if isinstance(board, dict) else {}
        timeline = board.get("timeline", []) if isinstance(board, dict) else []
        executive_summary = self._executive_summary(board, summary, entity_links)
        c = canvas.Canvas(str(pdf_path), pagesize=A4)
        width, height = A4
        y = height - 20 * mm
        c.setFont("Helvetica-Bold", 16)
        c.drawString(20 * mm, y, "ShadowLab Executive Case Report")
        y -= 8 * mm
        c.setFont("Helvetica", 10)
        case_meta = board.get("case", {}) if isinstance(board, dict) else {}
        lines = [
            f"Case: {case_meta.get('title', 'Unknown')}",
            f"Owner: {case_meta.get('owner', '')}",
            f"Priority: {case_meta.get('priority', '')}",
            f"Events: {summary.get('total_events', 0)} | Pins: {summary.get('pin_count', 0)} | Notes: {summary.get('note_count', 0)}",
            f"Stories: {summary.get('story_count', 0)} | Open tasks: {board.get('queue', {}).get('open_tasks', 0)}",
        ]
        for line in lines:
            c.drawString(20 * mm, y, line[:120])
            y -= 6 * mm
        c.setFont("Helvetica-Bold", 12)
        c.drawString(20 * mm, y, "Executive Summary")
        y -= 6 * mm
        c.setFont("Helvetica", 10)
        for chunk in self._wrap_text(executive_summary, 95)[:4]:
            c.drawString(24 * mm, y, chunk)
            y -= 5 * mm
        c.setFont("Helvetica-Bold", 12)
        c.drawString(20 * mm, y, "Key Hypotheses")
        y -= 6 * mm
        c.setFont("Helvetica", 10)
        for story in stories[:5]:
            c.drawString(24 * mm, y, f"- {str(story.get('title', ''))[:100]}")
            y -= 5 * mm
        c.setFont("Helvetica-Bold", 12)
        c.drawString(20 * mm, y, "Assignments")
        y -= 6 * mm
        c.setFont("Helvetica", 10)
        for assignment in assignments[:5]:
            c.drawString(24 * mm, y, f"- {assignment.get('analyst', '')} ({assignment.get('role', '')})")
            y -= 5 * mm
        c.setFont("Helvetica-Bold", 12)
        c.drawString(20 * mm, y, "Task Checklist")
        y -= 6 * mm
        c.setFont("Helvetica", 10)
        for task in tasks[:8]:
            c.drawString(24 * mm, y, f"- [{task.get('status', 'todo')}] {str(task.get('title', ''))[:90]}")
            y -= 5 * mm
            if y < 20 * mm:
                c.showPage()
                y = height - 20 * mm
        if timeline:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(20 * mm, y, "Timeline Highlights")
            y -= 6 * mm
            c.setFont("Helvetica", 10)
            for item in timeline[:6]:
                c.drawString(24 * mm, y, f"- {str(item.get('kind', 'event'))}: {str(item.get('title', ''))[:88]}")
                y -= 5 * mm
                if y < 20 * mm:
                    c.showPage()
                    y = height - 20 * mm
        if entity_links.get("items"):
            c.setFont("Helvetica-Bold", 12)
            c.drawString(20 * mm, y, "Linked Entities")
            y -= 6 * mm
            c.setFont("Helvetica", 10)
            for item in entity_links.get("items", [])[:6]:
                c.drawString(24 * mm, y, f"- {item.get('kind', 'entity')}: {str(item.get('entity', ''))[:80]}")
                y -= 5 * mm
                if y < 20 * mm:
                    c.showPage()
                    y = height - 20 * mm
        c.save()
        return pdf_path

    def _case_timeline(
        self,
        items: list[dict[str, Any]],
        notes: list[dict[str, Any]],
        stories: list[dict[str, Any]],
        pins: list[dict[str, Any]],
        tasks: list[dict[str, Any]],
        activity: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        timeline: list[dict[str, Any]] = []
        for item in items[:20]:
            timeline.append(
                {
                    "time": item.get("time", 0),
                    "kind": item.get("type", "event"),
                    "severity": item.get("severity", "info"),
                    "title": item.get("title", ""),
                }
            )
        for note in notes[:10]:
            timeline.append({"time": note.get("created_at", 0), "kind": "note", "severity": "info", "title": note.get("item_title") or note.get("note_text", "")[:96]})
        for story in stories[:10]:
            timeline.append({"time": story.get("updated_at") or story.get("created_at", 0), "kind": "story", "severity": story.get("confidence", "medium"), "title": story.get("title", "")})
        for pin in pins[:10]:
            timeline.append({"time": pin.get("created_at", 0), "kind": "pin", "severity": pin.get("item_severity", "medium"), "title": pin.get("item_title", "")})
        for task in tasks[:10]:
            timeline.append({"time": task.get("updated_at") or task.get("created_at", 0), "kind": "task", "severity": task.get("priority", "medium"), "title": task.get("title", "")})
        for entry in activity[:15]:
            timeline.append({"time": entry.get("created_at", 0), "kind": entry.get("event_type", "activity"), "severity": "info", "title": entry.get("summary", "")})
        timeline.sort(key=lambda item: self._time_sort_value(item.get("time", 0)), reverse=True)
        return timeline

    def _case_entity_links(
        self,
        case_record: dict[str, Any],
        items: list[dict[str, Any]],
        notes: list[dict[str, Any]],
        stories: list[dict[str, Any]],
        pins: list[dict[str, Any]],
        tasks: list[dict[str, Any]],
        activity: list[dict[str, Any]],
    ) -> dict[str, Any]:
        evidence_rows = [case_record] + items[:20] + notes[:20] + stories[:20] + pins[:20] + tasks[:20] + activity[:20]
        links: dict[tuple[str, str], set[str]] = {}
        for row in evidence_rows:
            text = self._evidence_text(row)
            for kind, pattern in [
                ("pid", r"\bpid(?:\s*[:#-]?\s*)(\d{1,6})\b"),
                ("incident", r"\bINC-[A-Z0-9-]+\b"),
                ("ip", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
                ("hash", r"\b[a-fA-F0-9]{32,64}\b"),
                ("process", r"\b[a-z0-9_.-]+\.exe\b"),
            ]:
                for match in re.findall(pattern, text, flags=re.IGNORECASE):
                    entity = match if isinstance(match, str) else "".join(match)
                    key = (kind, entity.lower())
                    links.setdefault(key, set()).add(text[:120])
        items_out = [
            {"kind": kind, "entity": entity, "evidence_count": len(examples), "examples": sorted(examples)[:2]}
            for (kind, entity), examples in links.items()
        ]
        items_out.sort(key=lambda item: (int(item.get("evidence_count", 0)), str(item.get("kind", ""))), reverse=True)
        return {
            "counts": self._count_values(items_out, "kind"),
            "items": items_out[:20],
        }

    def _evidence_text(self, value: Any) -> str:
        if isinstance(value, dict):
            return " ".join(self._evidence_text(item) for item in value.values())
        if isinstance(value, list):
            return " ".join(self._evidence_text(item) for item in value)
        return str(value or "")

    def _executive_summary(self, board: dict[str, Any], summary: dict[str, Any], entity_links: dict[str, Any]) -> str:
        case_meta = board.get("case", {}) if isinstance(board, dict) else {}
        queue = board.get("queue", {}) if isinstance(board, dict) else {}
        linked = entity_links.get("counts", {}) if isinstance(entity_links, dict) else {}
        top_entities = ", ".join(f"{kind}:{count}" for kind, count in list(linked.items())[:3]) or "no strong entity pivots yet"
        return (
            f"Case '{case_meta.get('title', 'Unknown')}' is currently in {case_meta.get('stage', 'triage')} with "
            f"{queue.get('open_tasks', 0)} open tasks, {queue.get('overdue_tasks', 0)} overdue items, "
            f"and {summary.get('high_or_critical_events', summary.get('by_severity', {}).get('high', 0))} notable high-risk events. "
            f"The strongest linked entities right now are {top_entities}. Recommended next steps remain focused on evidence review, task closure, and hypothesis refinement."
        )

    def _wrap_text(self, text: str, width: int) -> list[str]:
        words = str(text).split()
        lines: list[str] = []
        current = ""
        for word in words:
            candidate = f"{current} {word}".strip()
            if len(candidate) > width and current:
                lines.append(current)
                current = word
            else:
                current = candidate
        if current:
            lines.append(current)
        return lines

    def _time_sort_value(self, value: Any) -> float:
        try:
            return float(value or 0)
        except Exception:
            pass
        try:
            from datetime import datetime

            return datetime.fromisoformat(str(value)).timestamp()
        except Exception:
            return 0.0

    def _html_escape(self, text: str) -> str:
        import html

        return html.escape(text)
