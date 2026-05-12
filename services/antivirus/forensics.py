"""Forensic helpers — process tree, network state, registry context.

Currently exposes one MVP capability: build a process-tree snapshot
around an arbitrary PID. Real EDR consoles call this 'Storyline'
(SentinelOne) or 'Process Explorer' (CrowdStrike) — the analyst sees
where the suspicious binary was spawned from and what it spawned in
turn, in one glance.

The tree returned has the shape `{root: <pid_dict>, depth, total_nodes}`.
Each node is `{pid, name, exe, cmdline, create_time, username, status,
parent_pid, children: [<recursive>]}`. Depth is bounded so a forkbomb
or cycle can't blow up the response.
"""
from __future__ import annotations

from typing import Any


def get_process_tree(pid: int, *, max_depth: int = 6, include_parent_chain: bool = True) -> dict[str, Any]:
    try:
        pid = int(pid)
    except Exception:
        return {"ok": False, "reason": "invalid_pid"}
    try:
        import psutil
    except ImportError:
        return {"ok": False, "reason": "psutil_not_available"}
    try:
        target = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return {"ok": False, "reason": "no_such_process"}
    parent_chain: list[dict[str, Any]] = []
    if include_parent_chain:
        try:
            current = target
            for _ in range(max_depth):
                parent = current.parent()
                if parent is None:
                    break
                parent_chain.append(_describe(parent))
                current = parent
        except Exception:
            pass
    root = _describe(target)
    root["children"] = _children_recursive(target, depth=1, max_depth=max_depth)
    total = _count_nodes(root)
    return {
        "ok": True,
        "pid": pid,
        "tree_depth": _measure_depth(root),
        "total_nodes": total,
        "root": root,
        "parent_chain": parent_chain,
    }


def _describe(proc) -> dict[str, Any]:
    def _safe(callable_obj, default=None):
        try:
            return callable_obj()
        except Exception:
            return default
    return {
        "pid": getattr(proc, "pid", -1),
        "name": _safe(proc.name, ""),
        "exe": _safe(proc.exe, ""),
        "cmdline": _safe(proc.cmdline, []),
        "create_time": _safe(proc.create_time, 0.0),
        "username": _safe(proc.username, ""),
        "status": _safe(proc.status, ""),
        "parent_pid": (_safe(proc.parent, None).pid if _safe(proc.parent, None) else -1),
        "children": [],
    }


def _children_recursive(proc, *, depth: int, max_depth: int) -> list[dict[str, Any]]:
    if depth > max_depth:
        return []
    out: list[dict[str, Any]] = []
    try:
        children = list(proc.children(recursive=False))[:30]
    except Exception:
        return []
    for child in children:
        node = _describe(child)
        node["children"] = _children_recursive(child, depth=depth + 1, max_depth=max_depth)
        out.append(node)
    return out


def _count_nodes(node: dict[str, Any]) -> int:
    return 1 + sum(_count_nodes(c) for c in (node.get("children", []) or []))


def _measure_depth(node: dict[str, Any]) -> int:
    children = node.get("children", []) or []
    if not children:
        return 1
    return 1 + max(_measure_depth(c) for c in children)
