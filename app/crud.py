"""持久化层：规则集、不可变版本快照、决策结果。"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any

from .engine import compile_ruleset
from .snapshot import canonical_content, content_digest

ID_PATTERN_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id() -> str:
    return uuid.uuid4().hex


def valid_custom_id(value: str) -> bool:
    return bool(value) and all(c in ID_PATTERN_CHARS for c in value)


class InvalidCustomId(ValueError):
    """自定义规则集 id 非法。"""


# ---------- 序列化 ----------


def ruleset_payload(payload_in: dict[str, Any]) -> dict[str, Any]:
    """规范化创建/更新请求体（与快照迁移共用同一规范化结构）。"""
    return canonical_content(payload_in)


def snapshot_from_compiled(compiled, version: int) -> dict[str, Any]:
    return {
        "version": version,
        "name": compiled.name,
        "description": compiled.description,
        "default_conflict_policy": compiled.default_conflict_policy,
        "evaluation_order": compiled.evaluation_order,
        "rules": [
            {
                "code": r.code,
                "name": r.name,
                "description": r.description,
                "priority": r.priority,
                "conflict_group": r.conflict_group,
                "conflict_policy": r.conflict_policy,
                "depends_on": list(r.depends_on),
                "condition": r.condition,
                "action": r.action or None,
                "referenced_rules": sorted(r.referenced_rules),
            }
            for r in sorted(compiled.rules, key=lambda x: x.order_index)
        ],
    }


# ---------- 规则集 ----------


def create_ruleset(conn: sqlite3.Connection, payload_in: dict[str, Any]) -> tuple[str, int, dict]:
    """编译 → 写规则集与 v1 快照。返回 (id, version, snapshot)。"""
    custom_id = payload_in.get("id")
    if isinstance(custom_id, str) and custom_id.strip() == "":
        raise InvalidCustomId("自定义 id 不能为空字符串")
    if custom_id is not None and not valid_custom_id(custom_id):
        raise InvalidCustomId("自定义 id 只能包含字母、数字、-、_")
    if custom_id is not None and get_ruleset(conn, custom_id) is not None:
        raise KeyError(f"规则集 id 已存在：{custom_id}")

    payload = ruleset_payload(payload_in)
    compiled = compile_ruleset(
        payload["name"],
        payload["description"],
        payload["default_conflict_policy"],
        payload["rules"],
    )

    ruleset_id = custom_id if custom_id is not None else new_id()

    ts = now()
    version = 1
    snapshot = snapshot_from_compiled(compiled, version)
    version_id = new_id()

    conn.execute(
        """INSERT INTO rulesets
           (id, name, description, default_conflict_policy,
            current_version, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            ruleset_id,
            compiled.name,
            compiled.description,
            compiled.default_conflict_policy,
            version,
            ts,
            ts,
        ),
    )
    conn.execute(
        """INSERT INTO ruleset_versions
           (id, ruleset_id, version, snapshot, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (version_id, ruleset_id, version, json.dumps(snapshot, ensure_ascii=False), ts),
    )
    return ruleset_id, version, snapshot


def update_ruleset(conn: sqlite3.Connection, ruleset_id: str, payload_in: dict[str, Any]) -> int:
    """修改规则集：编译新版本快照并更新 current_version。旧版本保留。"""
    existing = get_ruleset(conn, ruleset_id)
    if existing is None:
        raise LookupError(f"规则集不存在：{ruleset_id}")

    payload = ruleset_payload(payload_in)
    compiled = compile_ruleset(
        payload["name"],
        payload["description"],
        payload["default_conflict_policy"],
        payload["rules"],
    )

    new_version = existing["current_version"] + 1
    snapshot = snapshot_from_compiled(compiled, new_version)
    ts = now()
    conn.execute(
        """INSERT INTO ruleset_versions
           (id, ruleset_id, version, snapshot, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (new_id(), ruleset_id, new_version, json.dumps(snapshot, ensure_ascii=False), ts),
    )
    conn.execute(
        """UPDATE rulesets
           SET name=?, description=?, default_conflict_policy=?,
               current_version=?, updated_at=?
           WHERE id=?""",
        (
            compiled.name,
            compiled.description,
            compiled.default_conflict_policy,
            new_version,
            ts,
            ruleset_id,
        ),
    )
    return new_version


def get_ruleset(conn: sqlite3.Connection, ruleset_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM rulesets WHERE id = ?", (ruleset_id,)
    ).fetchone()


def list_rulesets(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return list(
        conn.execute("SELECT * FROM rulesets ORDER BY created_at, id").fetchall()
    )


def list_versions(conn: sqlite3.Connection, ruleset_id: str) -> list[sqlite3.Row]:
    return list(
        conn.execute(
            """SELECT id, ruleset_id, version, created_at
               FROM ruleset_versions
               WHERE ruleset_id = ?
               ORDER BY version""",
            (ruleset_id,),
        ).fetchall()
    )


def get_version(
    conn: sqlite3.Connection, ruleset_id: str, version: int
) -> dict[str, Any] | None:
    row = conn.execute(
        """SELECT id, ruleset_id, version, snapshot, created_at
           FROM ruleset_versions
           WHERE ruleset_id = ? AND version = ?""",
        (ruleset_id, version),
    ).fetchone()
    if row is None:
        return None
    snapshot = json.loads(row["snapshot"])
    return {
        "id": row["id"],
        "ruleset_id": row["ruleset_id"],
        "version": row["version"],
        "created_at": row["created_at"],
        **snapshot,
    }


def latest_version_number(conn: sqlite3.Connection, ruleset_id: str) -> int | None:
    row = conn.execute(
        "SELECT current_version FROM rulesets WHERE id = ?", (ruleset_id,)
    ).fetchone()
    return None if row is None else row["current_version"]


# ---------- 快照迁移 ----------


def import_snapshot(
    conn: sqlite3.Connection, target_id: str, content: dict[str, Any]
) -> tuple[str, int, str, dict[str, Any]]:
    """把快照内容导入目标规则集（与包内版本号无关）。

    调用方须已完成格式与摘要核对；本函数先重新编译，编译失败直接抛出
    （尚未执行任何写操作，配合 get_db 回滚实现原子化）。随后：

    - 目标 id 不存在：创建规则集并写入 v1；
    - 目标已存在且内容与其任一版本的规范化摘要一致：返回该版本，不写库；
    - 目标已存在但无相同内容：追加新版本，版本号按目标当前版本 +1。

    返回 ``(ruleset_id, version, action, snapshot)``，action 为
    ``created`` / ``matched`` / ``appended`` 之一。
    """
    if not valid_custom_id(target_id):
        raise InvalidCustomId("自定义 id 只能包含字母、数字、-、_")

    payload = ruleset_payload(content)
    # 写库前先重新编译：任何编译错误在此抛出，保证“校验失败不写库”
    compiled = compile_ruleset(
        payload["name"],
        payload["description"],
        payload["default_conflict_policy"],
        payload["rules"],
    )
    digest = content_digest(payload)

    existing = get_ruleset(conn, target_id)
    ts = now()

    if existing is None:
        version = 1
        snapshot = snapshot_from_compiled(compiled, version)
        conn.execute(
            """INSERT INTO rulesets
               (id, name, description, default_conflict_policy,
                current_version, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                target_id,
                compiled.name,
                compiled.description,
                compiled.default_conflict_policy,
                version,
                ts,
                ts,
            ),
        )
        conn.execute(
            """INSERT INTO ruleset_versions
               (id, ruleset_id, version, snapshot, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (new_id(), target_id, version, json.dumps(snapshot, ensure_ascii=False), ts),
        )
        return target_id, version, "created", snapshot

    # 目标已存在：按版本号顺序逐版比较规范化内容摘要
    for row in list_versions(conn, target_id):
        stored = get_version(conn, target_id, row["version"])
        if stored is not None and content_digest(stored) == digest:
            return target_id, stored["version"], "matched", stored

    # 无相同内容：版本号按目标规则集递增（忽略包内版本号）
    new_version = existing["current_version"] + 1
    snapshot = snapshot_from_compiled(compiled, new_version)
    conn.execute(
        """INSERT INTO ruleset_versions
           (id, ruleset_id, version, snapshot, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (new_id(), target_id, new_version, json.dumps(snapshot, ensure_ascii=False), ts),
    )
    conn.execute(
        """UPDATE rulesets
           SET name=?, description=?, default_conflict_policy=?,
               current_version=?, updated_at=?
           WHERE id=?""",
        (
            compiled.name,
            compiled.description,
            compiled.default_conflict_policy,
            new_version,
            ts,
            target_id,
        ),
    )
    return target_id, new_version, "appended", snapshot


# ---------- 决策结果 ----------


def save_evaluation(
    conn: sqlite3.Connection,
    ruleset_id: str,
    version: int,
    document: Any,
    result: dict[str, Any],
) -> dict[str, Any]:
    eval_id = new_id()
    ts = now()
    conn.execute(
        """INSERT INTO evaluations
           (id, ruleset_id, version, document, result,
            converged, iterations, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            eval_id,
            ruleset_id,
            version,
            json.dumps(document, ensure_ascii=False),
            json.dumps(result, ensure_ascii=False),
            1 if result.get("converged") else 0,
            result.get("iterations", 0),
            ts,
        ),
    )
    return _evaluation_record(eval_id, ruleset_id, version, document, result, ts)


def _evaluation_record(
    eval_id: str,
    ruleset_id: str,
    version: int,
    document: Any,
    result: dict[str, Any],
    created_at: str,
) -> dict[str, Any]:
    return {
        "id": eval_id,
        "ruleset_id": ruleset_id,
        "version": version,
        "document": document,
        "created_at": created_at,
        **{k: v for k, v in result.items()},
    }


def get_evaluation(conn: sqlite3.Connection, eval_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM evaluations WHERE id = ?", (eval_id,)
    ).fetchone()
    if row is None:
        return None
    return _row_to_evaluation(row)


def list_evaluations(
    conn: sqlite3.Connection, ruleset_id: str, limit: int = 100
) -> list[dict[str, Any]]:
    rows = conn.execute(
        """SELECT * FROM evaluations
           WHERE ruleset_id = ?
           ORDER BY created_at DESC, id DESC
           LIMIT ?""",
        (ruleset_id, limit),
    ).fetchall()
    return [_row_to_evaluation(r) for r in rows]


def latest_evaluation_document(
    conn: sqlite3.Connection, ruleset_id: str
) -> Any | None:
    row = conn.execute(
        """SELECT document FROM evaluations
           WHERE ruleset_id = ?
           ORDER BY created_at DESC, id DESC
           LIMIT 1""",
        (ruleset_id,),
    ).fetchone()
    return None if row is None else json.loads(row["document"])


def evaluation_stats(
    conn: sqlite3.Connection,
    ruleset_id: str,
    version: int | None = None,
    since: str | None = None,
    until: str | None = None,
) -> dict[str, Any]:
    """聚合已持久化决策：总数、规则命中（取自 traces）与决策字段出现次数。

    since/until 须为与 created_at 同格式的 UTC 秒级字符串（含边界，字典序
    即时间序）；结果按规则编码 / 字段名排序，无匹配记录时返回零值结构。
    """
    clauses = ["ruleset_id = ?"]
    params: list[Any] = [ruleset_id]
    if version is not None:
        clauses.append("version = ?")
        params.append(version)
    if since is not None:
        clauses.append("created_at >= ?")
        params.append(since)
    if until is not None:
        clauses.append("created_at <= ?")
        params.append(until)
    rows = conn.execute(
        f"SELECT result FROM evaluations WHERE {' AND '.join(clauses)}",
        params,
    ).fetchall()

    total = 0
    hit_counts: dict[str, int] = {}
    field_counts: dict[str, int] = {}
    for row in rows:
        result = json.loads(row["result"])
        total += 1
        for trace in result.get("traces") or []:
            code = trace.get("rule_code")
            if not code:
                continue
            hit_counts.setdefault(code, 0)
            if trace.get("hit"):
                hit_counts[code] += 1
        decision = result.get("decision")
        if isinstance(decision, dict):
            for field in decision:
                field_counts[field] = field_counts.get(field, 0) + 1

    return {
        "ruleset_id": ruleset_id,
        "version": version,
        "since": since,
        "until": until,
        "total_evaluations": total,
        "rule_stats": [
            {
                "code": code,
                "hit_count": count,
                "hit_rate": round(count / total, 4) if total else 0.0,
            }
            for code, count in sorted(hit_counts.items())
        ],
        "decision_field_counts": [
            {"field": field, "count": count}
            for field, count in sorted(field_counts.items())
        ],
    }


def _row_to_evaluation(row: sqlite3.Row) -> dict[str, Any]:
    result = json.loads(row["result"])
    document = json.loads(row["document"])
    return {
        "id": row["id"],
        "ruleset_id": row["ruleset_id"],
        "version": row["version"],
        "document": document,
        "created_at": row["created_at"],
        **result,
    }
