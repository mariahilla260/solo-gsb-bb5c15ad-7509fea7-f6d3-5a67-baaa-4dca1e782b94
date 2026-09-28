"""规则集快照迁移包：规范化内容摘要、导出包构造与导入前校验。

摘要对规范化后的规则集内容（名称、描述、默认冲突策略、完整规则定义）
做规范化 JSON（键排序、紧凑分隔、UTF-8）后取 SHA-256。规则集标识、
版本号、时间戳等来源信息不参与摘要，因此同一份内容在任意目标规则集
上都得到相同摘要，可用于跨环境迁移时的完整性核对与版本去重。
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

SNAPSHOT_FORMAT = "ruleset-snapshot"
SNAPSHOT_FORMAT_VERSION = "1.0"
DIGEST_ALGORITHM = "sha256"

# 参与规范化摘要的规则字段（referenced_rules 等派生字段不含在内）
_RULE_FIELDS = (
    "code",
    "name",
    "description",
    "priority",
    "conflict_group",
    "conflict_policy",
    "depends_on",
    "condition",
    "action",
)


class SnapshotError(ValueError):
    """快照包校验失败。code 为机器可读错误码。"""

    def __init__(self, code: str, message: str, details: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


def canonical_content(data: dict[str, Any]) -> dict[str, Any]:
    """把规则集内容规范化为参与摘要/编译的稳定结构（与来源、版本无关）。

    接受创建/更新请求体、版本快照或导出包中的 ruleset 段落；只挑取
    内容字段并补默认值，保证同一内容无论从哪里来都得到同一结构。
    """
    return {
        "name": data["name"],
        "description": data.get("description") or "",
        "default_conflict_policy": data.get(
            "default_conflict_policy", "collect_all"
        ),
        "rules": [
            {
                "code": r["code"],
                "name": r.get("name") or r["code"],
                "description": r.get("description") or "",
                "priority": r.get("priority", 0),
                "conflict_group": r.get("conflict_group"),
                "conflict_policy": r.get("conflict_policy"),
                "depends_on": list(r.get("depends_on") or []),
                "condition": r.get("condition") or "",
                "action": r.get("action"),
            }
            for r in data["rules"]
        ],
    }


def canonical_json(data: dict[str, Any]) -> str:
    """规范化 JSON 序列化：键排序、无空白、UTF-8 原文（不转义非 ASCII）。"""
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def content_digest(data: dict[str, Any]) -> str:
    """规则集内容的 SHA-256 十六进制摘要（先规范化再序列化）。"""
    payload = canonical_json(canonical_content(data)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_package(snapshot: dict[str, Any], exported_at: str) -> dict[str, Any]:
    """从版本快照构造导出包：源标识 + 完整规则定义 + 规范化内容摘要。"""
    content = canonical_content(snapshot)
    return {
        "format": SNAPSHOT_FORMAT,
        "format_version": SNAPSHOT_FORMAT_VERSION,
        "exported_at": exported_at,
        "source": {
            "ruleset_id": snapshot["ruleset_id"],
            "version": snapshot["version"],
            "version_id": snapshot["id"],
            "created_at": snapshot["created_at"],
        },
        "ruleset": content,
        "content": {
            "digest_algorithm": DIGEST_ALGORITHM,
            "digest": content_digest(content),
        },
    }


def verify_package(package: dict[str, Any]) -> dict[str, Any]:
    """导入前核对格式与内容摘要，返回规范化后的规则集内容。

    任何失败都在写库之前抛出 :class:`SnapshotError`（HTTP 层映射为 400）。
    """
    if package.get("format") != SNAPSHOT_FORMAT:
        raise SnapshotError(
            "UNSUPPORTED_SNAPSHOT_FORMAT",
            f"不支持的快照格式：{package.get('format')!r}",
            {"expected_format": SNAPSHOT_FORMAT},
        )
    if package.get("format_version") != SNAPSHOT_FORMAT_VERSION:
        raise SnapshotError(
            "UNSUPPORTED_SNAPSHOT_FORMAT",
            f"不支持的快照格式版本：{package.get('format_version')!r}",
            {"expected_format_version": SNAPSHOT_FORMAT_VERSION},
        )

    body = package.get("ruleset")
    if not isinstance(body, dict):
        raise SnapshotError(
            "INVALID_SNAPSHOT", "快照缺少 ruleset 内容段", {}
        )

    checksum = package.get("content")
    if not isinstance(checksum, dict):
        raise SnapshotError("INVALID_SNAPSHOT", "快照缺少 content 摘要段", {})
    if checksum.get("digest_algorithm") != DIGEST_ALGORITHM:
        raise SnapshotError(
            "UNSUPPORTED_DIGEST_ALGORITHM",
            f"不支持的摘要算法：{checksum.get('digest_algorithm')!r}",
            {"expected_algorithm": DIGEST_ALGORITHM},
        )

    content = canonical_content(body)
    expected = checksum.get("digest")
    actual = content_digest(content)
    if not isinstance(expected, str) or not expected or actual != expected:
        raise SnapshotError(
            "SNAPSHOT_DIGEST_MISMATCH",
            "快照内容摘要核对失败：包已损坏或被篡改，拒绝导入",
            {"expected": expected, "actual": actual},
        )
    return content
