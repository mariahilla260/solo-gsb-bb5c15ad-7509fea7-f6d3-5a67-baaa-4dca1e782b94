"""规则集快照迁移接口测试：导出、摘要核对、原子导入与版本去重。"""

import copy


def _create(client, payload, rid=None):
    body = dict(payload)
    if rid is not None:
        body["id"] = rid
    resp = client.post("/api/rulesets", json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_export_snapshot_structure(client, simple_ruleset_payload):
    created = _create(client, simple_ruleset_payload, rid="src-set")
    resp = client.get("/api/rulesets/src-set/versions/1/snapshot")
    assert resp.status_code == 200, resp.text
    pkg = resp.json()
    assert pkg["format"] == "ruleset-snapshot"
    assert pkg["format_version"] == "1.0"
    assert pkg["exported_at"]
    # 源规则集标识
    assert pkg["source"] == {
        "ruleset_id": "src-set",
        "version": 1,
        "version_id": created["id"],
        "created_at": created["created_at"],
    }
    # 完整规则定义（规则输入字段，不含派生的 referenced_rules）
    assert set(pkg["ruleset"]) == {
        "name", "description", "default_conflict_policy", "rules"
    }
    assert {r["code"] for r in pkg["ruleset"]["rules"]} == {"r1", "r2"}
    assert pkg["ruleset"]["rules"][0]["condition"] == 'doc["x"] >= 10'
    # 规范化内容摘要
    assert pkg["content"]["digest_algorithm"] == "sha256"
    assert len(pkg["content"]["digest"]) == 64
    assert pkg["content"]["digest"] != ""


def test_export_snapshot_404(client, simple_ruleset_payload):
    _create(client, simple_ruleset_payload, rid="src-set")
    assert client.get("/api/rulesets/no-such/versions/1/snapshot").status_code == 404
    resp = client.get("/api/rulesets/src-set/versions/9/snapshot")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "VERSION_NOT_FOUND"


def test_import_creates_v1_on_missing_target(client, simple_ruleset_payload):
    _create(client, simple_ruleset_payload, rid="src-set")
    pkg = client.get("/api/rulesets/src-set/versions/1/snapshot").json()

    resp = client.post("/api/rulesets/dst-set/snapshots/import", json=pkg)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ruleset_id"] == "dst-set"
    assert body["version"] == 1
    assert body["action"] == "created"
    # 快照完整可读，且派生字段（referenced_rules / evaluation_order）已重新编译
    snap = body["snapshot"]
    assert snap["ruleset_id"] == "dst-set"
    assert snap["version"] == 1
    assert snap["evaluation_order"] == ["r1", "r2"]
    assert snap["rules"][1]["referenced_rules"] == ["r1"]

    meta = client.get("/api/rulesets/dst-set").json()
    assert meta["current_version"] == 1
    # 导入后可正常求值
    result = client.post(
        "/api/rulesets/dst-set/evaluate", json={"document": {"x": 42}}
    ).json()
    assert result["decision"] == {"level": "high", "bonus": 1}


def _export(client, rid, payload):
    _create(client, payload, rid=rid)
    return client.get(f"/api/rulesets/{rid}/versions/1/snapshot").json()


def test_import_matches_existing_identical_version(client, simple_ruleset_payload):
    _create(client, simple_ruleset_payload, rid="dst-set")
    pkg = _export(client, "src-set", simple_ruleset_payload)

    # 重复导入同一内容：返回既有版本，不追加
    resp = client.post("/api/rulesets/dst-set/snapshots/import", json=pkg)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["action"] == "matched"
    assert body["version"] == 1

    versions = client.get("/api/rulesets/dst-set/versions").json()
    assert [v["version"] for v in versions] == [1]


def test_import_matches_any_version_not_just_latest(client, simple_ruleset_payload):
    rid = "dst-set"
    _create(client, simple_ruleset_payload, rid=rid)
    # 追加一个不同内容的 v2
    client.put(
        f"/api/rulesets/{rid}",
        json={
            "name": "simple",
            "rules": [{"code": "r1", "condition": 'doc["x"] >= 1000'}],
        },
    )
    # 导出“源”的 v1（与目标 v1 内容一致，但包内 source.version 无关紧要）
    _create(client, simple_ruleset_payload, rid="src-set")
    pkg = client.get("/api/rulesets/src-set/versions/1/snapshot").json()

    resp = client.post(f"/api/rulesets/{rid}/snapshots/import", json=pkg)
    assert resp.status_code == 200
    body = resp.json()
    assert body["action"] == "matched"
    assert body["version"] == 1  # 命中旧版本，current_version 不变
    assert client.get(f"/api/rulesets/{rid}").json()["current_version"] == 2
    assert [
        v["version"] for v in client.get(f"/api/rulesets/{rid}/versions").json()
    ] == [1, 2]


def test_import_appends_new_version_with_target_numbering(client, simple_ruleset_payload):
    rid = "dst-set"
    _create(client, simple_ruleset_payload, rid=rid)
    client.put(
        f"/api/rulesets/{rid}",
        json={
            "name": "simple",
            "rules": [{"code": "r1", "condition": 'doc["x"] >= 1000'}],
        },
    )
    # 源规则集只有 v1，包内 source.version=1；目标当前是 v2，新内容必须落 v3
    _create(
        client,
        {
            "name": "simple",
            "rules": [
                {"code": "r1", "condition": 'doc["x"] >= 5000'},
                {"code": "r9", "condition": "true", "action": '{"tag": 9}'},
            ],
        },
        rid="src-set",
    )
    pkg = client.get("/api/rulesets/src-set/versions/1/snapshot").json()

    resp = client.post(f"/api/rulesets/{rid}/snapshots/import", json=pkg)
    assert resp.status_code == 200
    body = resp.json()
    assert body["action"] == "appended"
    assert body["version"] == 3  # 按目标递增，不采用包内版本号
    assert body["snapshot"]["ruleset_id"] == rid
    assert client.get(f"/api/rulesets/{rid}").json()["current_version"] == 3
    assert [
        v["version"] for v in client.get(f"/api/rulesets/{rid}/versions").json()
    ] == [1, 2, 3]


def test_import_rejects_tampered_digest(client, simple_ruleset_payload):
    _create(client, simple_ruleset_payload, rid="src-set")
    pkg = client.get("/api/rulesets/src-set/versions/1/snapshot").json()
    # 篡改规则内容但不更新摘要
    pkg["ruleset"]["rules"][0]["condition"] = 'doc["x"] >= 999'

    resp = client.post("/api/rulesets/new-dst/snapshots/import", json=pkg)
    assert resp.status_code == 400
    error = resp.json()["error"]
    assert error["code"] == "SNAPSHOT_DIGEST_MISMATCH"
    assert error["details"]["expected"] != error["details"]["actual"]
    # 校验失败不写库：目标规则集不存在
    assert client.get("/api/rulesets/new-dst").status_code == 404


def test_import_rejects_recompile_failure_and_rolls_back(client, simple_ruleset_payload):
    _create(client, simple_ruleset_payload, rid="src-set")
    pkg = client.get("/api/rulesets/src-set/versions/1/snapshot").json()
    # 绕过摘要校验后注入编译不通过的内容：未知依赖
    pkg["ruleset"]["rules"].append(
        {"code": "rx", "condition": "ghost.hit", "depends_on": ["ghost"]}
    )
    pkg["content"]["digest"] = _digest_of(pkg["ruleset"])

    # 目标已存在且已有两个版本，追加失败后必须保持原样
    rid = "dst-set"
    _create(client, simple_ruleset_payload, rid=rid)
    resp = client.post(f"/api/rulesets/{rid}/snapshots/import", json=pkg)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "UNKNOWN_DEPENDENCY"
    meta = client.get(f"/api/rulesets/{rid}").json()
    assert meta["current_version"] == 1
    assert [
        v["version"] for v in client.get(f"/api/rulesets/{rid}/versions").json()
    ] == [1]


def test_import_digest_covers_normalized_defaults(client):
    # name 相同、缺省字段与显式等价字段，规范化摘要应一致 → matched
    src = {
        "name": "n",
        "rules": [
            {"code": "a", "condition": "true", "action": None},
        ],
    }
    _create(client, src, rid="src-set")
    pkg = client.get("/api/rulesets/src-set/versions/1/snapshot").json()

    _create(
        client,
        {
            "name": "n",
            "description": "",
            "default_conflict_policy": "collect_all",
            "rules": [
                {
                    "code": "a",
                    "name": "a",
                    "description": "",
                    "priority": 0,
                    "conflict_group": None,
                    "conflict_policy": None,
                    "depends_on": [],
                    "condition": "true",
                },
            ],
        },
        rid="dst-set",
    )
    resp = client.post("/api/rulesets/dst-set/snapshots/import", json=pkg)
    assert resp.status_code == 200
    assert resp.json()["action"] == "matched"


def test_import_invalid_target_id(client, simple_ruleset_payload):
    _create(client, simple_ruleset_payload, rid="src-set")
    pkg = client.get("/api/rulesets/src-set/versions/1/snapshot").json()
    resp = client.post("/api/rulesets/bad%20id/snapshots/import", json=pkg)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "INVALID_ID"
    assert client.get("/api/rulesets/bad id").status_code == 404


def test_import_cross_environment_round_trip(client, demo_id):
    # 把演示规则集导出，再迁移到一个全新 id：内容、求值结果应完全一致
    pkg = client.get(f"/api/rulesets/{demo_id}/versions/1/snapshot").json()
    doc = {"amount": 1500, "customer": {"vip": True}, "region": "north"}
    resp = client.post("/api/rulesets/migrated-demo/snapshots/import", json=pkg)
    assert resp.status_code == 200
    assert resp.json()["action"] == "created"

    original = client.post(
        f"/api/rulesets/{demo_id}/evaluate?persist=false", json={"document": doc}
    ).json()
    migrated = client.post(
        "/api/rulesets/migrated-demo/evaluate?persist=false", json={"document": doc}
    ).json()
    for field in (
        "fired_rule_codes",
        "hit_rule_codes",
        "evaluation_order",
        "decision",
        "conflicts",
        "iterations",
        "converged",
    ):
        assert migrated[field] == original[field]


def _digest_of(ruleset_body):
    from app.snapshot import content_digest

    return content_digest(copy.deepcopy(ruleset_body))
