# -*- coding: utf-8 -*-
"""api_audit(OpenAPI 심층 점검) 순수 로직 단위테스트."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api_audit as aa

# OpenAPI 3 스펙 샘플
SPEC3 = {
    "openapi": "3.0.0",
    "paths": {
        "/api/users/{id}": {
            "get": {"parameters": [{"name": "id", "in": "path", "required": True}]},
        },
        "/api/users": {
            "get": {"parameters": [{"name": "page", "in": "query"}]},
            "post": {"requestBody": {"content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/User"}}}}},
        },
        "/api/search": {
            "get": {"parameters": [{"name": "q", "in": "query", "required": True}]},
        },
    },
    "components": {"schemas": {"User": {"type": "object", "properties": {
        "username": {"type": "string"}, "role": {"type": "string"}, "is_admin": {"type": "boolean"}}}}},
}


def test_parse_operations():
    ops = aa.parse_openapi_operations(SPEC3, base_origin="http://x")
    by = {(o["method"], o["path"]) for o in ops}
    assert ("GET", "/api/users/{id}") in by
    assert ("POST", "/api/users") in by
    getid = next(o for o in ops if o["path"] == "/api/users/{id}")
    assert getid["path_params"] == ["id"]
    post = next(o for o in ops if o["method"] == "POST")
    assert "role" in post["body_props"] and "is_admin" in post["body_props"]


def test_resolvable_get_ops_excludes_required_query():
    ops = aa.parse_openapi_operations(SPEC3, base_origin="http://x")
    res = aa.resolvable_get_ops(ops)
    paths = {o["path"] for o in res}
    assert "/api/users/{id}" in paths       # 필수 쿼리 없음(경로만)
    assert "/api/users" in paths            # page 는 필수 아님
    assert "/api/search" not in paths       # q 필수 쿼리 → 제외


def test_fill_path_params():
    assert aa.fill_path_params("http://x/api/users/{id}", ["id"]) == "http://x/api/users/1"
    assert aa.fill_path_params("http://x/a/{uid}/b/{k}", ["uid", "k"]) == "http://x/a/1/b/1"


def test_find_sensitive_fields():
    data = {"username": "a", "password_hash": "x", "profile": {"ssn": "1", "role": "admin"}, "items": [{"token": "t"}]}
    f = aa.find_sensitive_fields(data)
    assert "password_hash" in f and "ssn" in f and "role" in f and "token" in f
    assert "username" not in f
    assert aa.find_sensitive_fields({"name": "ok", "email_verified_at": None}) == []


def test_mass_assignment_candidates():
    ops = aa.parse_openapi_operations(SPEC3, base_origin="http://x")
    mass = aa.mass_assignment_candidates(ops)
    assert len(mass) == 1
    assert mass[0]["method"] == "POST"
    assert set(mass[0]["fields"]) == {"role", "is_admin"}


def test_bola_candidates():
    ops = aa.parse_openapi_operations(SPEC3, base_origin="http://x")
    bola = aa.bola_candidates(ops)
    assert any(b["path"] == "/api/users/{id}" and "id" in b["object_params"] for b in bola)


def test_openapi2_body_param():
    spec2 = {"swagger": "2.0", "basePath": "/v1", "paths": {"/acct": {"post": {"parameters": [
        {"in": "body", "name": "b", "schema": {"properties": {"balance": {}, "name": {}}}}]}}}}
    ops = aa.parse_openapi_operations(spec2, base_origin="http://x")
    post = ops[0]
    assert post["path"] == "/v1/acct"
    assert "balance" in post["body_props"]
    assert aa.mass_assignment_candidates(ops)[0]["fields"] == ["balance"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
