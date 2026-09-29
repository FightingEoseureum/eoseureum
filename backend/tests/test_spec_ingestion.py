"""① OpenAPI/Swagger 스펙 흡수 → 주입점 자동 생성 회귀."""
import json

import active_probing as ap


def test_openapi3_query_path_body_params():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "http://t:3000/api"}],
        "paths": {
            "/users/{id}": {
                "get": {"parameters": [
                    {"in": "path", "name": "id", "schema": {"type": "integer"}},
                    {"in": "query", "name": "fields", "schema": {"type": "string"}},
                ]},
                "put": {"requestBody": {"content": {"application/json": {"schema": {
                    "properties": {"name": {"type": "string"}, "role": {"type": "string"}}}}}}},
            },
            "/search": {"get": {"parameters": [{"in": "query", "name": "q", "schema": {"type": "string"}}]}},
        },
    }
    pts = ap.openapi_spec_to_injection_points(json.dumps(spec), "http://t:3000/api-docs/swagger.json")
    urls = {(p["method"], p["url"]) for p in pts}
    # GET /users/{id}?fields=... — path 채워짐(1), query 포함
    assert any(m == "GET" and "/api/users/1" in u and "fields=" in u for m, u in urls)
    # PUT /users/{id} — body 필드(name/role)가 params 로
    put = next(p for p in pts if p["method"] == "PUT")
    assert "name" in put["params"] and "role" in put["params"]
    # GET /search?q=
    assert any(m == "GET" and "/api/search?q=" in u for m, u in urls)
    # 모든 주입점 source 표기
    assert all(p["source"] == "openapi_spec" for p in pts)


def test_swagger2_basepath_and_body():
    spec = {
        "swagger": "2.0", "basePath": "/v1",
        "paths": {"/login": {"post": {"parameters": [
            {"in": "body", "name": "creds", "schema": {"properties": {
                "email": {"type": "string"}, "password": {"type": "string"}}}}]}}},
    }
    pts = ap.openapi_spec_to_injection_points(json.dumps(spec), "http://t/swagger.json")
    p = next(x for x in pts if x["method"] == "POST")
    assert "/v1/login" in p["url"]
    assert "email" in p["params"] and "password" in p["params"]


def test_invalid_spec_returns_empty():
    assert ap.openapi_spec_to_injection_points("not a spec", "http://t/x") == []
    assert ap.openapi_spec_to_injection_points(json.dumps({"paths": "bad"}), "http://t/x") == []


def test_cap_respected():
    paths = {f"/e{i}": {"get": {"parameters": [{"in": "query", "name": "a", "schema": {}}]}} for i in range(300)}
    pts = ap.openapi_spec_to_injection_points(json.dumps({"paths": paths}), "http://t/s.json", cap=50)
    assert len(pts) == 50
