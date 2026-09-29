"""보호 슈퍼관리자(admin) 계정 — 본인만 수정/삭제 가능(다른 admin 차단) 회귀 테스트."""
import pytest
from fastapi import HTTPException

import main


def test_other_admin_cannot_modify_superadmin():
    with pytest.raises(HTTPException) as e:
        main._guard_protected_account({"username": "bob"}, {"username": "admin"})
    assert e.value.status_code == 403


def test_superadmin_can_modify_self():
    main._guard_protected_account({"username": "admin"}, {"username": "admin"})  # 예외 없음


def test_other_admin_can_modify_normal_user():
    main._guard_protected_account({"username": "bob"}, {"username": "alice"})  # 예외 없음


def test_guard_is_case_insensitive():
    with pytest.raises(HTTPException):
        main._guard_protected_account({"username": "BOB"}, {"username": "Admin"})
