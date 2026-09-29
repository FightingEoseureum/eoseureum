"""scan_context.py — 동시 요청 간 os.environ 오염을 막는 컨텍스트 스코프 오버레이.

문제: 리포트 템플릿 옵션·스캔별 인증정보처럼 "이 요청 동안만" 적용돼야 하는 설정을
os.environ 에 직접 썼다가 끝나면 복원하는 방식은, 같은 프로세스에서 동시에 실행 중인
다른 요청(다른 스캔/다른 내보내기)이 그 사이의 값을 그대로 보게 되는 레이스 컨디션을
만든다 — asyncio 이벤트 루프는 await 지점마다 다른 task 로 제어를 넘길 수 있으므로,
"저장→변경→복원" 사이에 다른 요청의 코드가 끼어들 수 있다.

해결: os.environ 을 실제로 건드리지 않고, contextvars 기반 오버레이를 그 위에 얹는다.
asyncio.create_task() 로 만든 하위 task 는 생성 시점의 컨텍스트를 그대로 복사해가므로,
같은 요청에서 파생된 모든 코루틴은 오버레이를 공유하지만 '다른' 요청(다른 task)에서
설정한 오버레이는 서로 보이지 않는다. os.environ 은 여전히 process-wide 진짜 값을
담은 채로 남아 있고(전역·영구 설정은 지금처럼 그대로 os.environ 에 쓰면 된다), 오버레이가
없는 코드 경로는 기존과 100% 동일하게 동작한다.

적용 범위: os.environ 객체 자체를 이 오버레이 매핑으로 교체하므로(install()), 기존에
이미 흩어져 있는 수많은 os.getenv()/os.environ.get() 호출부는 단 하나도 고칠 필요가
없다 — 전부 자동으로 스코프를 인식하게 된다. 단, `os.environ[key] = value` 형태의
'쓰기'는 현재 활성 스코프가 있으면 오버레이에만 쓰고 진짜 환경은 건드리지 않는다
(전역 설정 엔드포인트처럼 스코프 밖에서 쓰면 지금처럼 진짜 os.environ 에 그대로 쓰인다).
"""
from __future__ import annotations

import contextvars
import os
from collections.abc import MutableMapping

_overlay: contextvars.ContextVar[dict | None] = contextvars.ContextVar("scan_env_overlay", default=None)
_real_environ = os.environ  # install() 이전의 진짜 os.environ 을 보존(폴백 대상)


class _ScopedEnviron(MutableMapping):
    """os.environ 을 대체하는 매핑.
    읽기: 현재 task 의 오버레이 → 없으면 진짜 environ.
    쓰기: 오버레이가 활성화된 task 안이면 오버레이에만 쓰고, 없으면(서버 시작 시 설정,
         관리자 전역 설정 등) 지금까지처럼 진짜 environ 에 쓴다."""

    def __getitem__(self, key):
        ov = _overlay.get()
        if ov is not None and key in ov:
            return ov[key]
        return _real_environ[key]

    def __setitem__(self, key, value):
        ov = _overlay.get()
        if ov is not None:
            ov[key] = value
        else:
            _real_environ[key] = value

    def __delitem__(self, key):
        ov = _overlay.get()
        if ov is not None and key in ov:
            del ov[key]
        else:
            del _real_environ[key]

    def __iter__(self):
        ov = _overlay.get() or {}
        seen = set(ov)
        yield from ov
        for k in _real_environ:
            if k not in seen:
                yield k

    def __len__(self):
        ov = _overlay.get() or {}
        return len(set(_real_environ) | set(ov))

    def __contains__(self, key):
        ov = _overlay.get()
        if ov is not None and key in ov:
            return True
        return key in _real_environ

    def get(self, key, default=None):
        ov = _overlay.get()
        if ov is not None and key in ov:
            return ov[key]
        return _real_environ.get(key, default)

    def copy(self):
        return dict(self)


def install() -> None:
    """os.environ 을 스코프 오버레이로 교체한다. 프로세스 시작 시(main.py 최상단) 1회만 호출."""
    if isinstance(os.environ, _ScopedEnviron):
        return
    os.environ = _ScopedEnviron()


class scope:
    """with scope({...}): 블록(그리고 그 안에서 asyncio.create_task 로 파생되는 모든
    하위 task) 동안만 유효한 env 오버라이드. 진짜 os.environ 은 전혀 바뀌지 않으므로
    동시에 실행 중인 다른 요청에는 이 값이 절대 보이지 않는다.

    values 에 None 이 들어오면 해당 키는 오버라이드하지 않는다(부분 지정 허용).
    """
    def __init__(self, overrides: dict | None = None):
        self._overrides = {k: str(v) for k, v in (overrides or {}).items() if v is not None}
        self._token = None

    def __enter__(self):
        base = dict(_overlay.get() or {})
        base.update(self._overrides)
        self._token = _overlay.set(base)
        return self

    def __exit__(self, exc_type, exc, tb):
        _overlay.reset(self._token)
        return False

    def __bool__(self):
        """오버라이드가 실제로 적용됐는지(빈 dict 로 생성됐으면 False) 확인용."""
        return bool(self._overrides)
