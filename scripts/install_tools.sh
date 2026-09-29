#!/usr/bin/env bash
#
# install_tools.sh — GVD 백엔드 외부 보안 도구 설치 스크립트 (Ubuntu 기준)
#
# 대상 도구:
#   - ghauri  : SQL 인젝션 심화 점검 (이 스크립트가 직접 설치)
#   - nuclei / katana / ffuf : Go 기반 도구 (설치 안내 주석 참고, 이미 있으면 건너뜀)
#
# 설계 원칙:
#   set -e 를 쓰지 않는다. 한 도구 설치가 실패해도 전체가 죽지 않도록
#   단계별 echo + `... || true` 로 방어적으로 처리한다.
#   (pip 설치가 막힌 환경을 대비해 ghauri 는 GitHub clone 방식을 기본으로 한다.)
#
# 사용:
#   bash scripts/install_tools.sh
#   (또는 chmod +x 후) ./scripts/install_tools.sh
#
# 환경변수(선택):
#   VENV_DIR   : 활성화할 파이썬 venv 경로 (기본: backend/venv_linux)
#   TOOLS_DIR  : 소스 clone 디렉터리        (기본: $HOME/.local/src)

# 일부러 set -e 를 쓰지 않는다. (방어적 진행)
set -u 2>/dev/null || true

# ── 경로 설정 ─────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
BACKEND_DIR="$(cd "${SCRIPT_DIR}/../backend" 2>/dev/null && pwd)"
VENV_DIR="${VENV_DIR:-${BACKEND_DIR}/venv_linux}"
TOOLS_DIR="${TOOLS_DIR:-${HOME}/.local/src}"

echo "=================================================="
echo " GVD 외부 도구 설치 스크립트"
echo "   BACKEND_DIR = ${BACKEND_DIR}"
echo "   VENV_DIR    = ${VENV_DIR}"
echo "   TOOLS_DIR   = ${TOOLS_DIR}"
echo "=================================================="

# ── 0. venv 활성화 + pip 업그레이드 ───────────────────────────────────────────
echo
echo "[0] venv 활성화 및 pip 업그레이드"
if [ -f "${VENV_DIR}/bin/activate" ]; then
    # shellcheck disable=SC1091
    . "${VENV_DIR}/bin/activate" || echo "  ! venv 활성화 실패 (계속 진행)"
    echo "  - venv 활성화: ${VIRTUAL_ENV:-(미설정)}"
else
    echo "  ! venv 를 찾을 수 없음(${VENV_DIR}) — 시스템 python 으로 진행"
fi

PY="$(command -v python3 || command -v python || echo python3)"
echo "  - python: ${PY}"
"${PY}" -m pip install --upgrade pip >/dev/null 2>&1 \
    && echo "  - pip 업그레이드 완료" \
    || echo "  ! pip 업그레이드 실패 (계속 진행)"

mkdir -p "${TOOLS_DIR}" 2>/dev/null || true

# ── 1. ghauri 설치 (GitHub clone 방식) ────────────────────────────────────────
echo
echo "[1] ghauri 설치 (SQL 인젝션 심화 점검)"

if command -v ghauri >/dev/null 2>&1; then
    echo "  - ghauri 이미 설치됨: $(command -v ghauri) — 건너뜀"
else
    # 1-1) 우선 pip 로 시도 (가장 간단). 실패하면 clone 으로 폴백.
    echo "  - (a) pip install ghauri 시도..."
    "${PY}" -m pip install ghauri >/dev/null 2>&1 \
        && echo "    -> pip 설치 성공" \
        || echo "    ! pip 설치 실패 — GitHub clone 방식으로 폴백"

    if ! command -v ghauri >/dev/null 2>&1; then
        GHAURI_SRC="${TOOLS_DIR}/ghauri"
        echo "  - (b) GitHub clone 방식 설치 (${GHAURI_SRC})"

        if [ -d "${GHAURI_SRC}/.git" ]; then
            echo "    - 기존 clone 발견 — git pull 로 갱신"
            git -C "${GHAURI_SRC}" pull --ff-only >/dev/null 2>&1 || echo "    ! git pull 실패 (계속 진행)"
        else
            rm -rf "${GHAURI_SRC}" 2>/dev/null || true
            git clone --depth 1 https://github.com/r0oth3x49/ghauri.git "${GHAURI_SRC}" \
                && echo "    - clone 완료" \
                || echo "    ! git clone 실패 (네트워크/권한 확인 필요)"
        fi

        if [ -d "${GHAURI_SRC}" ]; then
            # setup.py install → 실패 시 pip install . 폴백
            ( cd "${GHAURI_SRC}" \
                && ( "${PY}" -m pip install . >/dev/null 2>&1 \
                     || "${PY}" setup.py install >/dev/null 2>&1 ) ) \
                && echo "    - 빌드/설치 완료" \
                || echo "    ! pip install . / setup.py 모두 실패 (계속 진행)"
        fi
    fi

    # 1-1) 서버 프로세스가 PATH 로 찾을 수 있도록 /usr/local/bin 에 심볼릭 링크
    #      (백엔드는 venv 를 activate 하지 않고 venv/bin/python 으로 직접 실행되므로
    #       venv/bin 이 PATH 에 없을 수 있어 shutil.which('ghauri') 가 실패할 수 있다.)
    GHAURI_BIN="${VENV_DIR}/bin/ghauri"
    if [ -x "${GHAURI_BIN}" ] && [ ! -e /usr/local/bin/ghauri ]; then
        ln -sf "${GHAURI_BIN}" /usr/local/bin/ghauri 2>/dev/null \
            && echo "  - /usr/local/bin/ghauri 심볼릭 링크 생성" \
            || echo "  ! 심볼릭 링크 생성 실패 (sudo 필요할 수 있음) — PATH 에 ${VENV_DIR}/bin 추가 권장"
    fi

    # 1-2) 설치 검증
    echo "  - ghauri 설치 검증"
    if ghauri --version >/dev/null 2>&1; then
        echo "    -> ghauri OK: $(ghauri --version 2>&1 | head -1)"
    elif "${PY}" -m ghauri --version >/dev/null 2>&1; then
        echo "    -> python -m ghauri OK: $("${PY}" -m ghauri --version 2>&1 | head -1)"
    else
        echo "    ! ghauri 설치 확인 실패 — 백엔드는 'SQLi 심화 점검 불가(ghauri 미설치)'로 동작하며"
        echo "      나머지 스캔은 정상 진행됩니다. 수동 설치: ${TOOLS_DIR}/ghauri 참고"
    fi
fi

# ── 2. nuclei / katana / ffuf 설치 안내 (Go 기반) ─────────────────────────────
echo
echo "[2] nuclei / katana / ffuf (Go 기반 — 안내)"
#
# 이 세 도구는 Go 툴체인으로 설치하는 것이 가장 안정적입니다.
# 이미 설치되어 있으면 자동으로 건너뜁니다. (아래는 참고용 설치 명령)
#
#   # Go 설치(미설치 시):
#   sudo apt-get update && sudo apt-get install -y golang-go
#
#   # nuclei (CVE/설정오류 템플릿 스캐너):
#   go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
#   nuclei -update-templates
#
#   # katana (웹 크롤러):
#   go install -v github.com/projectdiscovery/katana/cmd/katana@latest
#
#   # ffuf (디렉터리 퍼저):
#   go install -v github.com/ffuf/ffuf/v2@latest
#
#   # 설치 후 PATH 에 $HOME/go/bin 을 추가해야 합니다:
#   #   export PATH="$PATH:$HOME/go/bin"
#
for tool in nuclei katana ffuf; do
    if command -v "${tool}" >/dev/null 2>&1; then
        echo "  - ${tool} 이미 설치됨: $(command -v "${tool}") — 건너뜀"
    else
        echo "  ! ${tool} 미설치 — 위 주석의 'go install' 명령 참고 (없어도 스캔은 계속 진행됨)"
    fi
done

# ── 3. 최종 상태 요약 ─────────────────────────────────────────────────────────
echo
echo "=================================================="
echo " 설치 상태 요약"
for tool in ghauri nuclei katana ffuf; do
    if command -v "${tool}" >/dev/null 2>&1; then
        echo "   [O] ${tool}"
    else
        echo "   [X] ${tool} (미설치 — 해당 단계는 건너뜀)"
    fi
done
echo "=================================================="
echo "완료. (일부 도구가 미설치여도 백엔드 스캔은 정상 동작합니다.)"
exit 0
