#!/bin/bash
# 어스름 서버 시작 — Finder 에서 더블클릭하면 백엔드가 켜집니다.
cd "$(dirname "$0")" || { echo "backend 폴더를 찾을 수 없습니다."; read -n 1 -s; exit 1; }

# 이미 켜져 있으면 종료 후 새로 시작(중복 방지)
pkill -f 'uvicorn main:app' 2>/dev/null
sleep 2

# 백그라운드로 시작(이 창을 닫아도 서버는 계속 실행됩니다)
nohup .venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8000 > /tmp/eoseureum_uvicorn.log 2>&1 &

# 기동 대기
code="000"
for i in 1 2 3 4 5 6 7 8; do
  sleep 2
  code=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/ 2>/dev/null)
  [ "$code" = "200" ] && break
done

clear
echo "======================================================"
echo "        어스름(Eoseureum) 서버 시작"
echo "======================================================"
if [ "$code" = "200" ]; then
  echo "  상태: ✅ 실행 중 (HTTP 200)"
else
  echo "  상태: ⚠️ 기동 확인 실패 (HTTP $code) — 로그: /tmp/eoseureum_uvicorn.log"
fi
echo "  프로세스 PID: $(pgrep -f 'uvicorn main:app' | head -1)"
echo "------------------------------------------------------"
echo "  접속 주소 — i7 단일관문 (i7 IP로만):"
echo "    케이블 : http://localhost:8000"
echo "    와이파이: http://localhost:8000"
echo "    (이 맥 로컬) http://localhost:8000  ※맥IP 직접접속은 403 차단"
echo "------------------------------------------------------"
echo "  현재 설정:"
grep -E '^EGRESS_ENABLED|^HYBRID_ENABLED' .env | sed 's/^/    /'
echo "------------------------------------------------------"
echo "  ※ 이 창은 닫으셔도 서버는 계속 실행됩니다."
echo "     서버를 끄려면 '어스름_서버_종료.command' 를 더블클릭하세요."
echo "======================================================"
echo ""
read -n 1 -s -r -p "아무 키나 누르면 이 창이 닫힙니다..."
echo ""
