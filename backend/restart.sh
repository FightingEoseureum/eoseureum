#!/bin/bash
# 어스름 백엔드 재시작 — .env 변경(EGRESS_ENABLED/HYBRID_ENABLED 등) 적용용.
# 사용: bash ~/Desktop/personal/backend/restart.sh
cd "$(dirname "$0")" || exit 1
echo "기존 백엔드 종료..."
kill $(pgrep -f 'uvicorn main:app') 2>/dev/null
sleep 2
echo "재시작..."
nohup .venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8000 > /tmp/eoseureum_uvicorn.log 2>&1 &
sleep 5
code=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/ 2>/dev/null)
echo "백엔드: HTTP $code (PID $(pgrep -f 'uvicorn main:app' | head -1))"
echo "현재 플래그:"
grep -E '^EGRESS_ENABLED|^HYBRID_ENABLED' .env | sed 's/^/  /'
