#!/bin/bash
# 어스름 서버 종료 — Finder 에서 더블클릭하면 백엔드가 꺼집니다.
clear
echo "======================================================"
echo "        어스름(Eoseureum) 서버 종료"
echo "======================================================"
PID=$(pgrep -f 'uvicorn main:app' | head -1)
if [ -z "$PID" ]; then
  echo "  이미 꺼져 있습니다."
else
  kill $(pgrep -f 'uvicorn main:app') 2>/dev/null
  sleep 2
  pkill -9 -f 'uvicorn main:app' 2>/dev/null
  echo "  ✅ 서버를 종료했습니다. (PID $PID)"
fi
echo "======================================================"
echo ""
read -n 1 -s -r -p "아무 키나 누르면 이 창이 닫힙니다..."
echo ""
