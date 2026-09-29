"""
run.py — 벤치마크 CLI.

사용:
  # 스캔 결과(analysis JSON) 파일을 골든셋과 대조
  python -m benchmark.run --result <analysis.json> --target testfire
  # 커스텀 골든셋 파일 사용
  python -m benchmark.run --result <analysis.json> --golden <golden.json>
  # scanner.db 의 저장 스캔을 scan_id 로 대조(도메인으로 골든셋 자동 매칭)
  python -m benchmark.run --scan-id <id> [--target <name>]
  # 사용 가능한 골든셋 목록
  python -m benchmark.run --list

analysis JSON 은 Eoseureum 스캔 결과의 analysis 객체(또는 {"analysis": {...}}) 이다.
"""
from __future__ import annotations

import argparse
import json
import sys

try:
    from . import golden as _g
    from . import evaluate as _e
except ImportError:
    from benchmark import golden as _g, evaluate as _e


def _load_analysis_from_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("analysis", data) if isinstance(data, dict) else {}


def _load_analysis_from_db(scan_id: str) -> tuple:
    import sqlite3
    import os
    db = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scanner.db")
    con = sqlite3.connect(db)
    row = con.execute("SELECT domain, analysis FROM scans WHERE scan_id=? OR scan_id LIKE ?",
                      (scan_id, scan_id + "%")).fetchone()
    if not row:
        return {}, ""
    domain, analysis_raw = row[0], row[1]
    try:
        return (json.loads(analysis_raw) if analysis_raw else {}), (domain or "")
    except Exception:
        return {}, (domain or "")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Eoseureum 정확도 벤치마크")
    ap.add_argument("--result", help="analysis JSON 파일")
    ap.add_argument("--scan-id", help="scanner.db 저장 스캔 ID")
    ap.add_argument("--target", help="골든셋 키/도메인(testfire/dvwa/juiceshop/bwapp)")
    ap.add_argument("--golden", help="커스텀 골든셋 JSON 파일")
    ap.add_argument("--list", action="store_true", help="골든셋 목록")
    ap.add_argument("--json", action="store_true", help="JSON 출력")
    args = ap.parse_args(argv)

    if args.list:
        for g in _g.available():
            print(f"  {g['key']:<12} {g['label']} (기대 {g['expected']})")
        return 0

    analysis, target = {}, (args.target or "")
    if args.scan_id:
        analysis, dom = _load_analysis_from_db(args.scan_id)
        if not target:
            target = dom
    elif args.result:
        analysis = _load_analysis_from_file(args.result)
    else:
        ap.error("--result 또는 --scan-id 필요")

    custom = None
    if args.golden:
        with open(args.golden, "r", encoding="utf-8") as f:
            custom = json.load(f)
    golden = _g.resolve_golden(target, custom)
    if not golden:
        print(f"골든셋을 찾을 수 없습니다: '{target}'. --list 로 확인하거나 --golden 지정.")
        return 2

    result = _e.evaluate(analysis, golden)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(_e.format_report(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
