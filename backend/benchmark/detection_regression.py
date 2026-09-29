"""
detection_regression.py — 탐지 로직 회귀 벤치마크 러너(오프라인·네트워크/스캔 없음).

benchmark/detection_cases.py 의 라벨 케이스를 실제 탐지 로직에 통과시켜
탐지율(recall)·오탐가드율(specificity)·정밀도(precision)를 계측한다.
payload/판정 로직 변경 전후로 이 수치를 비교하면 '실제로 좋아졌는지/오탐이 늘었는지'가 보인다.

no-self-run-scans 준수: 라이브 스캔을 실행하지 않는다. rule_engine._build_active_probe_findings
와 순수 판정 함수만 호출한다.

사용:
  python -m benchmark.detection_regression        # 리포트 출력 + 회귀 게이트 종료코드
"""
from __future__ import annotations

import importlib


def _run_active_probe_case(probe_key: str, probe_data: dict):
    """합성 active_probes 를 rule_engine 변환에 통과 → (reported: bool, judgment: str|None)."""
    import rule_engine as re_
    findings = re_._build_active_probe_findings(
        "bench-host", 80, "http", {probe_key: probe_data}, set())
    for f in findings or []:
        # 해당 probe_key 로 생성된 finding 인지 느슨히 확인(같은 스캔에 1개 키만 넣으므로 첫 건)
        return True, f.get("judgment")
    return False, None


def _run_judge_case(module: str, func: str, kwargs: dict):
    mod = importlib.import_module(module)
    fn = getattr(mod, func)
    res = fn(**kwargs)
    # judge_bfla 는 (grade, category, reason) 튜플 → grade 만 비교
    if isinstance(res, tuple):
        return res[0]
    return res


def run_regression() -> dict:
    from benchmark.detection_cases import ACTIVE_PROBE_CASES, JUDGE_CASES

    tp = fp = fn = tn = 0          # active_probe 케이스 혼동행렬
    judgment_mismatch = []         # 보고는 맞으나 판정(취약/참고) 불일치
    failures = []                  # 기대와 다른 케이스(상세)
    per_tech: dict = {}

    for cid, pkey, pdata, should_report, expect_judgment, note in ACTIVE_PROBE_CASES:
        reported, judgment = _run_active_probe_case(pkey, pdata)
        bucket = per_tech.setdefault(pkey, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
        ok = (reported == should_report)
        if should_report and reported:
            tp += 1; bucket["tp"] += 1
            if expect_judgment and judgment != expect_judgment:
                judgment_mismatch.append((cid, expect_judgment, judgment))
        elif should_report and not reported:
            fn += 1; bucket["fn"] += 1
            failures.append((cid, "FN(미탐)", note))
        elif (not should_report) and reported:
            fp += 1; bucket["fp"] += 1
            failures.append((cid, "FP(오탐)", note))
        else:
            tn += 1; bucket["tn"] += 1

    # judge 케이스(정확 일치)
    judge_pass = judge_total = 0
    for cid, module, func, kwargs, expected, note in JUDGE_CASES:
        judge_total += 1
        try:
            got = _run_judge_case(module, func, kwargs)
        except Exception as e:
            got = f"ERROR:{e}"
        if got == expected:
            judge_pass += 1
        else:
            failures.append((cid, f"JUDGE(기대 {expected} != {got})", note))

    recall = tp / (tp + fn) if (tp + fn) else 1.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    specificity = tn / (tn + fp) if (tn + fp) else 1.0  # 오탐가드율
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "recall": round(recall, 3), "precision": round(precision, 3),
        "specificity": round(specificity, 3),
        "judge_pass": judge_pass, "judge_total": judge_total,
        "judgment_mismatch": judgment_mismatch,
        "failures": failures, "per_tech": per_tech,
    }


def print_report(m: dict) -> None:
    print("=" * 60)
    print("  Eoseureum 탐지 로직 회귀 벤치마크 (오프라인)")
    print("=" * 60)
    print(f"  탐지율(recall)     : {m['recall']*100:.1f}%  (TP {m['tp']} / FN {m['fn']})")
    print(f"  정밀도(precision)  : {m['precision']*100:.1f}%  (FP {m['fp']})")
    print(f"  오탐가드(specific.): {m['specificity']*100:.1f}%  (TN {m['tn']} / FP {m['fp']})")
    print(f"  판정함수 정확도    : {m['judge_pass']}/{m['judge_total']}")
    if m["judgment_mismatch"]:
        print("  [판정 등급 불일치]")
        for cid, exp, got in m["judgment_mismatch"]:
            print(f"    - {cid}: 기대 {exp} != {got}")
    if m["failures"]:
        print("  [실패 케이스]")
        for cid, kind, note in m["failures"]:
            print(f"    - {cid}: {kind} — {note}")
    else:
        print("  실패 케이스 없음 ✓")
    print("-" * 60)
    print("  기법별:")
    for tech, b in sorted(m["per_tech"].items()):
        print(f"    {tech:20s} TP={b['tp']} FP={b['fp']} FN={b['fn']} TN={b['tn']}")
    print("=" * 60)


# 회귀 게이트 임계치(이 아래로 떨어지면 실패)
THRESHOLDS = {"recall": 1.0, "precision": 1.0, "specificity": 1.0, "judge": 1.0}


def gate_ok(m: dict) -> bool:
    return (m["recall"] >= THRESHOLDS["recall"]
            and m["precision"] >= THRESHOLDS["precision"]
            and m["specificity"] >= THRESHOLDS["specificity"]
            and m["judge_pass"] == m["judge_total"]
            and not m["judgment_mismatch"])


if __name__ == "__main__":
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    metrics = run_regression()
    print_report(metrics)
    sys.exit(0 if gate_ok(metrics) else 1)
