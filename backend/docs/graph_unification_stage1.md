# 그래프 3종 통합 — 1단계: 계측·매핑 + 골든 스냅샷

목적: `attack_graph` / `attack_path_prioritizer` / `security_knowledge_graph` 세 그래프의
현재 출력·소비처·중복을 문서화하고, 리팩터링(2~4단계)의 무회귀 기준(골든)을 확보한다.
이 단계는 **런타임 경로를 변경하지 않는다**(스캐닝 정상, 서버 재시작 불필요).

## 1. 세 그래프의 진입 함수와 출력(analysis 키)

| 모듈 | 진입 함수 | 산출 analysis 키 | 성격 |
|---|---|---|---|
| `attack_graph.py` | `build_attack_graph(analysis, *, ai_fn=None)` | `attack_graph`={nodes,edges}, `attack_nodes`, `attack_edges`, `attack_paths`, `attack_path_summary` | 스캔 중 finding→경로(증거 기반) 그래프·경로 시퀀스 |
| `attack_path_prioritizer.py` | `prioritize(attack_paths, nodes, *, max_paths)` | `prioritized_paths`(=selected), `path_priority_summary` | 경로 점수·우선순위 + 추천 Solver |
| `security_knowledge_graph.py` | `build_all(analysis)` | `security_knowledge_graph`, `attack_path_graph`, `graph_risk_context` | 캐노니컬 관계그래프(Asset→…→Remediation) + 표현용 Flow + finding별 우선순위 사유 |

main.py 데이터 흐름(호출 순서):
`build_attack_graph` → (attack_graph.nodes + attack_paths) → `prioritize` → `build_all`.
즉 KG(build_all)는 attack_graph/prioritizer 산출물을 입력으로 재사용한다(단방향 의존).

## 2. 소비처

- **리포트 계층만** 소비: `report.py`, `report_model.py`, `report_html_renderer.py`.
- **프론트엔드·API 엔드포인트 직접 소비 없음**(grep 확인) → 통합 이관 표면이 리포트 계층으로 국한된다(위험·범위 축소).

## 3. 중복·불일치(통합 대상)

1. **경로 표현 2종**: `attack_graph.attack_paths`(증거 기반 시퀀스) vs `security_knowledge_graph.attack_path_graph`(표현용 Flow). 같은 "공격 경로"를 서로 다른 스키마로 2번 생성.
2. **우선순위 신호 2종**: `attack_path_prioritizer`(경로 점수/선정) vs `graph_risk_context.graph_priority`(finding별 우선순위 사유). 우선순위 로직이 분산.
3. **노드/엣지 스키마 2종**: attack_graph 노드(역할 기반: entry/login/auth/admin/finding…) vs KG 노드(Asset/Host/Service/Port/URL/…/Remediation). "그래프" 개념 중복, 어휘 상이.
4. 공통 원칙: 세 모듈 모두 판정 불변(Severity/Confidence 인용만), ai_fn 미주입(결정적).

## 4. 통합 방향(후속 단계 요약)

- **캐노니컬 = `security_knowledge_graph`**(가장 상위 표현). attack_graph/prioritizer 출력을 KG에서
  파생하는 **어댑터(뷰)**로 제공 → 소비처(리포트 3파일)는 동일 형태 수신(출력 불변 = 무회귀).
- 2단계: 어댑터 추가. 3단계: 리포트 소비처를 하나씩 캐노니컬/어댑터로 이관(매번 골든 대조).
  4단계: 전부 이관 후 중복 그래프 생성 코드 제거.

## 5. 골든 스냅샷(무회귀 기준)

- 하니스: `benchmark/graph_golden.py`, 고정 픽스처 `FIXTURE_ANALYSIS`(findings 3 + surface 1 + discovery 1).
- 현재 출력(골든): attack_graph nodes=24·edges=27·paths=5, prioritize.selected=5, knowledge_graph 3키.
  결정적(재실행·재캡처 동일 — 집합 순서 등 비결정성 없음 확인).
- 저장/대조: `python -m benchmark.graph_golden --save|--check`, 파일 `benchmark/graph_golden.json`.
- 회귀 게이트: `tests/test_graph_golden.py`(캡처=골든, 결정성, 구조). 2~4단계에서 매 변경마다 이 게이트로
  '사용자에게 보이는 출력 불변'을 검증한다. 의도적 변경 시에만 `--save` 로 골든 갱신.

## 6. 다음 단계 착수 조건

2단계(어댑터) 착수 전 확인: (a) 골든 게이트 green, (b) 리포트 계층이 읽는 정확한 필드 목록을
report.py/report_model.py/report_html_renderer.py 에서 필드 단위로 추출(3단계 이관 체크리스트).
