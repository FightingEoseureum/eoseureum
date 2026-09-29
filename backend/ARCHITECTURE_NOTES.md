# Eoseureum 아키텍처 노트 — 계층 정리 & 통합 방향

## 파이프라인(단일 흐름)
Recon → URL/Browser Discovery → Attack Surface Planner(+Detection Intelligence 우선순위)
→ Active Probing(실제 점검) → Rule Engine 판정(evidence_levels/proof_mode)
→ Validation/Proof(proof_validation/proof_evidence) → Knowledge Graph(security_knowledge_graph)
→ Business Context → Report Model(report_model) → Renderer(DOCX/HTML/PDF/인앱)

## 개념 계층(겹침 정리)
- **판정 권위**: `evidence_levels`(Level 0~3) + `proof_mode`(무해 증거 등급) = Rule Engine. 유일한 최종 판정.
- **정책/게이트**: `payload_validator`, `proof_policy`, `validation_profiles`(SAFE/…/PROOF). "무엇을 해도 되는가".
- **계획**: `attack_surface_planner`(+`detection_intelligence`), `payload_planner`, `technique_kb`. "무엇을 먼저·왜".
- **증거 정리(표현)**: `proof_validation`(승격 문서화), `proof_evidence`(카드/지문/품질/재현), `false_positive_filter`(오탐 자문). 판정 불변.
- **관계 그래프**: 3종 존재 — 통합 대상.
  - `attack_graph`: 스캔 중 finding→경로(evidence 기반)
  - `attack_path_prioritizer`: 경로 우선순위
  - `security_knowledge_graph`: Asset→…→Finding→Proof→Business→Remediation 관계 + `attack_path_graph`(표현용 Flow)
  → **후속**: 셋을 하나의 그래프 저장소로 병합(현재는 KG가 상위 표현, attack_graph는 내부). 회귀 위험으로 물리 병합은 미수행.
- **집계**: `detection_coverage`(기법별 Tested/Confirmed/…), `evidence_correlation`, `evidence_graph`.
- **표현 통합**: `report_model.build_report_model()` = 렌더러 공용 정규화 모델(파사드). Finding별로
  proof 카드·오탐위험·그래프 우선순위·스크린샷을 `finding_uid`로 결합.

## 통합 진행 상태(파사드)
- ✅ `report_model.normalized_findings()` 도입 — **HTML 렌더러가 이 모델을 소비**하도록 이관(중복 제거).
- ⏳ DOCX 렌더러(report.py) 이관: 회귀 위험(다수 테스트)으로 후속. report_model이 이미 있으니 점진 이관 가능.
- ⏳ 3종 그래프 물리 병합: 후속. 현재는 KG가 캐노니컬 표현.

## 식별자 규약
- 취약점 Finding 은 `finding_uid`(F1,F2…)로 전 계층에서 매핑(카드 교차 오염 방지). `_idx`는 보고서 표시 번호.

## 불변식
- Rule Engine 외에는 verdict/Severity/Confidence/Level/Risk 를 바꾸지 않는다.
- SAFE 기본. 위험 행위(덤프/셸/추출/상태변경/권한상승/brute/내부망)는 프로파일 무관 항상 차단.
