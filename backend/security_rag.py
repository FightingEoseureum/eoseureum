"""
security_rag.py — 보안 지식베이스 기반 RAG 검색기 (네트워크 호출 없음).

탐지 결과(finding)의 텍스트를 security_knowledge/ 의 지식 엔트리와 키워드/CWE/OWASP
매칭하여 관련 지식(조치 가이드 포함)을 반환한다. 모든 데이터는 로컬 JSON 에서 로드하며
파일 누락·JSON 오류는 빈 결과로 안전하게 방어한다.

핵심 인터페이스
  retrieve_knowledge(finding: dict, technologies: list=None, attack_chains: list=None) -> dict
    반환: {"matched_knowledge": [
              {"id", "title", "owasp", "cwe", "matched_keywords": [...], "remediation": [...]},
              ... (관련도 높은 순, 최대 5개)
          ]}
    - owasp_top10_2021.json + cwe_mapping.json 엔트리를 모듈 로드 시 1회 캐시.
    - remediation_guide.json / false_positive_rules.json 을 id 로 병합 보강.
    - finding 의 title/name/category/cwe/owasp/evidence(evidence_detail)/tags/
      affected_urls(affected_endpoints) 텍스트를 합쳐 매칭.
    - 매칭 키워드 수 + cwe/owasp 정확 일치 가중치로 관련도 점수 산정.
    - technologies/attack_chains 가 주어지면 보조 매칭으로 가중치 보강.
    - 매칭 0개면 {"matched_knowledge": []}.
"""
import json
import os

_KNOWLEDGE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_knowledge")

# 점수 가중치
_W_KEYWORD = 2          # 매칭 키워드 1개당
_W_CWE_EXACT = 6        # CWE 정확 일치
_W_OWASP_EXACT = 4      # OWASP 카테고리 일치
_W_TECH_RELATED = 3     # 기술 규칙으로 연관된 id
_W_CHAIN_RELATED = 3    # 공격 체인 규칙으로 연관된 id

_MAX_RESULTS = 5

# 모듈 캐시
_CACHE = None


def _load_json(filename):
    """security_knowledge/<filename> 로드. 실패 시 None."""
    path = os.path.join(_KNOWLEDGE_DIR, filename)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _build_cache():
    """엔트리 + 보강 가이드 + 기술/체인 규칙을 1회 로드."""
    entries = []
    for fname in ("owasp_top10_2021.json", "cwe_mapping.json", "cwe_mapping_ext.json",
                  "service_knowledge.json"):
        data = _load_json(fname)
        if isinstance(data, list):
            for e in data:
                if isinstance(e, dict) and e.get("id"):
                    entries.append(e)

    remediation_guide = _load_json("remediation_guide.json")
    if not isinstance(remediation_guide, dict):
        remediation_guide = {}
    fp_rules = _load_json("false_positive_rules.json")
    if not isinstance(fp_rules, dict):
        fp_rules = {}

    # id 로 보강 병합
    for e in entries:
        eid = e.get("id")
        guide = remediation_guide.get(eid)
        if isinstance(guide, dict):
            if guide.get("remediation"):
                e["remediation"] = list(guide["remediation"])
            if guide.get("additional_verification"):
                e["additional_verification"] = list(guide["additional_verification"])
        fp = fp_rules.get(eid)
        if isinstance(fp, dict) and fp.get("false_positive_conditions"):
            e["false_positive_conditions"] = list(fp["false_positive_conditions"])

    tech_rules = _load_json("technology_rules.json")
    if not isinstance(tech_rules, list):
        tech_rules = []
    chain_rules = _load_json("attack_chain_rules.json")
    if not isinstance(chain_rules, list):
        chain_rules = []

    return {
        "entries": entries,
        "tech_rules": tech_rules,
        "chain_rules": chain_rules,
    }


def _get_cache():
    global _CACHE
    if _CACHE is None:
        try:
            _CACHE = _build_cache()
        except Exception:
            _CACHE = {"entries": [], "tech_rules": [], "chain_rules": []}
    return _CACHE


def reset_cache():
    """테스트/리로드용: 캐시 무효화."""
    global _CACHE
    _CACHE = None


def _as_text_parts(value):
    """문자열/리스트/딕트 값을 텍스트 조각 리스트로 평탄화."""
    parts = []
    if value is None:
        return parts
    if isinstance(value, str):
        if value:
            parts.append(value)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            parts.extend(_as_text_parts(v))
    elif isinstance(value, dict):
        for v in value.values():
            parts.extend(_as_text_parts(v))
    else:
        parts.append(str(value))
    return parts


def _finding_text(finding):
    """finding 의 관련 필드를 합쳐 소문자 검색 텍스트로."""
    if not isinstance(finding, dict):
        return ""
    keys = (
        "title", "name", "category", "evidence", "evidence_detail",
        "tags", "affected_urls", "affected_endpoints", "description",
    )
    parts = []
    for k in keys:
        parts.extend(_as_text_parts(finding.get(k)))
    return " ".join(parts).lower()


def _norm(s):
    return s.strip().lower() if isinstance(s, str) else ""


def _score_entry(entry, text, finding_cwe, finding_owasp,
                 tech_related_ids, chain_related_ids):
    """단일 엔트리 점수 + 매칭 키워드 반환."""
    matched_keywords = []
    for kw in entry.get("keywords", []) or []:
        kwl = _norm(kw)
        if kwl and kwl in text:
            matched_keywords.append(kw)

    score = len(matched_keywords) * _W_KEYWORD

    entry_cwe = _norm(entry.get("cwe"))
    if finding_cwe and entry_cwe and finding_cwe == entry_cwe:
        score += _W_CWE_EXACT

    # OWASP 는 카테고리 코드(예: A05) 단위로 비교
    entry_owasp = _norm(entry.get("owasp"))
    if finding_owasp and entry_owasp:
        if finding_owasp in entry_owasp or entry_owasp.startswith(finding_owasp):
            score += _W_OWASP_EXACT

    eid = entry.get("id")
    if eid in tech_related_ids:
        score += _W_TECH_RELATED
    if eid in chain_related_ids:
        score += _W_CHAIN_RELATED

    return score, matched_keywords


def _collect_tech_related_ids(technologies, tech_rules):
    """technologies 입력을 tech_rules 와 매칭해 연관 id 집합 반환."""
    related = set()
    if not technologies:
        return related
    tech_text = " ".join(_as_text_parts(technologies)).lower()
    if not tech_text:
        return related
    for rule in tech_rules:
        if not isinstance(rule, dict):
            continue
        hit = False
        for kw in rule.get("keywords", []) or []:
            kwl = _norm(kw)
            if kwl and kwl in tech_text:
                hit = True
                break
        tech_name = _norm(rule.get("tech"))
        if tech_name and tech_name in tech_text:
            hit = True
        if hit:
            for rid in rule.get("related_ids", []) or []:
                related.add(rid)
    return related


def _collect_chain_related_ids(attack_chains, chain_rules):
    """attack_chains 입력을 chain_rules 와 매칭해 연관 id 집합 반환."""
    related = set()
    if not attack_chains:
        return related
    chain_text = " ".join(_as_text_parts(attack_chains)).lower()
    if not chain_text:
        return related
    for rule in chain_rules:
        if not isinstance(rule, dict):
            continue
        hit = False
        rid = _norm(rule.get("id"))
        if rid and rid in chain_text:
            hit = True
        if not hit:
            for cond in rule.get("when", []) or []:
                condl = _norm(cond)
                if condl and condl in chain_text:
                    hit = True
                    break
        if hit:
            for r in rule.get("related_ids", []) or []:
                related.add(r)
    return related


# ── 임베딩(의미 검색) RAG — ENABLE_EMBED_RAG=true 일 때만 사용, 실패 시 키워드 폴백 ──
_ENTRY_VEC_CACHE: dict = {}   # entry id -> embedding vector


def _entry_text(entry: dict) -> str:
    parts = [entry.get("title", ""), entry.get("owasp", ""), entry.get("cwe", "")]
    parts += [str(k) for k in (entry.get("keywords") or [])]
    desc = entry.get("description") or entry.get("summary") or ""
    if desc:
        parts.append(str(desc))
    return " ".join(p for p in parts if p)[:4000]


async def retrieve_knowledge_semantic(finding, technologies=None, attack_chains=None):
    """임베딩 의미 검색으로 관련 지식을 반환. 비활성/실패/빈 결과 시 키워드 RAG 로 폴백."""
    import security_embed as se
    if not se.embed_enabled():
        return retrieve_knowledge(finding, technologies, attack_chains)
    try:
        cache = _get_cache()
        entries = cache["entries"]
        if not entries:
            return {"matched_knowledge": []}

        # 엔트리 임베딩 1회 캐시
        missing = [e for e in entries if e.get("id") not in _ENTRY_VEC_CACHE]
        for e in missing:
            vec = await se.embed_text(_entry_text(e))
            if vec:
                _ENTRY_VEC_CACHE[e.get("id")] = vec

        qvec = await se.embed_text(_finding_text(finding) or str(finding.get("title", "")))
        if not qvec:
            return retrieve_knowledge(finding, technologies, attack_chains)

        entry_vecs = [(e.get("id"), _ENTRY_VEC_CACHE[e.get("id")])
                      for e in entries if e.get("id") in _ENTRY_VEC_CACHE]
        ranked = se.rank_by_similarity(qvec, entry_vecs, top_k=_MAX_RESULTS)
        if not ranked:
            return retrieve_knowledge(finding, technologies, attack_chains)

        by_id = {e.get("id"): e for e in entries}

        # CWE 정확매칭 우선: finding 에 CWE 가 있고 동일 CWE 엔트리가 있으면 최상단에 고정.
        # (순수 의미검색이 깔끔한 CWE 라벨을 무시해 오매칭하는 것을 방지 — 임베딩=exact+의미 결합)
        ranked_ids = [eid for eid, _ in ranked]
        finding_cwe = _norm(finding.get("cwe")) if isinstance(finding, dict) else ""
        if finding_cwe:
            exact_ids = [e.get("id") for e in entries if _norm(e.get("cwe")) == finding_cwe]
            for xid in reversed(exact_ids):        # 여러 개면 원래 순서 유지하며 앞으로
                if xid in ranked_ids:
                    ranked_ids.remove(xid)
                ranked_ids.insert(0, xid)

        def _sim_of(eid):
            for i, s in ranked:
                if i == eid:
                    return round(float(s), 3)
            return None

        results = []
        for eid in ranked_ids[:_MAX_RESULTS]:
            e = by_id.get(eid)
            if not e:
                continue
            results.append({
                "id": e.get("id"), "title": e.get("title"),
                "owasp": e.get("owasp"), "cwe": e.get("cwe"),
                "matched_keywords": [], "similarity": _sim_of(eid),
                "remediation": list(e.get("remediation", []) or []),
            })
        return {"matched_knowledge": results} if results else \
            retrieve_knowledge(finding, technologies, attack_chains)
    except Exception:
        return retrieve_knowledge(finding, technologies, attack_chains)


def retrieve_knowledge(finding, technologies=None, attack_chains=None):
    """finding 에 관련된 보안 지식을 관련도 순으로 최대 5개 반환(키워드 매칭)."""
    empty = {"matched_knowledge": []}
    try:
        cache = _get_cache()
        entries = cache["entries"]
        if not entries:
            return empty

        text = _finding_text(finding)
        finding_cwe = _norm(finding.get("cwe")) if isinstance(finding, dict) else ""
        finding_owasp = _norm(finding.get("owasp")) if isinstance(finding, dict) else ""

        tech_related = _collect_tech_related_ids(technologies, cache["tech_rules"])
        chain_related = _collect_chain_related_ids(attack_chains, cache["chain_rules"])

        scored = []
        for entry in entries:
            score, matched_keywords = _score_entry(
                entry, text, finding_cwe, finding_owasp,
                tech_related, chain_related,
            )
            if score <= 0:
                continue
            scored.append((score, entry, matched_keywords))

        if not scored:
            return empty

        # 점수 내림차순, 동점은 매칭 키워드 수 → id 안정 정렬
        scored.sort(key=lambda t: (t[0], len(t[2]), t[1].get("id", "")), reverse=True)

        results = []
        for score, entry, matched_keywords in scored[:_MAX_RESULTS]:
            results.append({
                "id": entry.get("id"),
                "title": entry.get("title"),
                "owasp": entry.get("owasp"),
                "cwe": entry.get("cwe"),
                "matched_keywords": matched_keywords,
                "remediation": list(entry.get("remediation", []) or []),
            })

        return {"matched_knowledge": results}
    except Exception:
        return empty
