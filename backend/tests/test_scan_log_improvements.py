"""주입점 상한 상향(①) + 워드 표지 E 마크 제거 회귀."""
import os


def test_injection_cap_default_raised(monkeypatch):
    # 기본 500(상향), env 로 조정 가능, 상한 5000
    monkeypatch.delenv("MAX_DISCOVERED_FOR_INJECTION", raising=False)
    cap = max(1, min(5000, int(os.getenv("MAX_DISCOVERED_FOR_INJECTION", "500"))))
    assert cap == 500
    monkeypatch.setenv("MAX_DISCOVERED_FOR_INJECTION", "9999")
    cap2 = max(1, min(5000, int(os.getenv("MAX_DISCOVERED_FOR_INJECTION", "500"))))
    assert cap2 == 5000   # 상한 클램프


def test_word_cover_no_standalone_E_mark():
    # report.py 표지에서 큰 'E' 마크(_run(..., "E", size=40)) 가 제거되었는지
    src = open("report.py", encoding="utf-8").read()
    assert '_run(mark_p, "E", size=40' not in src
    assert "Eoseureum" in src   # 브랜드 텍스트는 유지
