"""test_sqlmap_strategy.py — SQLMap 실행 전략(기본 technique 미지정, 옵션 게이트, 위험 옵션 금지)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import external_tools as et

CFG = {"enum_dbs": False, "smart": True}   # 비PROOF 기본: --smart 켜서 빠르게
DANGEROUS = ("--dump", "--os-shell", "--os-pwn", "--file-read", "--file-write", "--sql-shell")

def _cmd(cfg=CFG, **kw):
    base = dict(level=2, risk=1, technique="", random_agent=False, tamper="")
    base.update(kw)
    return et._build_sqlmap_cmd("sqlmap", "http://t/p?id=1", cfg, "/tmp/x", **base)

def test_default_has_no_technique():
    cmd = _cmd()
    assert not any(c.startswith("--technique") for c in cmd)
    assert "--batch" in cmd and "--smart" in cmd and "--threads=1" in cmd

def test_smart_off_in_proof():
    # PROOF 심화(cfg["smart"]=False): --smart 를 빼고 모든 파라미터를 철저히 테스트한다.
    cmd = _cmd(cfg={"enum_dbs": False, "smart": False})
    assert "--smart" not in cmd
    assert "--batch" in cmd and "--threads=1" in cmd

def test_technique_added_only_when_set():
    cmd = _cmd(technique="BEU")
    assert "--technique=BEU" in cmd

def test_random_agent_gated():
    assert not any("random-agent" in c for c in _cmd())
    assert "--random-agent" in _cmd(random_agent=True)

def test_tamper_gated():
    assert not any(c.startswith("--tamper") for c in _cmd())
    assert "--tamper=space2comment" in _cmd(tamper="space2comment")

def test_no_dangerous_flags_ever():
    for cmd in (_cmd(), _cmd(technique="BEUST", random_agent=True, tamper="space2comment", level=5, risk=3)):
        assert not any(d in " ".join(cmd) for d in DANGEROUS)

def test_env_defaults(monkeypatch):
    for k in ("SQLMAP_TECHNIQUE","SQLMAP_RANDOM_AGENT","SQLMAP_TAMPER","SQLMAP_RETRY_ON_NO_INJECTABLE"):
        monkeypatch.delenv(k, raising=False)
    cfg = et._sqlmap_env()
    assert cfg["technique"] == "" and cfg["random_agent"] is False
    assert cfg["tamper"] == "" and cfg["retry_on_no_injectable"] is False
    assert cfg["risk"] == 1  # risk=3 기본 금지
