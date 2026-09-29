"""서비스/버전 식별 LOW finding 의 포트 병합 + Server 헤더 버전노출 중복 제거 검증.

- 같은 host+제품의 포트별 버전 식별 finding → 1건으로 병합(포트 한 란).
- 같은 host 에 'Server 헤더 버전 정보 노출' finding 이 있으면 → 버전 식별 finding 제거하고
  제품/버전 정보를 Server 헤더 finding 근거에 보강(정보노출 LOW 를 host 당 1건 유지).
- Server 헤더 finding 이 없으면 → 버전 식별 finding 을 standalone LOW 로 유지.
"""
import main


def _vfind(host, label, port):
    return {
        "host": host, "port": port, "judgment": "취약", "severity": "Low",
        "finding_type": "vulnerability", "cwe": "CWE-200",
        "title": f"서비스/버전 식별: {label} (포트 {port})",
        "tags": ["nmap", "version-detection"],
    }


def test_port_merge_and_standalone_when_no_server_header():
    analysis = {"findings": [
        _vfind("h1", "Apache Tomcat/Coyote 1.1", 80),
        _vfind("h1", "Apache Tomcat/Coyote 1.1", 8080),
    ]}
    main._consolidate_version_findings(analysis)
    vf = [f for f in analysis["findings"] if "서비스/버전 식별" in f["title"]]
    assert len(vf) == 1                       # 포트 병합으로 1건
    assert vf[0]["affected_ports"] == [80, 8080]
    assert "포트 80, 8080" in vf[0]["title"]


def test_dedup_into_server_header_finding():
    srv = {
        "host": "h1", "judgment": "취약", "severity": "Low",
        "title": "서버 소프트웨어 버전 정보 노출 (Server 헤더)",
        "affected_ports": [80, 443, 8080],
        "evidence_detail": "Server: Apache-Coyote/1.1",
    }
    analysis = {"findings": [
        srv,
        _vfind("h1", "Apache Tomcat/Coyote JSP engine 1.1", 80),
        _vfind("h1", "Apache Tomcat/Coyote JSP engine 1.1", 443),
        _vfind("h1", "Apache Tomcat/Coyote JSP engine 1.1", 8080),
    ]}
    main._consolidate_version_findings(analysis)
    titles = [f["title"] for f in analysis["findings"]]
    # 버전 식별 finding 은 Server 헤더 finding 으로 통합되어 사라짐
    assert not any("서비스/버전 식별" in t for t in titles)
    # Server 헤더 finding 은 그대로 있고 근거에 제품 정보 보강됨
    assert "서버 소프트웨어 버전 정보 노출 (Server 헤더)" in titles
    assert "Apache Tomcat/Coyote JSP engine 1.1" in srv["evidence_detail"]
    assert "배너 식별(nmap -sV)" in srv["evidence_detail"]


def test_kept_when_ports_not_covered_by_server_header():
    """Server 헤더 finding 이 커버하지 않는 포트(비HTTP 서비스)의 버전 식별은 유지."""
    srv = {
        "host": "h1", "judgment": "취약", "severity": "Low",
        "title": "서버 소프트웨어 버전 정보 노출 (Server 헤더)",
        "affected_ports": [80],
        "evidence_detail": "Server: nginx/1.18.0",
    }
    analysis = {"findings": [
        srv,
        _vfind("h1", "OpenSSH 8.9p1", 22),   # 22 포트는 Server 헤더가 커버 안 함
    ]}
    main._consolidate_version_findings(analysis)
    vf = [f for f in analysis["findings"] if "서비스/버전 식별" in f["title"]]
    assert len(vf) == 1
    assert vf[0]["affected_ports"] == [22]
