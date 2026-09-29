"""conftest.py — 테스트 환경 격리.

배포용 .env(EGRESS_ENABLED/HYBRID_ENABLED=true 등)가 load_dotenv 로 테스트 프로세스에 새어들면,
스캔 egress 를 i7 SOCKS 프록시로 돌리는 _ssl_connector 나 외부도구 오프로드 경로가 테스트에서
활성화돼(터널·워커가 없으니) 네트워크 기반 프로브 테스트가 깨진다.

pytest 는 conftest.py 를 가장 먼저 임포트하므로, 여기서 먼저 os.environ 에 테스트 기본값(OFF)을
심는다. 이후 어느 모듈이 load_dotenv() 를 부르더라도 python-dotenv 는 기본 override=False 라
'이미 설정된' 이 값을 덮지 않는다 → 배포 플래그와 무관하게 테스트가 결정적으로 돈다.

(RPS 등 다른 배포 env 누수는 이 파일 범위 밖의 기존 이슈로 여기서 다루지 않는다.)
"""
import os

# 단일출구(egress)·하이브리드 오프로드는 테스트에서 항상 OFF — 실제 커넥터/워커 배제.
os.environ["EGRESS_ENABLED"] = "false"
os.environ["HYBRID_ENABLED"] = "false"
