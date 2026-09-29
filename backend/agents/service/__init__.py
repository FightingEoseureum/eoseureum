"""
agents/service — 서비스 전용 Agent Group (Service Security Framework v2).

기존 수집 증거(배너/버전/TLS/인증 필요 여부/보호모드/Guest 등)만 해석·보강한다.
신규 네트워크 요청/로그인/브루트포스/exploit 금지. Evidence Level 변경·취약 확정 불가.
BaseAgent 안전 불변식(did_discovery=False, level_changed=False)을 상속한다.
"""
from __future__ import annotations
from ..base_agent import BaseAgent, ctx_level, ctx_detail


def _obs(role, text, **kw):
    out = {"observation": text}
    out.update(kw)
    return out


# ── SSH Agent Group ──────────────────────────────────────────────────────────
class RemoteAccessAgent(BaseAgent):
    name = "remote_access_agent"; role = "원격 접근 분석"; family = "ssh"
    recommend = "외부 접근 제한(VPN/Zero Trust), 포트 접근 제어"
    def _observe(self, ctx):
        return _obs(self.role, "원격 관리 접근 표면(SSH/RDP 등) — 외부 노출 시 권한 있는 접근 위험",
                    impact_note="원격 관리자 접근 위험")


class AuthenticationPolicyAgent(BaseAgent):
    name = "authentication_policy_agent"; role = "인증 정책 분석"; family = "ssh"
    recommend = "비밀번호 로그인 비활성·키 기반 인증·MFA(무차별 인증 미수행)"
    def _observe(self, ctx):
        d = ctx_detail(ctx)
        return _obs(self.role, "인증 방식/정책 단서 분석(password vs publickey)" + (f" — {d[:80]}" if d else ""),
                    limitation="로그인/패스워드 추측은 수행하지 않음")


class CryptoAlgorithmAgent(BaseAgent):
    name = "crypto_algorithm_agent"; role = "암호 알고리즘 분석"; family = "ssh"
    recommend = "약한 KEX/cipher/MAC 제거, 최신 알고리즘 적용"
    def _observe(self, ctx):
        return _obs(self.role, "KEX/cipher/MAC 알고리즘 노출 단서 분석(배너/핸드셰이크)")


# ── FTP Agent Group ──────────────────────────────────────────────────────────
class AnonymousAccessAgent(BaseAgent):
    name = "anonymous_access_agent"; role = "익명 접근 분석"; family = "ftp"
    recommend = "Anonymous 접속 비활성화"
    def _observe(self, ctx):
        return _obs(self.role, "FTP 익명(anonymous) 접속 가능성 단서 분석",
                    limitation="실제 익명 로그인/파일 다운로드는 수행하지 않음")


class FileExposureAgent(BaseAgent):
    name = "file_exposure_agent"; role = "파일 노출 분석"; family = "ftp"
    recommend = "공개 디렉터리 접근 제어·민감 파일 제거"
    def _observe(self, ctx):
        return _obs(self.role, "FTP 공개 파일/디렉터리 노출 가능성 분석", impact_note="민감 파일 노출 위험")


class PlaintextCredentialRiskAgent(BaseAgent):
    name = "plaintext_credential_risk_agent"; role = "평문 자격증명 위험 분석"; family = "ftp"
    recommend = "FTPS/SFTP(TLS) 적용으로 평문 전송 제거"
    def _observe(self, ctx):
        return _obs(self.role, "평문(비암호화) 전송 시 자격증명 노출 위험 분석(TLS 미적용 단서)")


# ── SMB Agent Group ──────────────────────────────────────────────────────────
class GuestAccessAgent(BaseAgent):
    name = "guest_access_agent"; role = "Guest 접근 분석"; family = "smb"
    recommend = "Guest/익명 접근 비활성화"
    def _observe(self, ctx):
        return _obs(self.role, "SMB Guest/익명 접근 가능성 단서 분석",
                    limitation="실제 공유 접근/파일 열람은 수행하지 않음")


class SigningPolicyAgent(BaseAgent):
    name = "signing_policy_agent"; role = "서명 정책 분석"; family = "smb"
    recommend = "SMB Signing 활성(중간자 공격 방지)"
    def _observe(self, ctx):
        return _obs(self.role, "SMB Signing(메시지 서명) 설정 단서 분석")


class FileSharingExposureAgent(BaseAgent):
    name = "file_sharing_exposure_agent"; role = "파일 공유 노출 분석"; family = "smb"
    recommend = "외부 차단·공유 권한 최소화"
    def _observe(self, ctx):
        return _obs(self.role, "SMB/NFS 파일 공유 외부 노출 단서 분석", impact_note="민감 파일 노출 위험")


# ── Database Agent Group ─────────────────────────────────────────────────────
class ExternalExposureAgent(BaseAgent):
    name = "external_exposure_agent"; role = "외부 노출 분석"; family = "mysql"
    recommend = "DB 외부 노출 차단(방화벽/내부망), 네트워크 ACL"
    def _observe(self, ctx):
        return _obs(self.role, "DB 포트 외부 노출 단서 분석(외부 스캔에서 식별됨)",
                    impact_note="민감 정보 노출 위험")


class AuthenticationRequirementAgent(BaseAgent):
    name = "authentication_requirement_agent"; role = "인증 요구 분석"; family = "mysql"
    recommend = "인증 필수화·최소 권한 계정"
    def _observe(self, ctx):
        return _obs(self.role, "DB 인증 요구 여부 단서 분석",
                    limitation="실제 로그인/쿼리/덤프는 수행하지 않음")


class DbDataExposureAgent(BaseAgent):
    name = "db_data_exposure_agent"; role = "데이터 노출 분석"; family = "mysql"
    recommend = "전송 암호화·접근 제어·민감 데이터 마스킹"
    def _observe(self, ctx):
        return _obs(self.role, "DB 민감 데이터 노출 가능성 분석", impact_note="개인/금융 정보 노출 가능성")


# ── Redis/Elasticsearch Agent Group ──────────────────────────────────────────
class UnauthenticatedAccessAgent(BaseAgent):
    name = "unauthenticated_access_agent"; role = "무인증 접근 분석"; family = "redis"
    recommend = "인증(requirepass) 활성·외부 노출 차단"
    def _observe(self, ctx):
        return _obs(self.role, "Redis/ES 무인증(noauth) 접근 가능성 단서 분석",
                    limitation="실제 명령/조회는 수행하지 않음")


class ProtectedModeAgent(BaseAgent):
    name = "protected_mode_agent"; role = "보호 모드 분석"; family = "redis"
    recommend = "Protected Mode 활성·바인드 주소 제한"
    def _observe(self, ctx):
        return _obs(self.role, "Redis Protected Mode 설정 단서 분석")


class DataExposureAgent(BaseAgent):
    name = "data_exposure_agent"; role = "데이터 노출 분석"; family = "redis"
    recommend = "외부 차단·인증·전송 암호화"
    def _observe(self, ctx):
        return _obs(self.role, "인메모리/검색 데이터 노출 가능성 분석", impact_note="데이터 노출 위험")


# ── Container Agent Group (docker + k8s) ─────────────────────────────────────
class DockerApiExposureAgent(BaseAgent):
    name = "docker_api_exposure_agent"; role = "Docker API 노출 분석"; family = "docker"
    recommend = "Docker API 외부 차단·TLS 상호 인증"
    def _observe(self, ctx):
        return _obs(self.role, "Docker 데몬/API 외부 노출 단서 분석",
                    impact_note="컨테이너/호스트 장악 위험",
                    limitation="컨테이너 생성/조작은 수행하지 않음")


class KubernetesApiExposureAgent(BaseAgent):
    name = "kubernetes_api_exposure_agent"; role = "Kubernetes API 노출 분석"; family = "k8s"
    recommend = "API Server/kubelet 익명 접근 차단·RBAC"
    def _observe(self, ctx):
        return _obs(self.role, "Kubernetes API Server/kubelet 노출 단서 분석",
                    impact_note="클러스터 제어 위험",
                    limitation="워크로드 배포/조작은 수행하지 않음")


class PrivilegedControlPlaneAgent(BaseAgent):
    name = "privileged_control_plane_agent"; role = "권한 컨트롤 플레인 분석"; family = "docker"
    recommend = "관리망 분리·인증/인가 강화"
    def _observe(self, ctx):
        return _obs(self.role, "컨테이너 컨트롤 플레인 권한 노출 가능성 분석", impact_note="인프라 제어 위험")


# ── Messaging Agent Group ────────────────────────────────────────────────────
class OpenRelayAgent(BaseAgent):
    name = "open_relay_agent"; role = "오픈 릴레이 분석"; family = "smtp"
    recommend = "오픈 릴레이 차단·인증 발송 적용"
    def _observe(self, ctx):
        return _obs(self.role, "SMTP 오픈 릴레이 가능성 단서 분석",
                    limitation="실제 메일 발송/릴레이 테스트는 수행하지 않음")


class MailExposureAgent(BaseAgent):
    name = "mail_exposure_agent"; role = "메일 노출 분석"; family = "smtp"
    recommend = "사용자 열거 방지·서비스 노출 최소화"
    def _observe(self, ctx):
        return _obs(self.role, "메일 서비스 정보/사용자 열거 노출 가능성 분석")


class MailTlsPolicyAgent(BaseAgent):
    name = "mail_tls_policy_agent"; role = "메일 TLS 정책 분석"; family = "smtp"
    recommend = "STARTTLS/TLS 적용으로 평문 전송 제거"
    def _observe(self, ctx):
        return _obs(self.role, "메일 전송 구간 TLS(STARTTLS) 적용 단서 분석")


# family → Agent 클래스 목록(서비스 Agent Group). docker/k8s 는 Container 그룹 공유.
_CONTAINER = [DockerApiExposureAgent, KubernetesApiExposureAgent, PrivilegedControlPlaneAgent]
SERVICE_FAMILY_AGENTS = {
    "ssh": [RemoteAccessAgent, AuthenticationPolicyAgent, CryptoAlgorithmAgent],
    "ftp": [AnonymousAccessAgent, FileExposureAgent, PlaintextCredentialRiskAgent],
    "smb": [GuestAccessAgent, SigningPolicyAgent, FileSharingExposureAgent],
    "mysql": [ExternalExposureAgent, AuthenticationRequirementAgent, DbDataExposureAgent],
    "redis": [UnauthenticatedAccessAgent, ProtectedModeAgent, DataExposureAgent],
    "docker": _CONTAINER,
    "k8s": _CONTAINER,
    "smtp": [OpenRelayAgent, MailExposureAgent, MailTlsPolicyAgent],
}
