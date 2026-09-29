"""agents/upload — Upload Agent Group (파일 입력/확장자 제한/저장 노출 해석, 업로드 미수행)."""
from __future__ import annotations
from ..base_agent import BaseAgent


class FileInputAgent(BaseAgent):
    name = "file_input_agent"
    role = "파일 입력 분석"
    family = "upload"
    recommend = "파일 입력 폼의 서버측 검증 존재 여부 확인"

    def _observe(self, ctx):
        return {"observation": "multipart/file input 업로드 폼 존재 분석",
                "limitation": "실제 파일/웹쉘 업로드는 수행하지 않음"}


class FileTypeRestrictionAgent(BaseAgent):
    name = "file_type_restriction_agent"
    role = "확장자 제한 분석"
    family = "upload"
    recommend = "서버측 확장자/MIME/매직바이트 화이트리스트 검증 확인"

    def _observe(self, ctx):
        return {"observation": "accept 속성 등 클라이언트 제한만 관찰 — 서버측 검증 수동 확인 필요",
                "impact_note": "서버측 검증 미흡 시 악성 파일 처리 위험"}


class StorageExposureAgent(BaseAgent):
    name = "storage_exposure_agent"
    role = "저장 노출 분석"
    family = "upload"
    recommend = "업로드 파일 저장 경로의 실행권한/직접 접근 가능성 확인"

    def _observe(self, ctx):
        return {"observation": "업로드/다운로드 경로 노출 관점 분석",
                "limitation": "실행 가능 여부는 자동 확인하지 않음(승인 시 무해 파일만)"}


AGENTS = [FileInputAgent, FileTypeRestrictionAgent, StorageExposureAgent]
