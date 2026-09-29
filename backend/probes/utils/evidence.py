"""probes/utils/evidence.py — probe 실행 중 증거/오류 수집 저장소."""
from __future__ import annotations

from dataclasses import dataclass, field

from .sanitization import mask_secrets


@dataclass
class EvidenceStore:
    items: list = field(default_factory=list)     # 일반 증거
    errors: list = field(default_factory=list)    # probe_error 기록

    def add(self, probe: str, detail: str):
        self.items.append({"probe": probe, "detail": mask_secrets(detail)})

    def add_error(self, probe: str, message: str):
        self.errors.append({"probe": probe, "error": mask_secrets(str(message))[:300]})

    def has_errors(self) -> bool:
        return bool(self.errors)
