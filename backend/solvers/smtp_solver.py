"""solvers/smtp_solver.py — SMTP 배너/STARTTLS/릴레이 노출 기존 정보 분석(메일 발송 없음)."""
from __future__ import annotations
from .base import BaseSolver


class SmtpSolver(BaseSolver):
    name = "smtp_solver"
    technique = "smtp"
    chain_name = "Messaging Service Chain"
    recommend = "오픈 릴레이 차단·STARTTLS 적용·사용자 열거 방지 점검(메일 발송 미수행)"
    handles = ("smtp", "imap", "pop3", "messaging")
