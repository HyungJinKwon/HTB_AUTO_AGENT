"""
htb-agent — HTB 머신 승인제 자동 풀이 에이전트
================================================

권한이 확인된 Hack The Box 머신에 한정해 동작하는, 승인제(Human-in-the-loop)
모의해킹 보조 에이전트. 정찰 → 열거 → 초기 침투 → 권한 상승 → (측면 이동) →
취약점 분석 → 보고/라이트업 순으로 진행하며, 모든 실행 명령은 검증 → 범위 →
승인 3관문을 통과한다.

구조·사용법은 docs/ARCHITECTURE.md 참고.
"""

from __future__ import annotations

__version__ = "1.1.0"

from .scope_guard import ScopeGuard, ScopeViolation
from .orchestrator import Orchestrator, OrchestrationReport, PENTEST_PHASES
from .knowledge import KnowledgeBase
from .vuln import VulnKB
from .creds import CredentialVault

__all__ = [
    "__version__",
    "ScopeGuard",
    "ScopeViolation",
    "Orchestrator",
    "OrchestrationReport",
    "PENTEST_PHASES",
    "KnowledgeBase",
    "VulnKB",
    "CredentialVault",
]
