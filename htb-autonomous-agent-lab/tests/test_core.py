# 실행: htb-agent 디렉토리에서  python3 tests/test_core.py
import sys
sys.path.insert(0, "src")
from htb_agent import command_validator as cv
from htb_agent.target_profiler import classify, OSClass

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1; print(f"  ✅ {name}")
    else:
        failed += 1; print(f"  ❌ {name}")

print("=== CommandValidator ===")
# 정상 명령
r = cv.validate("nmap -sV -p 22,80,443 10.129.1.5")
check("정상 nmap 통과(에러0)", r.ok)
# 포트 오류
r = cv.validate("nmap -p 70000 10.129.1.5")
check("포트 65535 초과 → 에러", not r.ok and any(i.code=="PORT" for i in r.errors))
# 포트 범위 역전
r = cv.validate("nmap -p 443-22 10.129.1.5")
check("포트 범위 역전 → 에러", any(i.code=="PORT" for i in r.errors))
# 따옴표 불균형
r = cv.validate("echo 'unbalanced")
check("따옴표 불균형 → 에러", any(i.code in ("QUOTE","SYNTAX") for i in r.errors))
# base64 정상
r = cv.validate("echo aGVsbG8= | base64 -d")
check("정상 base64 통과", not any(i.code=="BASE64" for i in r.errors))
# base64 깨짐 (패딩/문자 오류)
r = cv.validate("echo aGVsbG8 | base64 -d")   # 길이 7, 4의 배수 아님
check("깨진 base64 → 에러", any(i.code=="BASE64" for i in r.errors))
r = cv.validate("base64 -d <<< 'aGVs!!bG8='")
check("base64 문자셋 위반 → 에러", any(i.code=="BASE64" for i in r.errors))
# 파괴적 명령
check("rm -rf / 차단", not cv.validate("rm -rf /").ok)
check("fork bomb 차단", not cv.validate(":(){ :|:& };:").ok)
check("mkfs 차단", not cv.validate("mkfs.ext4 /dev/sda1").ok)

# 형식 헬퍼
check("validate_base64 정상", cv.validate_base64("aGVsbG8=")[0])
check("validate_base64 패딩오류", not cv.validate_base64("aGVsbG8")[0])
check("validate_port 1-1024", cv.validate_port_spec("1-1024")[0])
check("validate_port 0-65535 경계", cv.validate_port_spec("0,65535")[0])
check("validate_port 65536 거부", not cv.validate_port_spec("65536")[0])

# 해시 식별
check("MD5/NTLM 식별", "MD5/NTLM/LM(32hex·다의적)" in cv.identify_hash("5f4dcc3b5aa765d61d8327deb882cf99"))
check("SHA256 식별", "SHA256(64hex)" in cv.identify_hash("a"*64))
check("bcrypt 식별", any("bcrypt" in k for k in cv.identify_hash("$2b$12$"+"a"*53)))
check("sha512crypt 식별", any("sha512crypt" in k for k in cv.identify_hash("$6$abc$"+"a"*86)))
check("해시 아님 거부", cv.identify_hash("not_a_hash")==[])
check("validate_hash expected 불일치", not cv.validate_hash("a"*32, expected="SHA256")[0])

print("\n=== TargetProfiler ===")
# Linux 박스
r = classify([22,80], banners={22:"OpenSSH 8.2p1 Ubuntu-4ubuntu0.5", 80:"Apache/2.4.41"})
check("Linux 판정", r.os_class==OSClass.LINUX)
check("Linux 확신도 높음", r.confidence>=0.85)
# Windows AD DC
r = classify([53,88,135,139,389,445,636,3268,3389,5985],
             script_output="smb-os-discovery: OS: Windows Server 2019 Standard")
check("Windows AD 판정", r.os_class==OSClass.WINDOWS_AD)
check("DC 플래그", r.is_domain_controller)
check("AD 확신도 높음", r.confidence>=0.85)
# Windows 비AD
r = classify([135,139,445,3389], banners={445:"microsoft-ds"})
check("Windows(비AD) 판정", r.os_class==OSClass.WINDOWS)
# SSH on Windows 함정 (배너가 Windows 명시 → Linux 로 오판 금지)
r = classify([22,445,3389,5985], banners={22:"OpenSSH for_Windows_8.1"})
check("Windows용 SSH 오판 방지", r.os_class in (OSClass.WINDOWS, OSClass.WINDOWS_AD))
# 모호 (포트 1개)
r = classify([80])
check("모호 → 확신도 낮음/추정", r.tag=="〔추정〕")

print("\n=== 감사 회귀 테스트 (발견 A~D) ===")
# A: hydra -p 는 비밀번호 → 포트 오탐 금지
r = cv.validate("hydra -l admin -p 999999 -t 4 10.129.1.5 ssh")
check("A: hydra -p 숫자비번 포트오탐 없음", not any(i.code=="PORT" for i in r.errors))
# A: 스캐너는 여전히 포트 검증
check("A: masscan 포트초과 여전히 에러", any(i.code=="PORT" for i in cv.validate("masscan -p70000 10.129.1.5").errors))
# A: nmap -p- 전체포트 허용
check("A: nmap -p- 정상", not any(i.code=="PORT" for i in cv.validate("nmap -p- 10.129.1.5").errors))
# 체이닝 문법 정상
check("명령 체이닝(&&) 문법 통과", cv.validate("nmap -sV 10.129.1.5 && echo ok").ok)
# B: 포트만으로 과신 금지 (Linux Samba 가 Windows 로 보여도 추정이어야)
r = classify([139,445,80])
check("B: 배너없는 SMB박스 → 추정(과신금지)", r.tag=="〔추정〕")
# C: microsoft-ds 는 Windows 강증거 아님 → 추정
r = classify([445], banners={445:"microsoft-ds"})
check("C: microsoft-ds 강증거 아님(추정)", r.tag=="〔추정〕")
# C: smb-os-discovery 라벨만으로 과신 금지 (출력이 Linux 면 Linux)
r = classify([22,445], banners={22:"OpenSSH Ubuntu"}, script_output="smb-os-discovery attempted")
check("C: Samba+Ubuntu배너 → Linux", r.os_class==OSClass.LINUX)
# D: for_Windows 언더스코어 배너 탐지
r = classify([22], banners={22:"OpenSSH for_Windows_8.1"})
check("D: for_Windows 배너 → Windows", r.os_class in (OSClass.WINDOWS, OSClass.WINDOWS_AD))
check("D: for_Windows 확신도 높음", r.confidence>=0.85)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
