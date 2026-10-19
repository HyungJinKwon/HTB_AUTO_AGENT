# 실행: htb-agent 디렉토리에서  python3 tests/test_approval.py
import sys
sys.path.insert(0, "src")
from htb_agent.approval import explain_command

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== 옵션-값 페어링 (안전) ===")
ex = explain_command("nmap -sV -oX - 10.129.1.5")
check("바이너리", "바이너리 : nmap" in ex)
check("-oX 값(-) 페어링", "-oX -" in ex)
check("타겟 IP 는 파라미터(오인 방지)", "파라미터 : 10.129.1.5" in ex)
check("부울 -sV 는 단독 옵션", "-sV" in ex.split("옵션")[1].split("파라미터")[0])

ex2 = explain_command("gobuster dir -u http://10.129.1.5 -w list.txt")
check("-u 값 페어링", "-u http://10.129.1.5" in ex2)
check("-w 값 페어링", "-w list.txt" in ex2)

ex3 = explain_command("msfvenom LHOST=10.10.14.5 LPORT=443 -f elf")
check("환경변수형 인자 표기", "LHOST=10.10.14.5" in ex3)
check("-f 는 화이트리스트 밖 → 단독", "-f" in ex3)

ex4 = explain_command("nmap -Pn -p- 10.129.1.5")
check("-p- 결합형은 단독 + IP 파라미터", "-p-" in ex4 and "파라미터 : 10.129.1.5" in ex4)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
