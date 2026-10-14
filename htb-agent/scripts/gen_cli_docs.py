#!/usr/bin/env python3
"""README 의 '전체 CLI 옵션' 표를 argparse 정의에서 재생성한다(문서-코드 불일치 방지).

사용:  python3 scripts/gen_cli_docs.py          # README.md 갱신
       python3 scripts/gen_cli_docs.py --check  # 불일치면 종료코드 1(CI·테스트용)
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from htb_agent.main import build_parser  # noqa: E402

START = "<!-- CLI-OPTIONS:START (scripts/gen_cli_docs.py 가 자동 생성 — 직접 수정 금지) -->"
END = "<!-- CLI-OPTIONS:END -->"
README = os.path.join(ROOT, "README.md")


def render_table() -> str:
    rows = ["| 옵션 | 설명 |", "|---|---|"]
    # full=True: README 표는 '전체 CLI 옵션' 레퍼런스이므로 고급 옵션도 실제 설명을 담는다
    # (기본 -h 는 자주 쓰는 것만 보이게 비full 에서 help 를 SUPPRESS 하지만, 표에는 전부 노출).
    for a in build_parser(full=True)._actions:
        opts = [o for o in a.option_strings if o.startswith("--")]
        if not opts or "--help" in opts:
            continue
        name = ", ".join(f"`{o}`" for o in opts)
        if a.metavar:
            name += f" `{a.metavar}`"
        help_ = " ".join((a.help or "").split()).replace("|", "\\|")
        help_ = help_.replace("<", "&lt;").replace(">", "&gt;")   # GitHub 가 HTML 태그로 오인해 숨기지 않도록
        rows.append(f"| {name} | {help_} |")
    return "\n".join(rows)


def build_block() -> str:
    return f"{START}\n{render_table()}\n{END}"


def updated_readme(text: str) -> str:
    block = build_block()
    if START in text and END in text:
        pre = text.split(START, 1)[0]
        post = text.split(END, 1)[1]
        return pre + block + post
    # 최초 삽입: 문서 끝에 섹션 추가
    return text.rstrip() + "\n\n## 전체 CLI 옵션\n\n" + block + "\n"


def main(argv: list[str]) -> int:
    with open(README, encoding="utf-8") as f:
        text = f.read()
    new = updated_readme(text)
    if "--check" in argv:
        if new != text:
            print("README 의 CLI 옵션 표가 코드와 다릅니다 — scripts/gen_cli_docs.py 실행 필요")
            return 1
        print("README CLI 옵션 표: 최신")
        return 0
    with open(README, "w", encoding="utf-8") as f:
        f.write(new)
    print("README CLI 옵션 표 갱신 완료")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
