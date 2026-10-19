#!/usr/bin/env bash
# ARTEX 한국어판(jiwoochris/artex-ko) 설치·실행 — Kali(WSL 포함)에서 실행.
# 고정한 한국어판 소스를 빌드하고 PostgreSQL만 컨테이너로 쓴다.
#
#   bash scripts/artex.sh setup    # 클론·빌드·DB 준비
#   bash scripts/artex.sh run      # 준비가 없으면 setup 뒤 실행 → localhost:8787
#
# 문서: docs/ARTEX.md
set -euo pipefail

ARTEX_HOME="${ARTEX_HOME:-$HOME/artex-ko}"
ARTEX_REPO="${ARTEX_REPO:-https://github.com/jiwoochris/artex-ko.git}"
ARTEX_REF="${ARTEX_REF:-310fbb5789331ea8208c864dcd880dfed2d8dfdf}"   # 2026-10-10 빌드 확인 커밋
PG_NAME=artex-pg
PG_PORT=5433

pg_up() {
  docker info >/dev/null 2>&1 || { echo "Docker daemon access is required" >&2; exit 1; }
  if ! docker ps -a --format '{{.Names}}' | grep -qx "$PG_NAME"; then
    docker run -d --name "$PG_NAME" --restart unless-stopped \
      -e POSTGRES_USER=artex -e POSTGRES_DB=artex \
      -e POSTGRES_PASSWORD="$(openssl rand -hex 16)" \
      -p "127.0.0.1:$PG_PORT:5432" -v artex-pgdata:/var/lib/postgresql/data \
      postgres:16-alpine >/dev/null
  fi
  if [[ "$(docker inspect -f '{{.State.Running}}' "$PG_NAME")" != "true" ]]; then
    docker start "$PG_NAME" >/dev/null
  fi
  for _ in $(seq 1 30); do
    docker exec "$PG_NAME" pg_isready -q -U artex -d artex && return
    sleep 1
  done
  echo "PostgreSQL did not become ready within 30 seconds" >&2
  exit 1
}

setup() {
  if [[ -d "$ARTEX_HOME/.git" ]]; then
    [[ -z "$(git -C "$ARTEX_HOME" status --porcelain)" ]] ||
      { echo "ARTEX checkout has local changes: $ARTEX_HOME" >&2; exit 1; }
    [[ "$(git -C "$ARTEX_HOME" config --get remote.origin.url)" == "$ARTEX_REPO" ]] ||
      { echo "ARTEX checkout remote differs; set ARTEX_REPO explicitly" >&2; exit 1; }
  else
    git clone "$ARTEX_REPO" "$ARTEX_HOME"
  fi
  git -C "$ARTEX_HOME" fetch -q origin
  git -C "$ARTEX_HOME" checkout -q "$ARTEX_REF"

  # GOTOOLCHAIN=auto obtains the go.mod-required version when Kali's Go is older.
  command -v go >/dev/null || sudo apt-get install -y golang-go
  command -v npm >/dev/null || sudo apt-get install -y nodejs npm
  command -v docker >/dev/null || { echo "docker 가 필요합니다" >&2; exit 1; }

  cd "$ARTEX_HOME"
  (cd web && npm ci --include=dev && npm run build:static)
  rm -rf server/webui/dist && mkdir -p server/webui/dist && cp -a web/out/. server/webui/dist/
  CGO_ENABLED=0 GOTOOLCHAIN=auto go build -tags embedui -o artex ./cmd/artex

  pg_up
  # DB password stays in Docker. Do not overwrite a user-managed config.json.
  local pw
  pw=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$PG_NAME" | sed -n 's/^POSTGRES_PASSWORD=//p')
  if [[ ! -f config.json ]]; then
    (umask 077; printf '{"database":{"host":"127.0.0.1","port":%s,"user":"artex","password":"%s","dbname":"artex","sslmode":"disable"}}\n' \
      "$PG_PORT" "$pw" > config.json)
  fi
  echo "[artex] 설치 완료 → bash scripts/artex.sh run"
}

run() {
  [[ -x "$ARTEX_HOME/artex" && -f "$ARTEX_HOME/config.json" ]] || setup
  pg_up
  cd "$ARTEX_HOME"
  # 127.0.0.1 바인딩: VPN 상대 머신·tailnet 에서 UI 로 들어오지 못하게
  exec ./start.sh -addr 127.0.0.1:8787 "$@"
}

case "${1:-}" in
  setup) setup ;;
  run) shift; run "$@" ;;
  *) echo "사용법: $0 setup | run" >&2; exit 2 ;;
esac
