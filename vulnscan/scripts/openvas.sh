#!/usr/bin/env bash
# Manage the Greenbone Community Edition (OpenVAS) stack.
#   bash scripts/openvas.sh up        # download official compose file, start, set admin password
#   bash scripts/openvas.sh status
#   bash scripts/openvas.sh down
# The first start syncs vulnerability feeds: allow 30-60 minutes before the first scan.
set -euo pipefail
cd "$(dirname "$0")/.."
DIR=deploy/openvas
PROJECT=greenbone-community-edition
COMPOSE_URL=https://greenbone.github.io/docs/latest/_static/docker-compose.yml
GVM_PASSWORD=$(grep -E '^GVM_PASSWORD=' .env 2>/dev/null | cut -d= -f2- || true)
GVM_PASSWORD=${GVM_PASSWORD:-admin}

case "${1:-}" in
  up)
    mkdir -p "$DIR"
    [ -f "$DIR/docker-compose.yml" ] || curl -fsSL "$COMPOSE_URL" -o "$DIR/docker-compose.yml"
    docker compose -p "$PROJECT" -f "$DIR/docker-compose.yml" pull
    docker compose -p "$PROJECT" -f "$DIR/docker-compose.yml" up -d
    echo "waiting for gvmd…"; sleep 60
    docker compose -p "$PROJECT" -f "$DIR/docker-compose.yml" exec -u gvmd gvmd \
      gvmd --user=admin --new-password="$GVM_PASSWORD" || echo "(set password later: bash scripts/openvas.sh up again)"
    echo "✔ OpenVAS starting. Web UI: http://127.0.0.1:9392 (admin / your GVM_PASSWORD)"
    echo "  Now restart VulnScan with OpenVAS attached:"
    echo "  docker compose -f docker-compose.yml -f docker-compose.openvas.yml up -d"
    ;;
  status) docker compose -p "$PROJECT" -f "$DIR/docker-compose.yml" ps ;;
  down)   docker compose -p "$PROJECT" -f "$DIR/docker-compose.yml" down ;;
  *) echo "usage: $0 up|status|down"; exit 1 ;;
esac
