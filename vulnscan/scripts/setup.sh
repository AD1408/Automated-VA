#!/usr/bin/env bash
# One-time setup. Run from the project folder inside WSL Ubuntu:  bash scripts/setup.sh
set -euo pipefail
cd "$(dirname "$0")/.."

command -v docker >/dev/null || { echo "Docker not found. Enable WSL integration in Docker Desktop."; exit 1; }

if [ ! -f .env ]; then
  cp .env.example .env
  rand() { head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32; }
  sed -i "s/^ZAP_API_KEY=.*/ZAP_API_KEY=$(rand)/" .env
  sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(rand)/" .env
  echo "✔ created .env (random ZAP/Postgres secrets). Add HF_TOKEN later for Prompt Guard 2."
fi

echo "▶ building images (first build downloads ~3 GB, takes 10-20 min)…"
docker compose build

echo "▶ starting the stack + practice targets…"
docker compose --profile targets up -d

echo "▶ downloading the local LLM in the background (see: docker compose logs -f ollama-pull)"
echo
echo "✅ Open http://localhost:8000"
echo "   Try:  Website  -> http://juice-shop:3000"
echo "         AI bot   -> http://demo-chat:8090/chat"
