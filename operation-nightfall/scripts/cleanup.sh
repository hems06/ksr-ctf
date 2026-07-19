#!/bin/bash
# ============================================================
# Operation Nightfall — Cleanup Script
# Tears down all containers, removes volumes, and cleans up.
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo ""
echo "======================================================"
echo "  Operation Nightfall — Cleanup"
echo "======================================================"
echo ""

cd "$PROJECT_DIR"

echo "[*] Stopping containers..."
docker compose down --remove-orphans 2>/dev/null || true

echo "[*] Removing volumes..."
docker compose down -v 2>/dev/null || true

echo "[*] Removing built images..."
docker compose down --rmi local 2>/dev/null || true

echo "[*] Pruning dangling images..."
docker image prune -f 2>/dev/null || true

echo "[*] Removing .env file (if generated)..."
[ -f .env ] && rm -f .env && echo "  Removed .env" || echo "  No .env to remove"

echo ""
echo "======================================================"
echo "  ✓ Cleanup complete"
echo "======================================================"
echo ""
echo "To redeploy, run:"
echo "  cp .env.example .env"
echo "  python scripts/generate_flag.py --write"
echo "  docker compose up -d --build"
echo ""
