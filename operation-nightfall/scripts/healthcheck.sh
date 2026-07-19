#!/bin/bash
# ============================================================
# Operation Nightfall — Healthcheck Script
# Verifies all services are running and reachable.
# ============================================================

set -e

TARGET="${1:-http://localhost:8080}"
PASS=0
FAIL=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo "======================================================"
echo "  Operation Nightfall — Health Check"
echo "======================================================"
echo "  Target: ${TARGET}"
echo "======================================================"
echo ""

check() {
    local name="$1"
    local result="$2"
    
    if [ "$result" -eq 0 ]; then
        echo -e "  ${GREEN}✓${NC} ${name}"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${NC} ${name}"
        FAIL=$((FAIL + 1))
    fi
}

# --- Check Gateway ---
echo "Gateway Service:"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/" 2>/dev/null || echo "000")
[ "$HTTP_CODE" = "200" ] && check "Landing page (HTTP 200)" 0 || check "Landing page (HTTP ${HTTP_CODE})" 1

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/status" 2>/dev/null || echo "000")
[ "$HTTP_CODE" = "200" ] && check "Status page (HTTP 200)" 0 || check "Status page (HTTP ${HTTP_CODE})" 1

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/login" 2>/dev/null || echo "000")
[ "$HTTP_CODE" = "200" ] && check "Login page (HTTP 200)" 0 || check "Login page (HTTP ${HTTP_CODE})" 1

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/healthz" 2>/dev/null || echo "000")
[ "$HTTP_CODE" = "200" ] && check "Gateway healthz (HTTP 200)" 0 || check "Gateway healthz (HTTP ${HTTP_CODE})" 1
echo ""

# --- Check SSTI ---
echo "Vulnerability Checks:"
SSTI_RESULT=$(curl -s "${TARGET}/status?service={{7*7}}" 2>/dev/null | grep -c "49" || echo "0")
[ "$SSTI_RESULT" -gt 0 ] && check "SSTI vulnerability present" 0 || check "SSTI vulnerability present" 1
echo ""

# --- Check Login ---
echo "Authentication:"
LOGIN_RESULT=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${TARGET}/login" \
    -d "username=developer&password=N0v4D3v2024" \
    -H "Content-Type: application/x-www-form-urlencoded" 2>/dev/null || echo "000")
[ "$LOGIN_RESULT" = "302" ] && check "Developer login (redirect 302)" 0 || check "Developer login (HTTP ${LOGIN_RESULT})" 1
echo ""

# --- Docker services ---
echo "Docker Services:"
if command -v docker &>/dev/null; then
    for svc in gateway internal-api admin-bot postgres redis; do
        RUNNING=$(docker compose ps --format json 2>/dev/null | grep -c "\"$svc\"" || echo "0")
        if [ "$RUNNING" -gt 0 ]; then
            check "Container: ${svc}" 0
        else
            # Try without compose
            RUNNING=$(docker ps --format "{{.Names}}" 2>/dev/null | grep -c "$svc" || echo "0")
            [ "$RUNNING" -gt 0 ] && check "Container: ${svc}" 0 || check "Container: ${svc}" 1
        fi
    done
else
    echo -e "  ${YELLOW}⚠${NC} Docker CLI not available — skipping container checks"
fi
echo ""

# --- Summary ---
TOTAL=$((PASS + FAIL))
echo "======================================================"
echo -e "  Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC} (${TOTAL} total)"
echo "======================================================"

if [ "$FAIL" -gt 0 ]; then
    echo -e "\n  ${RED}⚠ Some checks failed. Review the output above.${NC}\n"
    exit 1
else
    echo -e "\n  ${GREEN}✓ All checks passed! Challenge is ready.${NC}\n"
    exit 0
fi
