#!/bin/bash
# Polls OpenCTI until MITRE ATT&CK import is complete and TAXII 2.1 is live.
# Usage: ./scripts/verify-platform.sh

set -e

# Resolve project root relative to script location (not cwd)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Load token from .env (fatal if missing)
if [ ! -f "$PROJECT_ROOT/.env" ]; then
  echo "ERROR: .env not found. Run ./scripts/setup-env.sh first."
  exit 1
fi
# shellcheck source=/dev/null
source "$PROJECT_ROOT/.env"

# Validate token is set
if [ -z "${OPENCTI_ADMIN_TOKEN:-}" ]; then
  echo "ERROR: OPENCTI_ADMIN_TOKEN not set in .env. Run ./scripts/setup-env.sh to regenerate."
  exit 1
fi

OPENCTI_URL="http://localhost:8080"
TIMEOUT=900          # 15 minutes
START_TIME=$(date +%s)
POLL_N=0

# ── Step 1: Wait for OpenCTI /health (5s retry, respect timeout) ─────────────
echo "[verify-platform] Waiting for OpenCTI at ${OPENCTI_URL}/health ..."
until curl -s "${OPENCTI_URL}/health" 2>/dev/null | grep -qE 'unauthorized|ok'; do
  ELAPSED=$(( $(date +%s) - START_TIME ))
  if [ $ELAPSED -ge $TIMEOUT ]; then
    echo "ERROR: Timeout waiting for OpenCTI health after ${TIMEOUT}s."
    echo "  Check logs: docker compose --profile platform logs opencti"
    exit 1
  fi
  sleep 5
done
echo "[verify-platform] OpenCTI is up. Waiting for MITRE ATT&CK import..."

# ── Step 2: Poll GraphQL for attackPatterns count (30s interval) ─────────────
# Primary approach: pageInfo.globalCount (OpenCTI pagination model)
# Fallback approach: edges | length with first: 500 (if globalCount is null/0)
# Success threshold: > 100 (Enterprise alone has 222+ techniques)
while true; do
  ELAPSED=$(( $(date +%s) - START_TIME ))
  if [ $ELAPSED -ge $TIMEOUT ]; then
    echo ""
    echo "ERROR: 15-minute timeout. MITRE import may still be running."
    echo "  Check logs: docker compose --profile platform logs connector-mitre"
    echo "  Re-run this script when import completes."
    exit 1
  fi

  # Primary: pageInfo.globalCount
  RESPONSE=$(curl -sf -X POST "${OPENCTI_URL}/graphql" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${OPENCTI_ADMIN_TOKEN}" \
    -d '{"query":"{ attackPatterns(first: 1) { pageInfo { globalCount } } }"}' \
    2>/dev/null || echo "")
  COUNT=$(echo "$RESPONSE" | jq -r '.data.attackPatterns.pageInfo.globalCount // 0' 2>/dev/null || echo "0")

  # Fallback: count edges if globalCount unavailable or 0
  if [ "$COUNT" = "0" ] || [ "$COUNT" = "null" ]; then
    RESPONSE2=$(curl -sf -X POST "${OPENCTI_URL}/graphql" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer ${OPENCTI_ADMIN_TOKEN}" \
      -d '{"query":"{ attackPatterns(first: 500) { edges { node { id } } } }"}' \
      2>/dev/null || echo "")
    COUNT=$(echo "$RESPONSE2" | jq '.data.attackPatterns.edges | length' 2>/dev/null || echo "0")
  fi

  POLL_N=$(( POLL_N + 1 ))
  printf "[%d/10+] OpenCTI up, ATT&CK objects: %s\n" "$POLL_N" "$COUNT"

  if [ "${COUNT:-0}" -gt 100 ] 2>/dev/null; then
    echo ""
    echo "[verify-platform] Platform ready. ${COUNT} ATT&CK patterns imported."
    break
  fi

  sleep 30
done

# ── Step 3: Verify TAXII 2.1 endpoint (D-10) ─────────────────────────────────
echo "[verify-platform] Checking TAXII 2.1 endpoint..."
TAXII_HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer ${OPENCTI_ADMIN_TOKEN}" \
  -H "Accept: application/taxii+json;version=2.1" \
  "${OPENCTI_URL}/taxii2/root/collections/")

if [ "$TAXII_HTTP" = "200" ]; then
  echo "[verify-platform] TAXII endpoint: OK (HTTP ${TAXII_HTTP})"
else
  echo "[verify-platform] TAXII endpoint: WARNING (HTTP ${TAXII_HTTP})"
  echo "  TAXII may not be ready. Check: OpenCTI > Data > Data Sharing > TAXII Collections."
fi

echo "[verify-platform] Phase 1 complete."
