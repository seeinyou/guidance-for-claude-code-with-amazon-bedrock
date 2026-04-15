#!/usr/bin/env bash
# Check quota usage via the /check and /tvm API endpoints.
# Usage:
#   ./scripts/check-quota.sh              # check quota (GET /check)
#   ./scripts/check-quota.sh --tvm        # call TVM (POST /tvm), show quota-related fields
#   ./scripts/check-quota.sh --raw        # print raw JSON response
#
# Reads config from ~/claude-code-with-bedrock/config.json to find the API endpoint,
# and retrieves the cached id_token for authentication.

set -euo pipefail

# ---------- defaults ----------
MODE="check"
RAW=false

for arg in "$@"; do
  case "$arg" in
    --tvm)  MODE="tvm" ;;
    --raw)  RAW=true ;;
    -h|--help)
      echo "Usage: $0 [--tvm] [--raw]"
      echo "  --tvm   Call POST /tvm instead of GET /check"
      echo "  --raw   Print raw JSON response"
      exit 0
      ;;
  esac
done

# ---------- resolve config ----------
CONFIG="$HOME/claude-code-with-bedrock/config.json"
if [[ ! -f "$CONFIG" ]]; then
  echo "Error: config not found at $CONFIG" >&2
  exit 1
fi

# Auto-detect profile (first key in old-format config, or first profile in new format)
PROFILE=$(python3 -c "
import json, sys
with open('$CONFIG') as f:
    c = json.load(f)
if 'profiles' in c:
    print(next(iter(c['profiles'])))
else:
    print(next(iter(c)))
" 2>/dev/null)

ENDPOINT=$(python3 -c "
import json, sys
with open('$CONFIG') as f:
    c = json.load(f)
p = c.get('profiles', c).get('$PROFILE', c.get('$PROFILE', {}))
# tvm_endpoint and quota_api_endpoint share the same base URL
print(p.get('tvm_endpoint') or p.get('quota_api_endpoint') or '')
" 2>/dev/null)

if [[ -z "$ENDPOINT" ]]; then
  echo "Error: no tvm_endpoint or quota_api_endpoint in config for profile '$PROFILE'" >&2
  exit 1
fi

# ---------- get id_token ----------
# Try cached monitoring token from session file first
TOKEN=""
SESSION_FILE="$HOME/.claude-code-session/${PROFILE}-monitoring.json"
if [[ -f "$SESSION_FILE" ]]; then
  TOKEN=$(python3 -c "
import json, sys, time
with open('$SESSION_FILE') as f:
    d = json.load(f)
if d.get('expires', 0) - time.time() > 60:
    print(d['token'])
" 2>/dev/null || true)
fi

# Try keyring if session file didn't work
if [[ -z "$TOKEN" ]]; then
  TOKEN=$(python3 -c "
import json, sys, time
try:
    import keyring
    data = keyring.get_password('claude-code-with-bedrock', '${PROFILE}-monitoring')
    if data:
        d = json.loads(data)
        if d.get('expires', 0) - time.time() > 60:
            print(d['token'])
except Exception:
    pass
" 2>/dev/null || true)
fi

if [[ -z "$TOKEN" ]]; then
  echo "Error: no valid id_token found. Run the credential provider first to authenticate." >&2
  echo "  Hint: python -m credential_provider --get-monitoring-token" >&2
  exit 1
fi

# ---------- call API ----------
if [[ "$MODE" == "tvm" ]]; then
  RESP=$(curl -s -w "\n%{http_code}" \
    -X POST "${ENDPOINT}/tvm" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -H "X-OTEL-Helper-Status: not-configured")
else
  RESP=$(curl -s -w "\n%{http_code}" \
    -X GET "${ENDPOINT}/check" \
    -H "Authorization: Bearer ${TOKEN}")
fi

# Split body and status code
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')

# ---------- display ----------
if [[ "$RAW" == true ]]; then
  echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"
  echo "(HTTP $HTTP_CODE)"
  exit 0
fi

if [[ "$HTTP_CODE" -ne 200 ]]; then
  echo "API returned HTTP $HTTP_CODE"
  echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"
  exit 1
fi

# Pretty print
python3 -c "
import json, sys

body = json.loads('''${BODY}''')
mode = '${MODE}'

if mode == 'tvm':
    # TVM response
    if 'credentials' in body:
        creds = body['credentials']
        print('TVM: credentials issued')
        print(f'  Expiration:       {creds.get(\"Expiration\", \"?\")}')
        print(f'  Session duration: {body.get(\"session_duration\", \"?\")}s')
        print(f'  Message:          {body.get(\"message\", \"\")}')
    elif 'error' in body:
        print(f'TVM DENIED: {body.get(\"reason\", \"\")}')
        print(f'  {body.get(\"message\", \"\")}')
    sys.exit(0)

# Quota check response
allowed = body.get('allowed')
reason = body.get('reason', '')
enforcement = body.get('enforcement_mode', 'N/A')
message = body.get('message', '')

status = '✓ ALLOWED' if allowed else '✗ BLOCKED'
print(f'{status}  (reason: {reason}, enforcement: {enforcement})')
print(f'  {message}')

usage = body.get('usage')
if usage:
    print()
    print('Usage this month:')
    mt = usage.get('monthly_tokens', 0)
    ml = usage.get('monthly_limit', 0)
    mp = usage.get('monthly_percent', 0)
    print(f'  Monthly tokens: {mt:>12,} / {ml:>12,}  ({mp:.1f}%)')

    dt = usage.get('daily_tokens', 0)
    dl = usage.get('daily_limit')
    dp = usage.get('daily_percent')
    if dl is not None:
        print(f'  Daily tokens:   {dt:>12,} / {dl:>12,}  ({dp:.1f}%)')
    else:
        print(f'  Daily tokens:   {dt:>12,}  (no daily limit)')

    ec = usage.get('estimated_cost', 0)
    mcl = usage.get('monthly_cost_limit')
    mcp = usage.get('monthly_cost_percent')
    if mcl is not None:
        print(f'  Monthly cost:     \${ec:>10,.2f} / \${mcl:>10,.2f}  ({mcp:.1f}%)')
    else:
        print(f'  Monthly cost:     \${ec:>10,.2f}  (no cost limit)')

    dc = usage.get('daily_cost', 0)
    dcl = usage.get('daily_cost_limit')
    dcp = usage.get('daily_cost_percent')
    if dcl is not None:
        print(f'  Daily cost:       \${dc:>10,.2f} / \${dcl:>10,.2f}  ({dcp:.1f}%)')

policy = body.get('policy')
if policy:
    print()
    print(f'Policy: {policy.get(\"type\", \"?\")} / {policy.get(\"identifier\", \"?\")}')

unblock = body.get('unblock_status')
if unblock and unblock.get('is_unblocked'):
    print(f'  ⚠ UNBLOCKED until {unblock.get(\"expires_at\", \"?\")} by {unblock.get(\"unblocked_by\", \"?\")}')
" 2>/dev/null || {
  echo "Parse error — raw response:"
  echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"
}
