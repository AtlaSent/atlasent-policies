#!/usr/bin/env bash
# Fail if anything in this public repository looks internal: AtlaSent project
# refs or hosts, real-looking API keys or permit tokens, service-role secrets,
# or references to internal-only repositories.
#
#   scripts/check-public-safety.sh              scan the repository
#   scripts/check-public-safety.sh --self-test  prove each pattern fires
set -euo pipefail

patterns=(
  'kttccumlnmdtupgbyfue|ihghhasvxtltlbizvkqy|lwnqpmnxpeyhpxvastku|pvmnefndvqsjoydxhqhg|zqvcefarqlqvfpomzfhy'
  '[a-z0-9]{20}\.supabase\.co'
  'ask_(live|test)_[A-Za-z0-9]{12,}'
  'pt\.v[0-9]+\.[A-Za-z0-9_-]{20,}'
  'service_role|SUPABASE_SERVICE_ROLE_KEY|sb_secret_'
  'atlasent-internal|atlasent-control-plane'
  'eyJhbGciOi[A-Za-z0-9_-]{10,}'
  'github(usercontent)?\.com/Atlasent/atlasent-(api|console|docs|internal|examples|control-plane)'
  '\b(CROSS|IMPL)-[0-9]{3}\b'
)

scan() {
  local root="$1" bad=0
  for pat in "${patterns[@]}"; do
    if grep -rEn --exclude-dir=.git --exclude=check-public-safety.sh -e "$pat" "$root"; then
      echo "::error::public-safety: pattern matched: $pat" >&2
      bad=1
    fi
  done
  return $bad
}

if [ "${1:-}" = "--self-test" ]; then
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  samples=(
    'url: https://kttccumlnmdtupgbyfue.supabase.co'
    'url: https://abcdefghijklmnopqrst.supabase.co'
    'key: ask_live_AbCdEf123456789'
    'permit: pt.v4.eyJvcmciOiJhYmMiLCJleHAiOjF9'
    'env: SUPABASE_SERVICE_ROLE_KEY'
    'see atlasent-internal/planning'
    'jwt: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
    'schema: https://raw.githubusercontent.com/Atlasent/atlasent-api/main/x.json'
    'decided in CROSS-011'
  )
  for s in "${samples[@]}"; do
    printf '%s\n' "$s" > "$tmp/sample.yaml"
    if scan "$tmp" >/dev/null 2>&1; then echo "self-test FAILED: not caught: $s"; exit 1; fi
  done
  printf 'action_type: data.export\nrules: { templates: [{ decision: allow }] }\n' > "$tmp/sample.yaml"
  scan "$tmp" >/dev/null 2>&1 || { echo "self-test FAILED: clean file flagged"; exit 1; }
  echo "self-test: ${#samples[@]} leak samples caught, clean file passes"
  exit 0
fi

scan "${1:-.}" && echo "public-safety: clean"
