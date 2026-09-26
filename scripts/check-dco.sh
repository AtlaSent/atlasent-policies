#!/usr/bin/env bash
# Fail unless every commit in BASE..HEAD carries a Signed-off-by line (DCO).
#   scripts/check-dco.sh <base-sha> <head-sha>
set -euo pipefail
base="$1"; head="$2"
missing=0
for c in $(git rev-list --no-merges "$base..$head"); do
  if ! git log -1 --format=%B "$c" | grep -qE '^Signed-off-by: .+ <.+@.+>$'; then
    echo "::error::commit $(git log -1 --format='%h %s' "$c") is missing a DCO Signed-off-by line (use git commit -s)"
    missing=1
  fi
done
[ "$missing" -eq 0 ] && echo "dco: all commits signed off"
exit "$missing"
