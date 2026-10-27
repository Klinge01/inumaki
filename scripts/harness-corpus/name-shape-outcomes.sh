#!/usr/bin/env bash
# Per-id outcomes of the name-shape cases (plan 2026-10-12, review N1): one
# eval per case, printed as `id outcome` (pass, uncertain, blocked; `+residue`
# when released text kept a gold value). `--compare BEFORE AFTER` exits 1 when
# an id is worse in AFTER (pass < uncertain < blocked < any residue).
#   scripts/harness-corpus/name-shape-outcomes.sh PROFILE [CONFIG] [BINARY]
#   CORPUS=FILE ... PROFILE [CONFIG] [BINARY]   (default: harness/name-shapes.jsonl)
#   scripts/harness-corpus/name-shape-outcomes.sh --compare BEFORE AFTER
set -euo pipefail
cd "$(dirname "$0")/../.."
if [ "${1:-}" = "--compare" ]; then
  exec python3 - "$2" "$3" <<'EOF2'
import sys
rank = {"pass": 0, "uncertain": 1, "blocked": 2}
def load(path):
    out = {}
    for line in open(path):
        i, o = line.split()
        out[i] = (3 if o.endswith("+residue") else rank[o], o)
    return out
a, b = load(sys.argv[1]), load(sys.argv[2])
worse = [f"{i}: {a[i][1]} -> {b[i][1] if i in b else 'missing'}" for i in a if i not in b or b[i][0] > a[i][0]]
print("\n".join(worse) or "no id worse")
sys.exit(1 if worse else 0)
EOF2
fi
PROFILE=$1
CONFIG=${2:-}
BIN=${3:-target/release/inumaki}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
while IFS= read -r line; do
  id=$(printf '%s' "$line" | jq -r .id)
  printf '%s\n' "$line" > "$TMP/one.jsonl"
  "$BIN" ${CONFIG:+--config "$CONFIG"} --profile "$PROFILE" eval --corpus "$TMP/one.jsonl" --no-verifier-trials --json 2>/dev/null \
    | jq -r --arg id "$id" '$id + " " + (if .blocked_docs > 0 then "blocked" elif .uncertain_docs > 0 then "uncertain" else "pass" end) + (if .docs_with_leak > 0 then "+residue" else "" end)'
done < "${CORPUS:-crates/inumaki-eval/harness/name-shapes.jsonl}"
