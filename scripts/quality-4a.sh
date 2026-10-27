#!/usr/bin/env bash
# Plan 4a Task 9: every report M4 spec §13.1 asks for, in one run, on the reference machine.
# Writes docs/quality/$STAMP-*.json and the bench text, then prints one table row per report.
# Each eval takes 3-6 minutes; the whole script runs for well over an hour.
# Print the table for an existing stamp only: TABLE_ONLY=1 STAMP=2026-09-28-4a-before scripts/quality-4a.sh
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=${OUT:-docs/quality}
STAMP=${STAMP:-2026-10-09-4a-after}
if [ -z "${TABLE_ONLY:-}" ]; then
  cargo build --release -q -p inumaki-cli
  BIN=target/release/inumaki
  SEQ=crates/inumaki-eval/targets/sequence.toml
  # One-line variants of the default config: each opt-in cross-request flag on, and independent surface forms.
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT
  sed 's/^surnames_across_requests = false/surnames_across_requests = true/' configs/default.toml > "$TMP/surnames.toml"
  sed 's/^first_names_across_requests = false/first_names_across_requests = true/' configs/default.toml > "$TMP/first-names.toml"
  sed 's/^surface_form = "derived"/surface_form = "independent"/' configs/default.toml > "$TMP/independent.toml"
  grep -q '^surnames_across_requests = true' "$TMP/surnames.toml"
  grep -q '^first_names_across_requests = true' "$TMP/first-names.toml"
  grep -q '^surface_form = "independent"' "$TMP/independent.toml"
  for p in support-email strict thorough; do
    "$BIN" eval --profile "$p" --json --report-json "$OUT/$STAMP-$p.json" > /dev/null
  done
  "$BIN" eval --profile offline --json --report-json "$OUT/$STAMP-offline.json" > /dev/null
  for p in support-email strict; do
    "$BIN" eval --profile "$p" --held-out --json --report-json "$OUT/$STAMP-held-out-$p.json" > /dev/null
    "$BIN" eval --profile "$p" --via-service --json --report-json "$OUT/$STAMP-service-$p.json" > /dev/null
    "$BIN" eval --profile "$p" --held-out --via-service --json --report-json "$OUT/$STAMP-service-held-out-$p.json" > /dev/null
    "$BIN" eval --profile "$p" --sequences --targets "$SEQ" --json --report-json "$OUT/$STAMP-sequence-$p.json" > /dev/null \
      || echo "sequence $p exit $? (default config: expected 0)"
    # The opt-in flags are expected to miss the sequence targets (exit 5): their wrong-link rates are the measurement.
    for flag in surnames first-names; do
      "$BIN" --config "$TMP/$flag.toml" eval --profile "$p" --sequences --targets "$SEQ" --json \
        --report-json "$OUT/$STAMP-sequence-$p-$flag.json" > /dev/null || echo "sequence $p $flag exit $?"
    done
    "$BIN" eval --profile "$p" --track tool-json --via-service --json --report-json "$OUT/$STAMP-tool-json-$p.json" > /dev/null
    "$BIN" eval --profile "$p" --track tool-json --held-out --via-service --json --report-json "$OUT/$STAMP-tool-json-held-out-$p.json" > /dev/null
    "$BIN" eval --profile "$p" --cases-only --targets crates/inumaki-eval/targets/safety.toml || echo "safety $p exit $?"
  done
  # Surface form: the coreference proxy with independent tokens (support-email, both corpora).
  SURF=${STAMP%-after}-surface-independent
  "$BIN" --config "$TMP/independent.toml" eval --profile support-email --json --report-json "$OUT/$SURF-support-email.json" > /dev/null
  "$BIN" --config "$TMP/independent.toml" eval --profile support-email --held-out --json --report-json "$OUT/$SURF-held-out-support-email.json" > /dev/null
  "$BIN" bench --profile support-email | tee "$OUT/$STAMP-bench-support-email.txt"
fi
python3 - "$OUT" "$STAMP" <<'PY'
import json, sys, os
out, stamp = sys.argv[1:]
def row(name, r):
    k = r["per_kind"]
    rec = lambda x: k[x]["gold_found"] / k[x]["gold"] if x in k and k[x]["gold"] else float("nan")
    al = r["accepted_leak_docs"] / max(r["pass_docs"], 1)
    bl = (r["blocked_docs"] + r["uncertain_docs"]) / max(r["docs"], 1)
    fp = r["verifier_false_positives"] / r["verifier_clean_trials"] if r["verifier_clean_trials"] else float("nan")
    l = r.get("links") or {}
    wr = l.get("wrong_restorations", "-")
    co = f"{l['coref_recoverable_docs']}/{l['coref_docs']}" if "coref_docs" in l else "-"
    return (f"| {name} | {r['docs']} | {al:.2%} ({r['accepted_leak_docs']}/{r['pass_docs']}) | {bl:.2%} | {fp:.2%} "
            f"| {rec('PERSON'):.1%} | {rec('STREET_ADDRESS'):.1%} | {wr} | {co} | {r['latency_ms']['p50']:.1f} |")
print("| report | docs | accepted leak | block | verifier FP | PERSON recall | STREET recall | wrong restorations | coref recoverable | p50 ms |")
print("|---|---|---|---|---|---|---|---|---|---|")
for f in sorted(os.listdir(out)):
    if f.startswith(stamp + "-") and f.endswith(".json"):
        print(row(f[len(stamp) + 1:-5], json.load(open(os.path.join(out, f)))))
PY
