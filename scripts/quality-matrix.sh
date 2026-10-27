#!/usr/bin/env bash
# Plan 1 Task 4: measure detector/verifier variants on the tuning corpus and the
# held-out corpus for the support-email and strict profiles. Writes JSON reports
# and a Markdown table under $OUT (default /tmp/inumaki-m4-matrix).
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=${OUT:-/tmp/inumaki-m4-matrix}
mkdir -p "$OUT"
cargo build --release -q -p inumaki-cli
BIN=target/release/inumaki

# variant NAME GLINER_THRESHOLD LABELS(A|B) TC_THRESHOLD
variant() {
  local name=$1 g=$2 labels=$3 tc=$4 cfg
  cfg="$OUT/$name.toml"
  python3 - "$g" "$labels" "$tc" > "$cfg" <<'PY'
import sys
g, labels, tc = sys.argv[1:]
s = open('configs/default.toml', encoding='utf-8').read()
old = '[ner.gliner]\nmodel = "gliner-x-small"\nthreshold = 0.5'
assert old in s
s = s.replace(old, f'[ner.gliner]\nmodel = "gliner-x-small"\nthreshold = {g}')
if labels == 'B':
    old = '  { label = "person", kind = "PERSON" },\n  { label = "street address", kind = "STREET_ADDRESS" },'
    assert old in s
    s = s.replace(old, '  { label = "person", kind = "PERSON" },\n  { label = "name", kind = "PERSON" },\n  { label = "full name", kind = "PERSON" },\n  { label = "street address", kind = "STREET_ADDRESS" },')
old = '[ner.token_classifier]\nmodel = "mbert-ner-hrl"\nthreshold = 0.5'
assert old in s
s = s.replace(old, f'[ner.token_classifier]\nmodel = "mbert-ner-hrl"\nthreshold = {tc}')
sys.stdout.write(s)
PY
  for profile in support-email strict; do
    "$BIN" --config "$cfg" eval --profile "$profile" --json --report-json "$OUT/$name-$profile-tuning.json" > /dev/null
    "$BIN" --config "$cfg" eval --profile "$profile" --held-out --json --report-json "$OUT/$name-$profile-heldout.json" > /dev/null
    echo "done $name $profile"
  done
}

for g in 0.5 0.3; do
  for L in A B; do
    for tc in 0.5 0.4; do
      variant "g$g-L$L-tc$tc" "$g" "$L" "$tc"
    done
  done
done

python3 - "$OUT" <<'PY' | tee "$OUT/matrix.md"
import json, glob, os, sys
out = sys.argv[1]
rows = []
for p in sorted(glob.glob(os.path.join(out, '*-*-*.json'))):
    r = json.load(open(p))
    name = os.path.basename(p)[:-5]
    # rsplit('-', 2) would mis-split "support-email" (it has its own hyphen), so
    # peel off the known corpus and profile suffixes by name instead.
    for corpus in ('tuning', 'heldout'):
        if name.endswith('-' + corpus):
            rest = name[: -(len(corpus) + 1)]
            break
    else:
        raise ValueError(f"unrecognized corpus suffix: {name}")
    for profile in ('support-email', 'strict'):
        if rest.endswith('-' + profile):
            variant = rest[: -(len(profile) + 1)]
            break
    else:
        raise ValueError(f"unrecognized profile suffix: {rest}")
    acc = r['pass_docs']
    alr = 'N/A' if acc == 0 else f"{100*r['accepted_leak_docs']/acc:.2f}%"
    block = 100*(r['blocked_docs']+r['uncertain_docs'])/r['docs']
    fp = 'N/A' if r['verifier_clean_trials']==0 else f"{100*r['verifier_false_positives']/r['verifier_clean_trials']:.2f}%"
    def recall(k):
        s = r['per_kind'].get(k)
        return 'N/A' if not s or s['gold']==0 else f"{100*s['gold_found']/s['gold']:.1f}%"
    rows.append((variant, profile, corpus, alr, f"{block:.2f}%", fp, recall('PERSON'), recall('STREET_ADDRESS'), f"{r['latency_ms']['p50']:.1f}"))
print('| variant | profile | corpus | accepted leak | block rate | verifier FP | PERSON recall | STREET recall | p50 ms |')
print('|---|---|---|---|---|---|---|---|---|')
for row in rows:
    print('| ' + ' | '.join(row) + ' |')
PY
