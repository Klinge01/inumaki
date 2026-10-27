#!/usr/bin/env bash
# Plan 4a Task 8 (M4 spec §16.7): the Kiji model as sanitizer and as verifier,
# on both corpora, against the shipped support-email configuration. Writes
# reports to $OUT and prints a Markdown table.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=${OUT:-docs/quality}
cargo build --release -q -p inumaki-cli
BIN=target/release/inumaki
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
cat configs/default.toml - > "$TMP/kiji.toml" <<'TOML'

[ner.kiji]
model = "kiji-pii"
threshold = 0.5
labels = [
  { label = "NAME", kind = "PERSON" },
  { label = "FIRSTNAME", kind = "PERSON" },
  { label = "SURNAME", kind = "PERSON" },
  { label = "ADDRESS", kind = "STREET_ADDRESS" },
  { label = "STREET", kind = "STREET_ADDRESS" },
  { label = "CITY", kind = "CITY" },
  { label = "COMPANYNAME", kind = "ORGANIZATION", threshold = 0.6 },
  { label = "EMAIL", kind = "EMAIL" },
  { label = "PHONENUMBER", kind = "PHONE" },
  { label = "IBAN", kind = "IBAN" },
  { label = "ZIP", kind = "POSTAL_CODE" },
  { label = "DATEOFBIRTH", kind = "DATE_OF_BIRTH" },
]

# Kiji as the verifier's independent re-scan (replaces mbert-ner-hrl)
[profiles.kiji-verifier]
extends = "support-email"
ner_verifier = "kiji"
[profiles.kiji-verifier.verifier]
retry_profile = "kiji-verifier-strict"
[profiles.kiji-verifier-strict]
extends = "kiji-verifier"
default_min_confidence = 0.4
escalate_below = 0.4
[profiles.kiji-verifier-strict.entities]
CITY            = { action = "tokenize", min_confidence = 0.40 }
POSTAL_CODE     = { action = "tokenize", min_confidence = 0.40 }
ORGANIZATION    = { action = "tokenize", min_confidence = 0.40 }
URL             = { action = "tokenize", min_confidence = 0.40 }
DATE            = { action = "tokenize", min_confidence = 0.40 }

# Kiji as the sanitizer (GLiNER stays the verifier through gliner_verifier)
[profiles.kiji-sanitizer]
extends = "support-email"
ner_sanitizer = "kiji"
ner_verifier = "gliner_verifier"
[profiles.kiji-sanitizer.verifier]
retry_profile = "kiji-sanitizer-strict"
[profiles.kiji-sanitizer-strict]
extends = "kiji-sanitizer"
default_min_confidence = 0.4
escalate_below = 0.4
[profiles.kiji-sanitizer-strict.entities]
CITY            = { action = "tokenize", min_confidence = 0.40 }
POSTAL_CODE     = { action = "tokenize", min_confidence = 0.40 }
ORGANIZATION    = { action = "tokenize", min_confidence = 0.40 }
URL             = { action = "tokenize", min_confidence = 0.40 }
DATE            = { action = "tokenize", min_confidence = 0.40 }
TOML
for profile in support-email kiji-verifier kiji-sanitizer; do
  "$BIN" --config "$TMP/kiji.toml" eval --profile "$profile" --json --report-json "$OUT/2026-09-28-4a-kiji-$profile.json" > /dev/null
  "$BIN" --config "$TMP/kiji.toml" eval --profile "$profile" --held-out --json --report-json "$OUT/2026-09-28-4a-kiji-held-out-$profile.json" > /dev/null
  "$BIN" --config "$TMP/kiji.toml" bench --profile "$profile" | tee "$OUT/2026-09-28-4a-kiji-bench-$profile.txt"
done
python3 - "$OUT" <<'PY'
import json, sys, os
out = sys.argv[1]
print("| profile | corpus | PERSON recall | PERSON precision | STREET recall | accepted leak | block | verifier FN | verifier FP | p50 ms |")
print("|---|---|---|---|---|---|---|---|---|---|")
for profile in ["support-email", "kiji-verifier", "kiji-sanitizer"]:
    for corpus, name in [("tuning", f"2026-09-28-4a-kiji-{profile}.json"), ("held-out", f"2026-09-28-4a-kiji-held-out-{profile}.json")]:
        r = json.load(open(os.path.join(out, name))); k = r["per_kind"]
        rec = lambda x: k[x]["gold_found"] / k[x]["gold"] if x in k and k[x]["gold"] else 0
        prec = lambda x: k[x]["detected_correct"] / k[x]["detected"] if x in k and k[x]["detected"] else 0
        al = r["accepted_leak_docs"] / max(r["pass_docs"], 1); bl = (r["blocked_docs"] + r["uncertain_docs"]) / r["docs"]
        fn = r["verifier_false_negatives"] / max(r["verifier_broken_trials"], 1); fp = r["verifier_false_positives"] / max(r["verifier_clean_trials"], 1)
        print(f"| {profile} | {corpus} | {rec('PERSON'):.1%} | {prec('PERSON'):.1%} | {rec('STREET_ADDRESS'):.1%} | {al:.2%} | {bl:.2%} | {fn:.1%} | {fp:.1%} | {r['latency_ms']['p50']:.1f} |")
PY
