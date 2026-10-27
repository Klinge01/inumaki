#!/usr/bin/env bash
# List the PERSON spans the engine detects in the harness-static corpus: count,
# confidence range, sources, text, first document id; most frequent first. The
# corpus is public harness text and generated random ids with no identifying
# value, so printing span text here is intended. From the repository root,
# with models pulled and INUMAKI_MODELS_DIR set:
#   scripts/harness-corpus/person-spans.sh [PROFILE] [BINARY] [ORIGIN]
# ORIGIN is `harness-static` (default: the corpus's own origin, as the gate
# runs it) or `free` (what the proxy sends until it passes the origin).
set -euo pipefail
cd "$(dirname "$0")/../.."
PROFILE=${1:-support-email}
BIN=${2:-target/release/inumaki}
ORIGIN=${3:-harness-static}
CORPUS=crates/inumaki-eval/harness/harness-static.jsonl
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
python3 - "$CORPUS" "$TMP" <<'PY'
import json, sys
for n, line in enumerate(open(sys.argv[1], encoding="utf-8")):
    d = json.loads(line)
    open(f"{sys.argv[2]}/{n:04d}.txt", "w", encoding="utf-8").write(d["text"])
    open(f"{sys.argv[2]}/{n:04d}.id", "w").write(d["id"])
PY
for f in "$TMP"/*.txt; do
  "$BIN" --profile "$PROFILE" scan --origin "$ORIGIN" --json "$f" > "${f%.txt}.json"
done
python3 - "$TMP" <<'PY'
import collections, glob, json, sys
rows = collections.defaultdict(list)
for j in sorted(glob.glob(f"{sys.argv[1]}/*.json")):
    doc = open(j[:-5] + ".id").read()
    for s in json.load(open(j)):
        if s["kind"] == "PERSON":
            rows[s["text"]].append((s["confidence"], s["source"], doc))
total = sum(len(v) for v in rows.values())
print(f"{total} PERSON spans, {len(rows)} distinct texts")
for text, hits in sorted(rows.items(), key=lambda kv: (-len(kv[1]), kv[0])):
    confs = [c for c, _, _ in hits]
    srcs = ",".join(sorted({s for _, s, _ in hits}))
    print(f"{len(hits):4d}  {min(confs):.3f}-{max(confs):.3f}  {srcs:12s}  {text!r}  ({hits[0][2]})")
PY
