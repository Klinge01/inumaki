#!/usr/bin/env bash
# Check the `surname` marks in crates/inumaki-core/data/technical_words.txt,
# and the `surname` and `rare` marks in crates/inumaki-core/data/document_words.txt
# (ruling S3: `surname` iff 1000 or more bearers, `rare` iff 1-999), against the US Census Bureau's 2010 surname list (names with 100 or more
# bearers, 162 254 names; a work of the US government, public domain):
# https://www2.census.gov/topics/genealogy/2010surnames/names.zip
# Build time only (curl, unzip, python3); nothing from the list is committed.
# DACH-origin surnames (Koch, Bauer, Weber, Wagner, Fischer, Kaiser, Richter,
# Graf, Schreiber) are in the list. Exit 1 lists every word whose mark is wrong.
NAMES_ZIP_SHA256=117c41cb4668727b7627b2845b6df3f83eb2a22a1813f42c0ff4bdcab86de135
set -euo pipefail
cd "$(dirname "$0")/../.."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
curl -fsSL https://www2.census.gov/topics/genealogy/2010surnames/names.zip -o "$TMP/names.zip"
GOT=$(shasum -a 256 "$TMP/names.zip" | cut -d' ' -f1)
[ "$GOT" = "$NAMES_ZIP_SHA256" ] || { echo "names.zip changed: $GOT; inspect and re-pin" >&2; exit 1; }
unzip -q -o "$TMP/names.zip" Names_2010Census.csv -d "$TMP"
python3 - "$TMP/Names_2010Census.csv" crates/inumaki-core/data/technical_words.txt <<'PY'
import csv, sys
census = {r["name"].lower() for r in csv.DictReader(open(sys.argv[1]))}
bad = []
for line in open(sys.argv[2], encoding="utf-8"):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    word, *mark = line.split()
    if (word in census) != (mark == ["surname"]):
        bad.append(f"{word}: census={word in census} marked={mark == ['surname']}")
print("\n".join(bad) or "marks match the 2010 Census surname list")
sys.exit(1 if bad else 0)
PY
python3 - "$TMP/Names_2010Census.csv" crates/inumaki-core/data/document_words.txt <<'PY'
import csv, sys
count = {r["name"].lower(): int(r["count"]) for r in csv.DictReader(open(sys.argv[1]))}
bad = []
for line in open(sys.argv[2], encoding="utf-8"):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    word, *mark = line.split()
    n = count.get(word, 0)
    want = ["surname"] if n >= 1000 else ["rare"] if n >= 1 else []
    if mark != want:
        bad.append(f"{word}: census count={n} marked={mark} want={want}")
print("\n".join(bad) or "document marks match the 2010 Census surname counts")
sys.exit(1 if bad else 0)
PY
