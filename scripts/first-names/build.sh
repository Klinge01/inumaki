#!/usr/bin/env bash
# Build crates/inumaki-core/data/first_names_dach.txt from two open data sets.
# Build time only (curl, awk, python3 for Unicode normalization); the result
# is committed and embedded. Re-run when the sources publish a new year.
#
#   Statistik Austria, "Vornamen der geborenen Kinder seit 1984",
#   OGDEXT_VORNAMEN_1, CC BY 4.0, https://data.statistik.gv.at
#   BerlinOnline / Landesamt für Bürger- und Ordnungsangelegenheiten,
#   "Liste der häufigen Vornamen", CC BY 3.0 DE (repository code MIT),
#   https://github.com/berlin/haeufige-vornamen-berlin
#
# Pinned inputs (2026-09-27, verified 2026-09-29: AT hash matched on
# re-download; Berlin commit is the repository's current `main` HEAD, data
# years 2012-2023 published). The AT file is republished in place, so its
# hash is checked and the script stops when it changed: read the new file,
# re-pin AT_SHA256 here, and re-run. The Berlin data is read at a commit.
AT_SHA256=49c277575ff669e5a7b670d759ec17d033e9c079aa802e3a096a0640b6756a6c
BERLIN_COMMIT=34ce79c5eccb7bc1f24087a7a3edb1a100bf39e4
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT=crates/inumaki-core/data/first_names_dach.txt
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Austria: C-JAHR-0;C-WOHNBEZIRK-0;C-GESCHLECHT-0;F-VORNAME_NORMALISIERT;F-ANZAHL_LGEB
curl -fsSL https://data.statistik.gv.at/data/OGDEXT_VORNAMEN_1.csv -o "$TMP/at.csv"
GOT=$(shasum -a 256 "$TMP/at.csv" | cut -d' ' -f1)
if [ "$GOT" != "$AT_SHA256" ]; then
  echo "OGDEXT_VORNAMEN_1.csv changed: sha256 $GOT, pinned $AT_SHA256; inspect and re-pin" >&2
  exit 1
fi
awk -F';' 'NR>1 {c[$4]+=$5} END {for (k in c) if (c[k]>=5) print k}' "$TMP/at.csv" > "$TMP/raw.txt"

# Berlin: data/<year>/<district>.csv with vorname,anzahl,geschlecht[,position]
BASE=https://raw.githubusercontent.com/berlin/haeufige-vornamen-berlin/$BERLIN_COMMIT
for y in $(seq 2012 2025); do
  for d in charlottenburg-wilmersdorf friedrichshain-kreuzberg lichtenberg marzahn-hellersdorf mitte \
           neukoelln pankow reinickendorf spandau steglitz-zehlendorf tempelhof-schoeneberg treptow-koepenick; do
    curl -fsSL "$BASE/data/$y/$d.csv" 2>/dev/null | awk -F',' 'NR>1 && $2+0 >= 2 {print $1}' >> "$TMP/raw.txt" || true
  done
done
curl -fsSL "$BASE/conf/non_names.txt" -o "$TMP/non_names.txt" || : > "$TMP/non_names.txt"

python3 - "$TMP/raw.txt" "$TMP/non_names.txt" "$OUT" "$AT_SHA256" "$BERLIN_COMMIT" <<'PY'
import sys, unicodedata, re
raw, non, out, at_sha, berlin_commit = sys.argv[1:]
def norm(s):
    s = unicodedata.normalize("NFKC", s.strip())
    s = "".join(c for c in unicodedata.normalize("NFD", s) if not unicodedata.combining(c))
    return s.casefold().replace("ß", "ss")
skip = {norm(l) for l in open(non, encoding="utf-8") if l.strip() and not l.startswith("#")}
# inumaki's own stop list (greeting words, ambiguous first names) wins over the
# sources: only the WORDS array, never the test strings of that file
src = open("crates/inumaki-core/src/stoplist.rs", encoding="utf-8").read()
words_array = src[src.index("const WORDS: &[&str] = &["):]
words_array = words_array[: words_array.index("];")]
skip |= {norm(w) for w in re.findall(r'"([^"]+)"', words_array)}
ok = re.compile(r"^[^\W\d_][^\W\d_'\-]*(?:[-'][^\W\d_]+)*$")
names = {}
for line in open(raw, encoding="utf-8"):
    n = unicodedata.normalize("NFC", line.strip())
    if len(n) < 3 or not ok.match(n) or norm(n) in skip:
        continue
    names.setdefault(norm(n), n)   # one spelling per normalized form
header = [
    "# DACH first names, supporting evidence for inumaki's anchor detector and name linker.",
    "# Never used to emit a span on its own (engine spec §6.1, plan 4a).",
    "# Sources (see NOTICE):",
    "#   Statistik Austria, OGDEXT_VORNAMEN_1 (names with >= 5 births since 1984), CC BY 4.0, https://data.statistik.gv.at",
    "#   BerlinOnline, haeufige-vornamen-berlin (district lists 2012 onward, count >= 2), CC BY 3.0 DE, https://github.com/berlin/haeufige-vornamen-berlin",
    f"# Built by scripts/first-names/build.sh from OGDEXT_VORNAMEN_1.csv sha256 {at_sha} and haeufige-vornamen-berlin commit {berlin_commit}; edit the script, not this file.",
]
with open(out, "w", encoding="utf-8") as f:
    f.write("\n".join(header) + "\n")
    for k in sorted(names):
        f.write(names[k] + "\n")
print(len(names), "names written to", out)
PY
